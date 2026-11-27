// Package managed is the client of the portmanagster management server: it
// enrolls this computer, pulls its signed policy and applies it. It does
// nothing until the computer is enrolled.
package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/info"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/service/mgr"
)

// PullInterval is the time between two policy pulls.
const PullInterval = 5 * time.Minute

var (
	errOnlyOne     = errors.New("only one instance allowed")
	errNotEnrolled = errors.New("this computer is not enrolled")
)

// Managed is the management client module.
type Managed struct {
	mgr      *mgr.Manager
	instance instance
	dir      stateDir
	applier  applier
	// coreStatus returns the core/status data for the reports; nil in tests.
	coreStatus func() any

	// lock serializes enroll, leave and pulls.
	lock   sync.Mutex
	puller *mgr.WorkerMgr

	statusLock sync.Mutex
	status     Status
}

// Status is the state of the management client, shown by
// "portmaster-core manage status".
type Status struct {
	Enrolled       bool      `json:"enrolled"`
	Server         string    `json:"server,omitempty"`
	ComputerID     string    `json:"computerId,omitempty"`
	Group          string    `json:"group,omitempty"`
	AppliedVersion uint64    `json:"appliedVersion,omitempty"`
	LastPull       time.Time `json:"lastPull,omitzero"`
	LastSuccess    time.Time `json:"lastSuccess,omitzero"`
	LastError      string    `json:"lastError,omitempty"`
	LastReport     time.Time `json:"lastReport,omitzero"`
	// LastReportError is the error of the last report, empty if it was sent.
	LastReportError string `json:"lastReportError,omitempty"`
	// LastCorrected lists the settings set again at the last apply because
	// they differed from the policy.
	LastCorrected []string `json:"lastCorrected,omitempty"`
}

type instance interface {
	DataDir() string
	// CoreStatus returns the health of the Portmaster (core/status) for
	// the reports.
	CoreStatus() any
}

var shimLoaded atomic.Bool

// New returns the management client module.
func New(instance instance) (*Managed, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errOnlyOne
	}
	m := &Managed{
		mgr:      mgr.New("Managed"),
		instance: instance,
		dir:      stateDir(filepath.Join(instance.DataDir(), stateDirName)),
		applier:  coreApplier{},

		coreStatus: instance.CoreStatus,
	}
	err := m.registerAPI()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Manager returns the module manager.
func (m *Managed) Manager() *mgr.Manager {
	return m.mgr
}

// Start applies the stored policy and starts the pulls.
func (m *Managed) Start() error {
	m.puller = m.mgr.NewWorkerMgr("policy pull", m.pullWorker, nil)
	if !m.dir.enrolled() {
		return nil
	}
	// Apply the last policy first, so the computer is configured even when
	// the server cannot be reached.
	err := m.applyStored()
	if err != nil {
		log.Warningf("managed: failed to apply the stored policy: %s", err)
	}
	m.puller.Go()
	m.puller.Repeat(PullInterval)
	return nil
}

// Stop stops the pulls.
func (m *Managed) Stop() error {
	if m.puller != nil {
		m.puller.Stop()
	}
	return nil
}

// Status returns the current status.
func (m *Managed) Status() Status {
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	s := m.status
	s.Enrolled = m.dir.enrolled()
	st, err := m.dir.loadState()
	if err == nil {
		s.Server, s.ComputerID, s.AppliedVersion = st.Server, st.ComputerID, st.AppliedVersion
	}
	return s
}

// Enroll enrolls this computer and pulls the first policy.
func (m *Managed) Enroll(ctx context.Context, r *EnrollRequest) (Status, error) {
	m.lock.Lock()
	err := enroll(ctx, m.dir, r, time.Now())
	m.lock.Unlock()
	if err != nil {
		return m.Status(), err
	}
	log.Infof("managed: enrolled at %s", r.Server)
	err = m.pull(ctx)
	if m.puller != nil {
		m.puller.Repeat(PullInterval)
	}
	return m.Status(), err
}

// Leave removes the enrollment. The applied settings stay as they are.
func (m *Managed) Leave() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	if !m.dir.enrolled() {
		return errNotEnrolled
	}
	err := m.dir.remove()
	if err != nil {
		return err
	}
	m.statusLock.Lock()
	m.status = Status{}
	m.statusLock.Unlock()
	log.Info("managed: left the management server")
	return nil
}

func (m *Managed) pullWorker(w *mgr.WorkerCtx) error {
	if !m.dir.enrolled() {
		return nil
	}
	err := m.pull(w.Ctx())
	if err != nil {
		// Logged by pull; the stored policy stays in force.
		return nil //nolint:nilerr // Not an error of the worker.
	}
	return nil
}

// pull fetches, verifies and applies the policy.
func (m *Managed) pull(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	now := time.Now()
	err := m.pullLocked(ctx)
	m.statusLock.Lock()
	m.status.LastPull = now
	if err != nil {
		m.status.LastError = err.Error()
	} else {
		m.status.LastError = ""
		m.status.LastSuccess = now
	}
	m.statusLock.Unlock()
	if err != nil {
		log.Warningf("managed: policy pull failed: %s", err)
	}
	m.reportLocked(ctx)
	return err
}

// reportLocked sends the report of the last pull to the server. Errors are
// only logged and shown in the status: the policy is in force either way.
func (m *Managed) reportLocked(ctx context.Context) {
	st, err := m.dir.loadState()
	if err != nil {
		return
	}
	m.statusLock.Lock()
	r := &policy.Report{
		Type:           policy.TypeReport,
		Time:           time.Now().UTC().Truncate(time.Second),
		AppliedVersion: st.AppliedVersion,
		CoreVersion:    info.Version(),
		Drift:          m.status.LastCorrected,
		Error:          m.status.LastError,
	}
	m.statusLock.Unlock()
	if m.coreStatus != nil {
		data, err := json.Marshal(m.coreStatus())
		if err == nil {
			r.Status = data
		}
	}

	err = sendReport(ctx, m.dir, st, r)
	m.statusLock.Lock()
	defer m.statusLock.Unlock()
	if err != nil {
		m.status.LastReportError = err.Error()
		log.Debugf("managed: report failed: %s", err)
		return
	}
	m.status.LastReport = r.Time
	m.status.LastReportError = ""
}

func (m *Managed) pullLocked(ctx context.Context) error {
	st, err := m.dir.loadState()
	if err != nil {
		return err
	}
	data, err := fetchPolicy(ctx, m.dir, st)
	if err != nil {
		return err
	}
	return m.verifyAndApply(st, data, true)
}

// applyStored applies the stored policy again.
func (m *Managed) applyStored() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	st, err := m.dir.loadState()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(m.dir.path(filePolicy))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// Force the profiles to be imported again: they may have been changed
	// while the Portmaster was not running.
	st.AppliedProfilesHash = ""
	return m.verifyAndApply(st, data, false)
}

func (m *Managed) verifyAndApply(st *State, data []byte, store bool) error {
	pk, err := m.dir.policyKey(st)
	if err != nil {
		return fmt.Errorf("pinned policy key: %w", err)
	}
	p, err := policy.Verify(data, pk, st.ComputerID)
	if err != nil {
		return fmt.Errorf("policy refused: %w", err)
	}
	err = policy.CheckVersion(p, st.AppliedVersion)
	if err != nil {
		return fmt.Errorf("policy refused: %w", err)
	}

	res, hash, err := applyPolicy(m.applier, p, st.AppliedProfilesHash)
	if err != nil {
		return fmt.Errorf("apply policy %d: %w", p.Version, err)
	}
	if len(res.Corrected) > 0 || res.Profiles > 0 {
		log.Infof("managed: applied policy %d: %d settings set, %d profiles imported", p.Version, len(res.Corrected), res.Profiles)
	}

	if store {
		err = m.dir.writeFile(filePolicy, data)
		if err != nil {
			return err
		}
	}
	st.AppliedVersion = p.Version
	st.AppliedProfilesHash = hash
	err = m.dir.saveState(st)
	if err != nil {
		return err
	}

	m.statusLock.Lock()
	m.status.Group = p.Group
	m.status.LastCorrected = res.Corrected
	m.statusLock.Unlock()
	return nil
}

func (m *Managed) registerAPI() error {
	err := api.RegisterEndpoint(api.Endpoint{
		Name:        "Management Status",
		Description: "Shows whether this computer is managed by a portmanagster server and the state of its policy.",
		Path:        "managed/status",
		Read:        api.PermitUser,
		StructFunc: func(_ *api.Request) (any, error) {
			return m.Status(), nil
		},
	})
	if err != nil {
		return err
	}
	err = api.RegisterEndpoint(api.Endpoint{
		Name:        "Enroll",
		Description: "Enrolls this computer at a portmanagster server with a one-time token.",
		Path:        "managed/enroll",
		Write:       api.PermitAdmin,
		StructFunc: func(ar *api.Request) (any, error) {
			var r EnrollRequest
			err := json.Unmarshal(ar.InputData, &r)
			if err != nil {
				return nil, fmt.Errorf("invalid enroll request: %w", err)
			}
			return m.Enroll(ar.Context(), &r)
		},
	})
	if err != nil {
		return err
	}
	return api.RegisterEndpoint(api.Endpoint{
		Name:        "Leave Management",
		Description: "Removes the enrollment of this computer. The applied settings stay.",
		Path:        "managed/leave",
		Write:       api.PermitAdmin,
		StructFunc: func(_ *api.Request) (any, error) {
			err := m.Leave()
			if err != nil {
				return nil, err
			}
			return m.Status(), nil
		},
	})
}
