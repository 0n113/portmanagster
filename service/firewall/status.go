package firewall

import (
	"time"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/info"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/updates"
)

// Status is a machine-readable summary of the health of the Portmaster, for
// monitoring and remote administration tools.
type Status struct {
	Version string `json:"version"`
	// Ready is true when all service modules are started and running.
	Ready bool `json:"ready"`
	// Interception is true when packets are intercepted and filtered.
	Interception bool `json:"interception"`
	// Filtering is the setting "filter/enable".
	Filtering bool `json:"filtering"`

	IntelVersion   string    `json:"intelVersion,omitempty"`
	IntelPublished time.Time `json:"intelPublished,omitzero"`
	// IntelAgeHours is the age of the intel data (filter lists, geoip) in hours.
	IntelAgeHours float64 `json:"intelAgeHours,omitempty"`

	// Problems lists the warnings and errors that modules report.
	Problems []StatusProblem `json:"problems"`
}

// StatusProblem is a warning or error reported by a module.
type StatusProblem struct {
	Module  string `json:"module"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Message string `json:"message,omitempty"`
}

func registerStatusAPI() error {
	return api.RegisterEndpoint(api.Endpoint{
		Name:        "Status",
		Description: "Returns a machine-readable summary of the health of the Portmaster.",
		Path:        "core/status",
		Read:        api.PermitUser,
		StructFunc: func(_ *api.Request) (any, error) {
			return getStatus(), nil
		},
	})
}

// CoreStatus returns the health of the Portmaster, as served by core/status.
func CoreStatus() *Status {
	return getStatus()
}

func getStatus() *Status {
	s := &Status{
		Version:      info.Version(),
		Ready:        module.instance.Ready(),
		Interception: module.instance.Interception().IsStarted(),
	}
	if filterEnabled != nil {
		s.Filtering = filterEnabled()
	}
	idx, err := module.instance.IntelUpdates().GetIndex()
	if err == nil {
		fillIntelStatus(s, idx, time.Now())
	}
	s.Problems = statusProblems(module.instance.GetStates())
	return s
}

func fillIntelStatus(s *Status, idx *updates.Index, now time.Time) {
	s.IntelVersion = idx.Version
	if !idx.Published.IsZero() {
		s.IntelPublished = idx.Published
		s.IntelAgeHours = float64(now.Sub(idx.Published).Round(time.Minute)) / float64(time.Hour)
	}
}

func statusProblems(updates []mgr.StateUpdate) []StatusProblem {
	problems := []StatusProblem{}
	for _, u := range updates {
		for _, st := range u.States {
			if st.Type != mgr.StateTypeWarning && st.Type != mgr.StateTypeError {
				continue
			}
			problems = append(problems, StatusProblem{
				Module:  u.Module,
				ID:      st.ID,
				Type:    string(st.Type),
				Name:    st.Name,
				Message: st.Message,
			})
		}
	}
	return problems
}
