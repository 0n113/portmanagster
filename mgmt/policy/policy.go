// Package policy defines the policy that the management server sends to the
// Portmaster clients, how it is signed and how a client verifies it, and the
// messages of the enrollment. It is shared by the server and the client.
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/safing/jess"
	"github.com/safing/jess/filesig"
)

// TypePolicy is the value of Policy.Type.
const TypePolicy = "policy"

// KeyTool is the jess tool of the policy signing key.
const KeyTool = "Ed25519"

var (
	// ErrWrongType is returned for a document that is not a policy.
	ErrWrongType = errors.New("not a policy")
	// ErrWrongComputer is returned for a policy issued for another computer.
	ErrWrongComputer = errors.New("policy is for another computer")
	// ErrRollback is returned for a policy older than the applied one.
	ErrRollback = errors.New("policy is older than the applied policy")
	// ErrNoKey is returned when a key has no public key loaded.
	ErrNoKey = errors.New("key has no public key")
)

// Policy is the configuration the server sets for one computer.
type Policy struct {
	Type string `json:"type"`
	// Version increases with every change on the server. Clients refuse a
	// policy with a lower version than the one they applied.
	Version uint64    `json:"version"`
	Issued  time.Time `json:"issued"`
	// Computer is the ID of the computer the policy is for.
	Computer string `json:"computer"`
	Group    string `json:"group,omitempty"`
	// Settings are global settings with slash-joined keys, e.g.
	// "filter/blockInbound".
	Settings map[string]any `json:"settings"`
	// Locked lists the settings keys a local admin must not change. The
	// other settings are defaults a local admin may override.
	Locked []string `json:"locked,omitempty"`
	// Rules are endpoint rules evaluated before the rules of all app
	// profiles and the global rules.
	Rules *Rules `json:"rules,omitempty"`
	// Profiles are app profiles in the format of the profile export.
	Profiles []json.RawMessage `json:"profiles,omitempty"`
	// BlockSummary asks the client to add a summary of its blocked
	// connections to every report (opt-in per group).
	BlockSummary bool `json:"blockSummary,omitempty"`
}

// Rules are the endpoint rules of a policy, in the format of the
// filter/endpoints and filter/serviceEndpoints settings.
type Rules struct {
	// Endpoints apply to outgoing connections.
	Endpoints []string `json:"endpoints,omitempty" yaml:"endpoints,omitempty"`
	// ServiceEndpoints apply to incoming connections.
	ServiceEndpoints []string `json:"serviceEndpoints,omitempty" yaml:"serviceEndpoints,omitempty"`
}

// Empty returns whether there are no rules.
func (r *Rules) Empty() bool {
	return r == nil || (len(r.Endpoints) == 0 && len(r.ServiceEndpoints) == 0)
}

// GenerateKey creates a new policy signing key.
func GenerateKey(name string) (*jess.Signet, error) {
	key, err := jess.GenerateSignet(KeyTool, 0)
	if err != nil {
		return nil, err
	}
	err = key.AssignUUID()
	if err != nil {
		return nil, err
	}
	key.Info = &jess.SignetInfo{Name: name}
	// Serialize the key into the signet; an envelope treats a signet
	// without serialized key as a reference into a trust store.
	err = key.StoreKey()
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Sign serializes and signs the policy with the signing key.
func Sign(p *Policy, key *jess.Signet) ([]byte, error) {
	p.Type = TypePolicy
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	pub, err := key.AsRecipient()
	if err != nil {
		return nil, err
	}
	trustStore := jess.NewMemTrustStore()
	err = trustStore.StoreSignet(pub)
	if err != nil {
		return nil, err
	}

	envelope := jess.NewUnconfiguredEnvelope()
	envelope.SuiteID = jess.SuiteSignV1
	envelope.Senders = []*jess.Signet{key}
	signed, err := filesig.AddJSONSignature(data, envelope, trustStore)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return signed, nil
}

// Verify checks the signature of a signed policy against the public policy
// key and that it is for the given computer, and returns the policy. The
// caller compares the version with the applied one, see CheckVersion.
func Verify(data []byte, policyKey *jess.Signet, computer string) (*Policy, error) {
	trustStore := jess.NewMemTrustStore()
	err := trustStore.StoreSignet(policyKey)
	if err != nil {
		return nil, err
	}
	err = filesig.VerifyJSONSignature(data, trustStore)
	if err != nil {
		return nil, err
	}

	p := &Policy{}
	err = json.Unmarshal(data, p)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Type != TypePolicy {
		return nil, ErrWrongType
	}
	if p.Computer != computer {
		return nil, ErrWrongComputer
	}
	return p, nil
}

// CheckVersion returns ErrRollback if p is older than the applied version.
// The same version is accepted: the server sends it again on every pull.
func CheckVersion(p *Policy, applied uint64) error {
	if p.Version < applied {
		return fmt.Errorf("%w: %d < %d", ErrRollback, p.Version, applied)
	}
	return nil
}

// KeyFingerprint returns "sha256:<hex>" of the public key of a signet.
func KeyFingerprint(key *jess.Signet) (string, error) {
	pub, ok := key.PublicKey().(ed25519.PublicKey)
	if !ok || len(pub) == 0 {
		err := key.LoadKey()
		if err != nil {
			return "", err
		}
		pub, ok = key.PublicKey().(ed25519.PublicKey)
		if !ok || len(pub) == 0 {
			return "", ErrNoKey
		}
	}
	return Fingerprint(pub), nil
}

// Fingerprint returns "sha256:<hex>" of data, e.g. of a DER certificate.
func Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EnrollRequest is sent by a client to POST /v1/enroll.
type EnrollRequest struct {
	Token string `json:"token"`
	// CSR is a PEM encoded certificate request for the client key.
	CSR         string `json:"csr"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	CoreVersion string `json:"coreVersion"`
}

// EnrollResponse is the answer to a successful enrollment.
type EnrollResponse struct {
	ComputerID string `json:"computerId"`
	// Certificate is the PEM encoded client certificate.
	Certificate string `json:"certificate"`
	// CA is the PEM encoded CA certificate of the client certificates.
	CA string `json:"ca"`
	// PolicyKey is the public policy key in jess text format.
	PolicyKey string `json:"policyKey"`
}

// TypeReport is the value of Report.Type.
const TypeReport = "report"

// Report is sent by a client to POST /v1/report after each policy pull.
type Report struct {
	Type string    `json:"type"`
	Time time.Time `json:"time"`
	// AppliedVersion is the version of the policy in force on the client.
	AppliedVersion uint64 `json:"appliedVersion"`
	CoreVersion    string `json:"coreVersion"`
	// Overridden lists the policy defaults (unlocked settings) a local
	// admin changed.
	Overridden []string `json:"overridden,omitempty"`
	// Refused lists policy settings the client did not apply because their
	// value is invalid or the setting is unknown to this version.
	Refused []string `json:"refused,omitempty"`
	// Error is the error of the last pull or apply, empty if it succeeded.
	Error string `json:"error,omitempty"`
	// Status is the health of the Portmaster, as returned by core/status.
	Status json.RawMessage `json:"status,omitempty"`
	// Blocks summarizes the connections blocked from BlocksSince until
	// Time, if the policy asks for it; at most MaxBlocks entries, the
	// largest counts first.
	Blocks      []Block   `json:"blocks,omitempty"`
	BlocksSince time.Time `json:"blocksSince,omitzero"`
	// Apps lists the apps that had allowed connections in the same time,
	// sent together with the block summary; at most MaxApps entries.
	Apps []App `json:"apps,omitempty"`
}

// MaxApps is the maximum number of apps in a report.
const MaxApps = 200

// App is an app with network access. It has no path, only a hash of it.
type App struct {
	// Name is the name of the app profile.
	Name string `json:"name"`
	// ID is the hex SHA-256 of the executable path, shortened to 32
	// characters; it tells apps with the same name apart.
	ID string `json:"id"`
}

// MaxBlocks is the maximum number of entries of a block summary.
const MaxBlocks = 200

// Block counts the blocked connections of an app with the same reason and
// destination. It has no connection details and no user names.
type Block struct {
	// App is the name of the app profile.
	App string `json:"app"`
	// Reason is the setting that blocked, e.g. "filter/lists" or
	// "filter/endpoints", or the reason message if there is none.
	Reason string `json:"reason,omitempty"`
	// Lists are the filter lists that matched, comma-separated, e.g. "MAL".
	Lists string `json:"lists,omitempty"`
	// Target is the domain, or the IP address if there is no domain.
	Target string `json:"target"`
	// Inbound is set for blocked incoming connections.
	Inbound bool `json:"inbound,omitempty"`
	Count   int  `json:"count"`
}
