package managed

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/safing/jess"
)

// Files in the state directory <data>/managed.
const (
	stateDirName   = "managed"
	fileState      = "state.json"
	fileClientKey  = "client.key"
	fileClientCert = "client.crt"
	fileCA         = "ca.crt"
	filePolicy     = "policy.json"

	pemTypeCert = "CERTIFICATE"
	pemTypeKey  = "PRIVATE KEY"
)

var (
	errNoPEM    = errors.New("no PEM block found")
	errNotECDSA = errors.New("client key is not an ECDSA key")
)

// State is the enrollment state of this computer.
type State struct {
	Server     string    `json:"server"`
	ComputerID string    `json:"computerId"`
	Enrolled   time.Time `json:"enrolled"`
	// PolicyKey is the pinned public policy key in jess text format.
	PolicyKey string `json:"policyKey"`
	// AppliedVersion is the highest policy version applied; older policies
	// are refused.
	AppliedVersion uint64 `json:"appliedVersion"`
	// AppliedProfilesHash is the hash of the profiles of the applied
	// policy; profiles are only imported again when it changes.
	AppliedProfilesHash string `json:"appliedProfilesHash,omitempty"`
}

// stateDir holds the files of an enrollment.
type stateDir string

func (d stateDir) path(name string) string {
	return filepath.Join(string(d), name)
}

func (d stateDir) enrolled() bool {
	_, err := os.Stat(d.path(fileState))
	return err == nil
}

func (d stateDir) loadState() (*State, error) {
	data, err := os.ReadFile(d.path(fileState))
	if err != nil {
		return nil, err
	}
	s := &State{}
	err = json.Unmarshal(data, s)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", fileState, err)
	}
	return s, nil
}

// saveState writes the state atomically.
func (d stateDir) saveState(s *State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return d.writeFile(fileState, data)
}

func (d stateDir) writeFile(name string, data []byte) error {
	err := os.MkdirAll(string(d), 0o700)
	if err != nil {
		return err
	}
	tmp := d.path(name + ".tmp")
	err = os.WriteFile(tmp, data, 0o600) //nolint:gosec // Fixed file names in the state directory.
	if err != nil {
		return err
	}
	return os.Rename(tmp, d.path(name))
}

func (d stateDir) policyKey(s *State) (*jess.Signet, error) {
	return jess.RecipientFromTextFormat(s.PolicyKey)
}

func (d stateDir) caPool() (*x509.CertPool, error) {
	data, err := os.ReadFile(d.path(fileCA))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s: %w", fileCA, errNoPEM)
	}
	return pool, nil
}

func (d stateDir) clientKey() (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(d.path(fileClientKey))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypeKey {
		return nil, fmt.Errorf("%s: %w", fileClientKey, errNoPEM)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errNotECDSA
	}
	return key, nil
}

func (d stateDir) clientCertDER() ([]byte, error) {
	data, err := os.ReadFile(d.path(fileClientCert))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypeCert {
		return nil, fmt.Errorf("%s: %w", fileClientCert, errNoPEM)
	}
	return block.Bytes, nil
}

// remove deletes the enrollment.
func (d stateDir) remove() error {
	return os.RemoveAll(string(d))
}
