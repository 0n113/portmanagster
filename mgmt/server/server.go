// Package server implements the portmanagster management server: the
// internal CA, enrollment of computers with one-time tokens, and signed
// policies per computer.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
)

// Files in the data directory.
const (
	FileCACert     = "ca.crt"
	FileCAKey      = "ca.key"
	FileServerCert = "server.crt"
	FileServerKey  = "server.key"
	FilePolicyKey  = "policy.key"
	FilePolicyPub  = "policy.pub"
	FileDB         = "portmanagster.db"

	maxRequestSize = 64 << 10
	// maxReportSize leaves room for a block summary with policy.MaxBlocks
	// entries of 255-byte fields.
	maxReportSize = 512 << 10
)

var (
	errInitialized = errors.New("data directory is already initialized")
	errNoClientCrt = errors.New("no client certificate")
	errRevoked     = errors.New("computer is revoked")
	errCertUnknown = errors.New("client certificate does not match the computer")
)

// Server is a loaded management server.
type Server struct {
	Dir        string
	Store      *Store
	CA         *CA
	ServerCert tls.Certificate
	PolicyKey  *jess.Signet
	// PolicyPub is the public policy key in jess text format.
	PolicyPub string
	Log       *slog.Logger
	Now       func() time.Time
}

// Init creates the CA, the server certificate for hosts, the policy signing
// key and the database in dir.
func Init(dir, name string, hosts []string, now time.Time) error {
	_, err := os.Stat(filepath.Join(dir, FileCAKey))
	if err == nil {
		return fmt.Errorf("%s: %w", dir, errInitialized)
	}
	err = os.MkdirAll(dir, 0o700)
	if err != nil {
		return err
	}

	ca, err := NewCA(name, now)
	if err != nil {
		return err
	}
	srvDER, srvKey, err := ca.IssueServer(hosts, now)
	if err != nil {
		return err
	}
	caKeyPEM, err := keyPEM(ca.Key)
	if err != nil {
		return err
	}
	srvKeyPEM, err := keyPEM(srvKey)
	if err != nil {
		return err
	}

	pk, err := policy.GenerateKey(name + " policy")
	if err != nil {
		return err
	}
	pkBackup, err := pk.Backup(false)
	if err != nil {
		return err
	}
	pkPub, err := pk.Export(false)
	if err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{FileCACert, certPEM(ca.Cert.Raw), 0o644},
		{FileCAKey, caKeyPEM, 0o600},
		{FileServerCert, certPEM(srvDER), 0o644},
		{FileServerKey, srvKeyPEM, 0o600},
		{FilePolicyKey, []byte(pkBackup + "\n"), 0o600},
		{FilePolicyPub, []byte(pkPub + "\n"), 0o644},
	}
	for _, f := range files {
		err = os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode)
		if err != nil {
			return err
		}
	}

	store, err := OpenStore(filepath.Join(dir, FileDB))
	if err != nil {
		return err
	}
	err = store.Close()
	if err != nil {
		return err
	}
	return os.Chmod(filepath.Join(dir, FileDB), 0o600)
}

// Load opens an initialized data directory.
func Load(dir string, logger *slog.Logger) (*Server, error) {
	caCert, err := readCert(filepath.Join(dir, FileCACert))
	if err != nil {
		return nil, err
	}
	caKey, err := readKey(filepath.Join(dir, FileCAKey))
	if err != nil {
		return nil, err
	}
	srvCert, err := tls.LoadX509KeyPair(filepath.Join(dir, FileServerCert), filepath.Join(dir, FileServerKey))
	if err != nil {
		return nil, err
	}
	pkText, err := os.ReadFile(filepath.Join(dir, FilePolicyKey))
	if err != nil {
		return nil, err
	}
	pk, err := jess.SenderFromTextFormat(string(trimNL(pkText)))
	if err != nil {
		return nil, fmt.Errorf("policy key: %w", err)
	}
	pubText, err := os.ReadFile(filepath.Join(dir, FilePolicyPub))
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(filepath.Join(dir, FileDB))
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		Dir:        dir,
		Store:      store,
		CA:         &CA{Cert: caCert, Key: caKey},
		ServerCert: srvCert,
		PolicyKey:  pk,
		PolicyPub:  string(trimNL(pubText)),
		Log:        logger,
		Now:        time.Now,
	}, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// Fingerprints returns the fingerprints clients pin at enrollment.
func (s *Server) Fingerprints() (serverCert, policyKey string, err error) {
	serverCert = policy.Fingerprint(s.ServerCert.Certificate[0])
	policyKey, err = policy.KeyFingerprint(s.PolicyKey)
	return serverCert, policyKey, err
}

// TLSConfig returns the TLS configuration of the API: client certificates
// of the internal CA are verified if given (enrollment has none yet).
func (s *Server) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.ServerCert},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
}

// Handler returns the HTTP handler of the client API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/policy-key", s.handlePolicyKey)
	mux.HandleFunc("POST /v1/enroll", s.handleEnroll)
	mux.HandleFunc("GET /v1/policy", s.handlePolicy)
	mux.HandleFunc("POST /v1/report", s.handleReport)
	return mux
}

// Serve runs the client API on addr until ctx is done.
func (s *Server) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         s.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx) //nolint:contextcheck // The parent context is done.
	}
}

// PolicyFor builds and signs the policy of a computer.
func (s *Server) PolicyFor(c *Computer, now time.Time) ([]byte, error) {
	g, err := s.Store.Group(c.Group)
	if err != nil {
		return nil, err
	}
	seq, err := s.Store.PolicySeq()
	if err != nil {
		return nil, err
	}
	return policy.Sign(&policy.Policy{
		Version:  seq,
		Issued:   now.UTC().Truncate(time.Second),
		Computer: c.ID,
		Group:    g.Name,
		Settings: g.Settings,
		Locked:   g.Locked,
		Rules:    g.Rules,
		Profiles: g.Profiles,

		BlockSummary: g.BlockSummary,
	}, s.PolicyKey)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		return // The client went away; nothing left to tell it.
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
	if err != nil {
		writeError(w, http.StatusBadRequest, "cannot read request")
		return
	}
	var req policy.EnrollRequest
	err = json.Unmarshal(body, &req)
	if err != nil || req.Token == "" || req.CSR == "" {
		writeError(w, http.StatusBadRequest, "invalid enrollment request")
		return
	}

	now := s.Now()
	c := &Computer{Hostname: req.Hostname, OS: req.OS, CoreVersion: req.CoreVersion}
	var certDER []byte
	err = s.Store.Enroll(req.Token, c, now, func(id string) (string, error) {
		var issueErr error
		certDER, issueErr = s.CA.IssueClient(req.CSR, id, now)
		if issueErr != nil {
			return "", issueErr
		}
		return policy.Fingerprint(certDER), nil
	})
	switch {
	case errors.Is(err, ErrBadToken):
		s.Log.Warn("enrollment with an invalid token", "remote", r.RemoteAddr, "hostname", req.Hostname)
		writeError(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, errBadCSR):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.Log.Error("enrollment failed", "err", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	s.Log.Info("computer enrolled", "id", c.ID, "hostname", c.Hostname, "group", c.Group, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, &policy.EnrollResponse{
		ComputerID:  c.ID,
		Certificate: string(certPEM(certDER)),
		CA:          string(certPEM(s.CA.Cert.Raw)),
		PolicyKey:   s.PolicyPub,
	})
}

// authenticate returns the computer of the verified client certificate.
func (s *Server) authenticate(r *http.Request) (*Computer, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, errNoClientCrt
	}
	cert := r.TLS.PeerCertificates[0]
	c, err := s.Store.Computer(cert.Subject.CommonName)
	if err != nil {
		return nil, err
	}
	if c.Revoked {
		return nil, errRevoked
	}
	if c.CertFP != policy.Fingerprint(cert.Raw) {
		return nil, errCertUnknown
	}
	return c, nil
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	c, err := s.authenticate(r)
	if err != nil {
		s.Log.Warn("policy request denied", "remote", r.RemoteAddr, "err", err)
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	now := s.Now()
	err = s.Store.Seen(c.ID, now)
	if err != nil {
		s.Log.Error("record last seen", "id", c.ID, "err", err)
	}

	signed, err := s.PolicyFor(c, now)
	if err != nil {
		s.Log.Error("build policy", "id", c.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "cannot build policy")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(signed) //nolint:gosec // Signed JSON policy, served as application/json.
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	c, err := s.authenticate(r)
	if err != nil {
		s.Log.Warn("report denied", "remote", r.RemoteAddr, "err", err)
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportSize+1))
	if err != nil || len(body) > maxReportSize {
		writeError(w, http.StatusBadRequest, "cannot read request or report too large")
		return
	}
	var report policy.Report
	err = json.Unmarshal(body, &report)
	if err != nil || report.Type != policy.TypeReport || CheckBlocks(report.Blocks) != nil {
		writeError(w, http.StatusBadRequest, "invalid report")
		return
	}
	if len(report.Blocks) > 0 {
		// Keep block summaries only of groups that ask for them.
		g, gerr := s.Store.Group(c.Group)
		if gerr != nil || !g.BlockSummary {
			report.Blocks = nil
		}
	}
	now := s.Now()
	err = s.Store.SaveReport(c.ID, &report, now)
	if err != nil {
		s.Log.Error("store report", "id", c.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "cannot store report")
		return
	}
	if len(report.Overridden) > 0 {
		s.Log.Info("policy defaults overridden locally", "id", c.ID, "hostname", c.Hostname, "settings", report.Overridden)
	}
	if len(report.Refused) > 0 {
		s.Log.Warn("client refused policy settings", "id", c.ID, "hostname", c.Hostname, "settings", report.Refused)
	}
	if report.Error != "" {
		s.Log.Warn("client reports an error", "id", c.ID, "hostname", c.Hostname, "err", report.Error)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePolicyKey returns the public policy key, so that a client can check
// it against its pin before it uses the enrollment token.
func (s *Server) handlePolicyKey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"policyKey": s.PolicyPub})
}
