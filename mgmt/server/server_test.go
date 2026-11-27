package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/safing/jess"

	"github.com/safing/portmaster/mgmt/policy"
)

type testClient struct {
	key  *ecdsa.PrivateKey
	cert *tls.Certificate
}

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	err := Init(dir, "test", []string{"127.0.0.1", "localhost"}, now)
	if err != nil {
		t.Fatal(err)
	}
	err = Init(dir, "test", []string{"127.0.0.1"}, now)
	if !errors.Is(err, errInitialized) {
		t.Fatalf("second init: want errInitialized, got %v", err)
	}
	s, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Store.Close() })

	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, ts
}

func (s *Server) testHTTPClient(cert *tls.Certificate) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(s.CA.Cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func enroll(t *testing.T, s *Server, url, token string) (*testClient, *policy.EnrollResponse, int) {
	t.Helper()
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	req, err := json.Marshal(&policy.EnrollRequest{
		Token:    token,
		CSR:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Hostname: "host1",
		OS:       "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.testHTTPClient(nil).Post(url+"/v1/enroll", "application/json", bytes.NewReader(req))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, resp.StatusCode
	}
	var er policy.EnrollResponse
	err = json.NewDecoder(resp.Body).Decode(&er)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(er.Certificate))
	if block == nil {
		t.Fatal("no certificate in the enrollment response")
	}
	return &testClient{key: key, cert: &tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: key}}, &er, resp.StatusCode
}

func getPolicy(t *testing.T, s *Server, url string, cert *tls.Certificate) ([]byte, int) {
	t.Helper()
	resp, err := s.testHTTPClient(cert).Get(url + "/v1/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data, resp.StatusCode
}

func TestEnrollAndPolicy(t *testing.T) {
	t.Parallel()

	s, ts := newTestServer(t)
	now := time.Now()
	err := s.Store.CreateGroup("office", now)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Store.CreateGroup("office", now)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	settings := map[string]any{"filter/askTimeout": 33}
	err = s.Store.SetGroupPolicy("office", settings, []string{"filter/askTimeout"}, now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := s.Store.CreateToken("office", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	// Enrollment: an unknown token fails, the token works once.
	if _, _, status := enroll(t, s, ts.URL, "wrong"); status != http.StatusForbidden {
		t.Fatalf("unknown token: want 403, got %d", status)
	}
	client, er, status := enroll(t, s, ts.URL, token)
	if status != http.StatusOK {
		t.Fatalf("enroll: status %d", status)
	}
	if _, _, status := enroll(t, s, ts.URL, token); status != http.StatusForbidden {
		t.Fatalf("reused token: want 403, got %d", status)
	}

	// The client pins the policy key from the response; the fingerprint
	// matches the one the admin got.
	pub, err := jess.RecipientFromTextFormat(er.PolicyKey)
	if err != nil {
		t.Fatal(err)
	}
	_, wantFP, err := s.Fingerprints()
	if err != nil {
		t.Fatal(err)
	}
	if gotFP, _ := policy.KeyFingerprint(pub); gotFP != wantFP {
		t.Fatalf("policy key fingerprint %s, want %s", gotFP, wantFP)
	}

	// Policy with the client certificate.
	data, status := getPolicy(t, s, ts.URL, client.cert)
	if status != http.StatusOK {
		t.Fatalf("policy: status %d: %s", status, data)
	}
	p, err := policy.Verify(data, pub, er.ComputerID)
	if err != nil {
		t.Fatalf("verify policy: %v", err)
	}
	if p.Group != "office" || p.Settings["filter/askTimeout"] != float64(33) || len(p.Locked) != 1 {
		t.Fatalf("unexpected policy: %+v", p)
	}
	c, err := s.Store.Computer(er.ComputerID)
	if err != nil || c.LastSeen.IsZero() || c.Hostname != "host1" {
		t.Fatalf("computer not recorded: %+v %v", c, err)
	}

	// A change of the group increases the policy version.
	err = s.Store.SetGroupPolicy("office", map[string]any{}, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = getPolicy(t, s, ts.URL, client.cert)
	p2, err := policy.Verify(data, pub, er.ComputerID)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Version <= p.Version {
		t.Fatalf("version did not increase: %d -> %d", p.Version, p2.Version)
	}

	// Without a certificate and with a certificate of another CA: denied.
	if _, status := getPolicy(t, s, ts.URL, nil); status != http.StatusForbidden {
		t.Fatalf("no certificate: want 403, got %d", status)
	}

	// Revoked: denied.
	err = s.Store.Revoke(er.ComputerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, status := getPolicy(t, s, ts.URL, client.cert); status != http.StatusForbidden {
		t.Fatalf("revoked: want 403, got %d", status)
	}
}

func TestForeignCertificateRejected(t *testing.T) {
	t.Parallel()

	s, ts := newTestServer(t)
	other, err := NewCA("other", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := other.IssueClient(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), "x", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	// The TLS handshake fails or the request is denied.
	resp, err := s.testHTTPClient(cert).Get(ts.URL + "/v1/policy")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("certificate of another CA must be rejected")
		}
	}
}
