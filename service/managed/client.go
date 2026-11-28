package managed

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/safing/jess"

	"github.com/safing/portmaster/base/info"
	"github.com/safing/portmaster/mgmt/policy"
)

const (
	requestTimeout = 30 * time.Second
	maxPolicySize  = 4 << 20
)

var (
	errServerPin     = errors.New("server certificate does not match the pinned fingerprint")
	errPolicyKeyPin  = errors.New("policy key does not match the pinned fingerprint")
	errNotHTTPS      = errors.New("the server URL must start with https://")
	errServerRefused = errors.New("server refused")
	errAlreadyEnroll = errors.New("this computer is already enrolled, leave first")
	errMissingArg    = errors.New("server, token, server fingerprint and policy key fingerprint are required")
	errNoOfflineKey  = errors.New("an offline key fingerprint is given, but the server has no offline key")
	errKeyPin        = errors.New("key does not match the pinned fingerprint")
	// errNoPolicyYet is returned when the server has no policy for this
	// computer yet (offline signing on, no signed group policy published).
	errNoPolicyYet = errors.New("the server has no policy for this computer yet")
)

// EnrollRequest holds the parameters of an enrollment.
type EnrollRequest struct {
	Server      string `json:"server"`
	Token       string `json:"token"`
	ServerFP    string `json:"serverFp"`
	PolicyKeyFP string `json:"policyKeyFp"`
	// OfflineKeyFP optionally pins the offline key at enrollment; the
	// computer then applies only offline-signed policies.
	OfflineKeyFP string `json:"offlineKeyFp,omitempty"`
}

// pinnedTLS returns a TLS config that accepts only the server certificate
// with the given fingerprint. It is used for the enrollment, before the
// client has the CA.
func pinnedTLS(fp string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The chain is not verified because the client does not have the CA
		// yet; instead the server certificate must match the pinned
		// fingerprint, which is stronger.
		InsecureSkipVerify: true, //nolint:gosec // Verified by the pin in VerifyConnection.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || policy.Fingerprint(cs.PeerCertificates[0].Raw) != fp {
				return errServerPin
			}
			return nil
		},
	}
}

func httpClient(cfg *tls.Config) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		// The server is reached directly, never through a proxy from the environment.
		Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil},
	}
}

func serverURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errNotHTTPS
	}
	return strings.TrimSuffix(u.String(), "/") + path, nil
}

// enroll enrolls this computer at the server and writes the state to dir.
func enroll(ctx context.Context, dir stateDir, r *EnrollRequest, now time.Time) error {
	if r.Server == "" || r.Token == "" || r.ServerFP == "" || r.PolicyKeyFP == "" {
		return errMissingArg
	}
	if dir.enrolled() {
		return errAlreadyEnroll
	}
	endpoint, err := serverURL(r.Server, "/v1/enroll")
	if err != nil {
		return err
	}

	// Check the policy key before the token is used, so that a wrong pin
	// does not use up the token. The key in the enrollment response is
	// checked again below.
	client := httpClient(pinnedTLS(r.ServerFP))
	err = checkPolicyKey(ctx, client, r)
	if err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	body, err := json.Marshal(&policy.EnrollRequest{
		Token:       r.Token,
		CSR:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		Hostname:    hostname,
		OS:          runtime.GOOS,
		CoreVersion: info.Version(),
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s: %s", errServerRefused, resp.Status, strings.TrimSpace(string(data)))
	}
	var er policy.EnrollResponse
	err = json.Unmarshal(data, &er)
	if err != nil {
		return fmt.Errorf("parse enrollment response: %w", err)
	}

	// Check the policy key against the pin before trusting anything else.
	err = matchPolicyKey(er.PolicyKey, r.PolicyKeyFP)
	if err != nil {
		return err
	}
	err = matchOfflineKey(er.OfflineKey, r.OfflineKeyFP)
	if err != nil {
		return err
	}
	var offlineKey string
	if r.OfflineKeyFP != "" {
		offlineKey = er.OfflineKey
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	state := &State{
		Server:     strings.TrimSuffix(r.Server, "/"),
		ComputerID: er.ComputerID,
		Enrolled:   now.UTC().Truncate(time.Second),
		PolicyKey:  er.PolicyKey,
		Pins:       policy.Pins{OfflineKey: offlineKey},
	}
	files := []struct {
		name string
		data []byte
	}{
		{fileClientKey, pem.EncodeToMemory(&pem.Block{Type: pemTypeKey, Bytes: keyDER})},
		{fileClientCert, []byte(er.Certificate)},
		{fileCA, []byte(er.CA)},
	}
	for _, f := range files {
		err = dir.writeFile(f.name, f.data)
		if err != nil {
			_ = dir.remove()
			return err
		}
	}
	// The state file is written last: it marks a complete enrollment.
	err = dir.saveState(state)
	if err != nil {
		_ = dir.remove()
		return err
	}
	return nil
}

// matchPolicyKey checks a policy key in jess text format against the pin.
// matchKey checks a key in jess text format against a pinned fingerprint.
func matchKey(textKey, pin string) error {
	key, err := jess.RecipientFromTextFormat(textKey)
	if err != nil {
		return err
	}
	fp, err := policy.KeyFingerprint(key)
	if err != nil {
		return err
	}
	if fp != pin {
		return errKeyPin
	}
	return nil
}

func matchPolicyKey(textKey, pin string) error {
	pk, err := jess.RecipientFromTextFormat(textKey)
	if err != nil {
		return fmt.Errorf("policy key: %w", err)
	}
	fp, err := policy.KeyFingerprint(pk)
	if err != nil {
		return err
	}
	if fp != pin {
		return errPolicyKeyPin
	}
	return nil
}

// checkPolicyKey fetches the policy key from the server and checks it
// against the pin.
func checkPolicyKey(ctx context.Context, client *http.Client, r *EnrollRequest) error {
	endpoint, err := serverURL(r.Server, "/v1/policy-key")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s: %s", errServerRefused, resp.Status, strings.TrimSpace(string(data)))
	}
	var pk struct {
		PolicyKey  string `json:"policyKey"`
		OfflineKey string `json:"offlineKey"`
	}
	err = json.Unmarshal(data, &pk)
	if err != nil {
		return fmt.Errorf("parse policy key: %w", err)
	}
	err = matchPolicyKey(pk.PolicyKey, r.PolicyKeyFP)
	if err != nil {
		return err
	}
	return matchOfflineKey(pk.OfflineKey, r.OfflineKeyFP)
}

// matchOfflineKey checks the offline key of the server against the
// optional pin and returns nil if there is no pin.
func matchOfflineKey(textKey, pin string) error {
	if pin == "" {
		return nil
	}
	if textKey == "" {
		return errNoOfflineKey
	}
	err := matchKey(textKey, pin)
	if err != nil {
		return fmt.Errorf("offline key: %w", err)
	}
	return nil
}

// mtlsClient returns a client that authenticates with the client
// certificate and trusts the server certificates of the server's CA.
func mtlsClient(dir stateDir, s *State) (*http.Client, error) {
	key, err := dir.clientKey()
	if err != nil {
		return nil, err
	}
	certDER, err := dir.clientCertDER()
	if err != nil {
		return nil, err
	}
	pool, err := dir.caPool()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(s.Server)
	if err != nil {
		return nil, err
	}
	return httpClient(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   u.Hostname(),
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
	}), nil
}

// fetchPolicy gets the signed policy from the server.
func fetchPolicy(ctx context.Context, dir stateDir, s *State) ([]byte, error) {
	endpoint, err := serverURL(s.Server, "/v1/policy")
	if err != nil {
		return nil, err
	}
	client, err := mtlsClient(dir, s)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("%w: %s", errNoPolicyYet, strings.TrimSpace(string(data)))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s: %s", errServerRefused, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

// sendReport sends the report to the server.
func sendReport(ctx context.Context, dir stateDir, s *State, r *policy.Report) error {
	endpoint, err := serverURL(s.Server, "/v1/report")
	if err != nil {
		return err
	}
	client, err := mtlsClient(dir, s)
	if err != nil {
		return err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: %s: %s", errServerRefused, resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}
