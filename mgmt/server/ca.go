package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour
	serverValidity = 2 * 365 * 24 * time.Hour
	clientValidity = 365 * 24 * time.Hour
	// Certificates are valid from a few minutes in the past, for clients
	// with a slightly wrong clock.
	clockSkew = 5 * time.Minute

	pemTypeCert = "CERTIFICATE"
	pemTypeKey  = "PRIVATE KEY"
)

var (
	errNoPEM      = errors.New("no PEM block found")
	errBadCSR     = errors.New("invalid certificate request")
	errNotECDSA   = errors.New("key is not an ECDSA key")
	errNoHostname = errors.New("at least one DNS name or IP address is required")
)

// CA is the internal certificate authority of the server. It signs the
// server certificate and the client certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

func newKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func newSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA creates a self-signed CA.
func NewCA(name string, now time.Time) (*CA, error) {
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name + " CA", Organization: []string{"portmanagster"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueServer creates a server certificate for the given DNS names and IPs.
func (ca *CA) IssueServer(hosts []string, now time.Time) (certDER []byte, key *ecdsa.PrivateKey, err error) {
	if len(hosts) == 0 {
		return nil, nil, errNoHostname
	}
	key, err = newKey()
	if err != nil {
		return nil, nil, err
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, err
	}
	return certDER, key, nil
}

// IssueClient checks the PEM encoded CSR and creates a client certificate
// for the computer ID. The subject of the CSR is ignored.
func (ca *CA) IssueClient(csrPEM, computerID string, now time.Time) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: no PEM certificate request", errBadCSR)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadCSR, err)
	}
	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errBadCSR, err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: computerID},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(clientValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
}

// PEM helpers.

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: der})
}

func keyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeKey, Bytes: der}), nil
}

func readCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypeCert {
		return nil, fmt.Errorf("%s: %w", path, errNoPEM)
	}
	return x509.ParseCertificate(block.Bytes)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemTypeKey {
		return nil, fmt.Errorf("%s: %w", path, errNoPEM)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, errNotECDSA)
	}
	return ecKey, nil
}
