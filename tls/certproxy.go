package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/verifier/attestation"
)

// CertProxyManager obtains certificates from a control plane proxy
type CertProxyManager struct {
	domains         []string
	cacheDir        string
	controlPlaneURL string
	privateKey      *ecdsa.PrivateKey
	attestation     *attestation.Document
}

// NewCertProxyManager creates a new certificate manager that obtains certs via control plane
func NewCertProxyManager(
	domains []string,
	cacheDir string,
	controlPlaneURL string,
	privateKey *ecdsa.PrivateKey,
	att *attestation.Document,
) (*CertProxyManager, error) {
	if controlPlaneURL == "" {
		return nil, fmt.Errorf("control plane URL is required")
	}

	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &CertProxyManager{
		domains:         domains,
		cacheDir:        cacheDir,
		controlPlaneURL: controlPlaneURL,
		privateKey:      privateKey,
		attestation:     att,
	}, nil
}

// Certificate returns a TLS certificate, either from cache or by requesting from control plane
func (m *CertProxyManager) Certificate() (*tls.Certificate, error) {
	certFile := filepath.Join(m.cacheDir, "cert.pem")
	keyFile := filepath.Join(m.cacheDir, "key.pem")

	// Check cache first
	if _, err := os.Stat(certFile); err == nil {
		log.Info("Certificate found in cache, using cached certificate")
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load cached certificate: %w", err)
		}
		return &cert, nil
	}

	return m.obtainCertificate(certFile, keyFile)
}

func (m *CertProxyManager) obtainCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	log.Debugf("Requesting certificate via cert proxy for: %v", m.domains)

	csrPEM, err := m.createCSR()
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	certPEM, err := m.requestCertificate(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate from control plane: %w", err)
	}

	keyBytes, err := encodeECDSAKeyToPEM(m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write certificate to cache: %w", err)
	}
	if err := os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key to cache: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	log.Info("Certificate obtained via cert proxy")
	return &cert, nil
}

func (m *CertProxyManager) createCSR() ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: m.domains[0],
		},
		DNSNames: m.domains,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, m.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

func (m *CertProxyManager) requestCertificate(csrPEM []byte) ([]byte, error) {
	certURL, err := url.JoinPath(m.controlPlaneURL, "api", "shim", "cert")
	if err != nil {
		return nil, fmt.Errorf("failed to construct cert URL: %w", err)
	}

	reqBody := struct {
		CSR         string                `json:"csr"`
		Attestation *attestation.Document `json:"attestation,omitempty"`
	}{
		CSR:         string(csrPEM),
		Attestation: m.attestation,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(certURL, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to control plane: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned error (status %d): %s", resp.StatusCode, string(body))
	}

	var certResp struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if certResp.Certificate == "" {
		return nil, fmt.Errorf("control plane returned empty certificate")
	}

	return []byte(certResp.Certificate), nil
}
