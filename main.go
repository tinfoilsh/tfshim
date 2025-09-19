package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"

	"github.com/creasty/defaults"
	"github.com/go-acme/lego/v4/lego"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
	"github.com/tinfoilsh/verifier/attestation"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"github.com/tinfoilsh/tfshim/dcode"
	"github.com/tinfoilsh/tfshim/key"
	"github.com/tinfoilsh/tfshim/key/online"
	tlsutil "github.com/tinfoilsh/tfshim/tls"
)

var version = "dev"

var config struct {
	ListenPort   int `yaml:"listen-port" default:"443"`
	UpstreamPort int `yaml:"upstream-port"`
	ControlPort  int `yaml:"control-port" default:"8086"`

	Paths         []string `yaml:"paths"`
	OriginDomains []string `yaml:"origins"`

	TLSMode          string `yaml:"tls-mode" default:"production"` // self-signed | staging | production
	TLSChallengeMode string `yaml:"tls-challenge" default:"tls"`   // tls | dns

	ControlPlane string `yaml:"control-plane"`

	RateLimit   float64 `yaml:"rate-limit"`
	RateBurst   int     `yaml:"rate-burst"`
	CacheDir    string  `yaml:"cache-dir" default:"/mnt/ramdisk/certs"`
	Email       string  `yaml:"email" default:"tls@tinfoil.sh"`
	HPKEKeyFile string  `yaml:"hpke-key-file" default:"/mnt/ramdisk/hpke_key.json"`

	PublishAttestation bool `yaml:"publish-attestation"`
	DummyAttestation   bool `yaml:"dummy-attestation"`

	Verbose bool `yaml:"verbose"`
}

var externalConfig struct {
	Domain              string `yaml:"domain"`
	CloudflareDNSToken  string `yaml:"cloudflare-dns-token"`
	CloudflareZoneToken string `yaml:"cloudflare-zone-token"`
}

var (
	configFile         = flag.String("c", "/mnt/ramdisk/shim.yml", "Path to config file")
	externalConfigFile = flag.String("e", "/mnt/ramdisk/external-config.yml", "Path to external config file")
	dev                = flag.Bool("d", false, "Skip dcode domains, use dummy attestation, and enable verbose logging")
)

func main() {
	flag.Parse()

	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		log.Fatalf("Failed to unmarshal config: %v", err)
	}
	if err := defaults.Set(&config); err != nil {
		log.Fatalf("Failed to set defaults: %v", err)
	}

	if config.UpstreamPort == 0 {
		log.Fatalf("Upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "staging", "production"}, config.TLSMode) {
		log.Fatalf("Invalid TLS mode: %s", config.TLSMode)
	}

	externalConfigBytes, err := os.ReadFile(*externalConfigFile)
	if err != nil {
		log.Fatalf("Failed to read external config file: %v", err)
	}
	if err := yaml.Unmarshal(externalConfigBytes, &externalConfig); err != nil {
		log.Fatalf("Failed to unmarshal external config: %v", err)
	}
	if err := defaults.Set(&externalConfig); err != nil {
		log.Fatalf("Failed to set defaults: %v", err)
	}

	if config.Verbose || *dev {
		log.SetLevel(log.DebugLevel)
	}

	log.Printf("Starting tinfoil attestation shim %s: %+v", version, config)

	var validator key.Validator
	var controlPlaneURL *url.URL

	if config.ControlPlane != "" {
		controlPlaneURL, err = url.Parse(config.ControlPlane)
		if err != nil {
			log.Fatalf("Failed to parse control plane URL: %v", err)
		}

		validator, err = online.NewValidator(controlPlaneURL.JoinPath("api", "shim", "validate").String())
		if err != nil {
			log.Fatalf("Failed to initialize online API key verifier: %v", err)
		}
	} else {
		validator = nil
		log.Warn("API key verification disabled")
	}

	log.Printf("Starting control server on port %d", config.ControlPort)
	controlServer := newControlServer()
	go controlServer.Start(config.ControlPort)

	// Generate or load HPKE key
	serverIdentity, err := identity.FromFile(config.HPKEKeyFile)
	if err != nil {
		logrus.Fatalf("Failed to get identity: %v", err)
	}

	// Generate key for TLS certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	if externalConfig.Domain == "" {
		externalConfig.Domain = "localhost"
	}

	hpkeKeyBytes := serverIdentity.MarshalPublicKey()
	if len(hpkeKeyBytes) != 32 {
		log.Fatalf("HPKE key length is not 32 bytes, got %d", len(hpkeKeyBytes))
	}
	var hpkeKey [32]byte
	copy(hpkeKey[:], hpkeKeyBytes)

	aBody := AttestationBodyV2{
		TLSKeyFP: tlsutil.KeyFPBytes(privateKey.Public().(*ecdsa.PublicKey)),
		HPKEKey:  hpkeKey,
	}
	attestationBody := aBody.Marshal()

	// Request attestation
	log.Printf("Fetching attestation over %s", attestationBody)
	var att *attestation.Document
	if externalConfig.Domain == "localhost" || *dev || config.DummyAttestation {
		log.Warn("Using dummy attestation report")
		att = &attestation.Document{
			Format: "https://tinfoil.sh/predicate/dummy/v2",
			Body:   string(attestationBody),
		}
	} else {
		att, err = attestationReport(attestationBody)
		if err != nil {
			log.Fatal(err)
		}
	}

	domains := []string{externalConfig.Domain}

	// Encode attestation into domains
	if config.PublishAttestation {
		attDomains, err := dcode.Encode(att, externalConfig.Domain)
		if err != nil {
			log.Fatalf("Failed to encode attestation: %v", err)
		}
		domains = append(domains, attDomains...)
	}

	for _, d := range domains {
		log.Debugf("Domain: %s", d)
	}

	// Request prod cert if needed
	var cert *tls.Certificate
	if externalConfig.Domain == "localhost" || config.TLSMode == "self-signed" {
		cert, err = tlsutil.Certificate(privateKey, domains...)
		if err != nil {
			log.Fatalf("Failed to generate self signed TLS certificate: %v", err)
		}
	} else { // Prod TLS cert
		dir := lego.LEDirectoryProduction
		if config.TLSMode == "staging" {
			dir = lego.LEDirectoryStaging
		}
		certManager, err := tlsutil.NewCertManager(
			domains,
			config.Email, config.CacheDir, dir,
			tlsutil.ChallengeMode(config.TLSChallengeMode),
			config.ListenPort,
			privateKey,
			externalConfig.CloudflareDNSToken,
			externalConfig.CloudflareZoneToken,
		)
		if err != nil {
			log.Fatalf("Failed to create cert manager: %v", err)
		}

		cert, err = certManager.Certificate()
		if err != nil {
			log.Fatalf("Failed to request TLS certificate: %v", err)
		}
	}

	tlsConfig := &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}

	var rateLimiter *RateLimiter
	if config.RateLimit > 0 {
		rateLimiter = NewRateLimiter(rate.Limit(config.RateLimit), config.RateBurst)
	}

	listenAddr := fmt.Sprintf(":%d", config.ListenPort)
	httpServer := &http.Server{
		Addr:      listenAddr,
		Handler:   newMux(validator, rateLimiter, att, serverIdentity),
		TLSConfig: tlsConfig,
	}

	log.Printf("Listening on %s", listenAddr)
	log.Fatal(httpServer.ListenAndServeTLS("", ""))
}
