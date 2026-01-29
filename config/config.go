package config

import (
	"fmt"
	"os"
	"slices"

	"github.com/creasty/defaults"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenPort   int `yaml:"listen-port" default:"443"`
	UpstreamPort int `yaml:"upstream-port"`
	ControlPort  int `yaml:"control-port" default:"8086"`

	Paths         []string `yaml:"paths"`
	OriginDomains []string `yaml:"origins"`

	TLSMode          string `yaml:"tls-mode" default:"cert-proxy"` // self-signed | staging | production | cert-proxy
	TLSChallengeMode string `yaml:"tls-challenge" default:"tls"`   // tls | dns

	ControlPlane  string `yaml:"control-plane" default:"https://api.tinfoil.sh"`
	Authenticated bool   `yaml:"authenticated" default:"false"`

	RateLimit   float64 `yaml:"rate-limit"`
	RateBurst   int     `yaml:"rate-burst"`
	CacheDir    string  `yaml:"cache-dir" default:"/mnt/ramdisk/tfshim-cache"`
	Email       string  `yaml:"email" default:"tls@tinfoil.sh"`
	HPKEKeyFile string  `yaml:"hpke-key-file" default:"/mnt/ramdisk/hpke_key.json"`

	PublishAttestation     bool `yaml:"publish-attestation" default:"true"`
	PublishFullAttestation bool `yaml:"publish-full-attestation" default:"false"`
	DummyAttestation       bool `yaml:"dummy-attestation" default:"false"`

	Verbose bool `yaml:"verbose"`
}

type Metadata struct {
	ID     string `yaml:"id"`
	Domain string `yaml:"domain"`
	Image  string `yaml:"image"`
	GPU    string `yaml:"gpu"`
}

type ExternalConfig struct {
	// Populated from env/secrets sections after loading
	Domain              string
	CloudflareDNSToken  string
	CloudflareZoneToken string
	MetricsAPIKey       string
	ACPIAPIKey          string

	// New format sections
	Env      map[string]string `yaml:"env"`
	Secrets  map[string]string `yaml:"secrets"`
	Metadata Metadata          `yaml:"metadata"`
}

// Load loads the config from the given files
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	var config Config
	if err := defaults.Set(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to set defaults: %v", err)
	}

	configBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}

	if config.UpstreamPort == 0 {
		return nil, nil, fmt.Errorf("upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "staging", "production", "cert-proxy"}, config.TLSMode) {
		return nil, nil, fmt.Errorf("invalid TLS mode: %s", config.TLSMode)
	}

	externalConfigBytes, err := os.ReadFile(externalConfigFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read external config file: %v", err)
	}
	var externalConfig ExternalConfig
	if err := yaml.Unmarshal(externalConfigBytes, &externalConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal external config: %v", err)
	}
	if err := defaults.Set(&externalConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to set defaults: %v", err)
	}

	// Populate fields from new format sections
	if externalConfig.Env != nil {
		externalConfig.Domain = externalConfig.Env["DOMAIN"]
	}
	if externalConfig.Secrets != nil {
		externalConfig.CloudflareDNSToken = externalConfig.Secrets["cloudflare-dns-token"]
		externalConfig.CloudflareZoneToken = externalConfig.Secrets["cloudflare-zone-token"]
		externalConfig.MetricsAPIKey = externalConfig.Secrets["metrics-api-key"]
		externalConfig.ACPIAPIKey = externalConfig.Secrets["acpi-api-key"]
	}

	return &config, &externalConfig, nil
}
