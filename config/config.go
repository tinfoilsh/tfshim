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

type Metadata struct {
	ID     string `yaml:"id"`
	Domain string `yaml:"domain"`
	Image  string `yaml:"image"`
	GPU    string `yaml:"gpu"`
}

type ExternalConfig struct {
	Domain              string   `yaml:"domain"`
	CloudflareDNSToken  string   `yaml:"cloudflare-dns-token"`
	CloudflareZoneToken string   `yaml:"cloudflare-zone-token"`
	MetricsAPIKey       string   `yaml:"metrics-api-key"`
	Metadata            Metadata `yaml:"metadata"`
}

// Load loads the config from the given files
func Load(configFile, externalConfigFile string) (*Config, *ExternalConfig, error) {
	configBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}
	var config Config
	if err := yaml.Unmarshal(configBytes, &config); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal config: %v", err)
	}
	if err := defaults.Set(&config); err != nil {
		return nil, nil, fmt.Errorf("failed to set defaults: %v", err)
	}

	if config.UpstreamPort == 0 {
		return nil, nil, fmt.Errorf("upstream port is not set")
	}
	if !slices.Contains([]string{"self-signed", "staging", "production"}, config.TLSMode) {
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

	return &config, &externalConfig, nil
}
