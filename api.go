package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
	ehbpProtocol "github.com/tinfoilsh/stransport/protocol"
	"github.com/tinfoilsh/tfshim/key"
	"github.com/tinfoilsh/tfshim/key/online"
	"github.com/tinfoilsh/verifier/attestation"
)

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			// Allow only configured origins
			if len(config.OriginDomains) > 0 && !slices.Contains(config.OriginDomains, origin) {
				log.Debugf("CORS origin not allowed: %s", origin)
				http.Error(w, "shim: 403 CORS origin not allowed", http.StatusForbidden)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin") // cache
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Encapsulated-Key, Content-Type")

			// Echo requested headers or use a safe default
			reqHdr := r.Header.Get("Access-Control-Request-Headers")
			if reqHdr == "" {
				reqHdr = "Authorization, Content-Type, Ehbp-Client-Public-Key, Ehbp-Encapsulated-Key"
			}
			w.Header().Set("Access-Control-Allow-Headers", reqHdr)

			if r.Method == http.MethodOptions {
				log.Debugf("CORS OPTIONS request: %s", origin)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			log.Tracef("CORS request allowed: %s", origin)
		}

		next.ServeHTTP(w, r)
	})
}

type Metrics struct {
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	Image       string `json:"image"`
	CPUUtil     int    `json:"cpu_util"`
	GPUUtil     int    `json:"gpu_util,omitempty"`
	CPUMemUtil  int    `json:"cpu_mem_util"`
	GPUMemUtil  int    `json:"gpu_mem_util,omitempty"`
	CPUMemTotal int    `json:"cpu_mem_total"`
	GPUMemTotal int    `json:"gpu_mem_total,omitempty"`
	CPUType     string `json:"cpu_type"`
	GPUType     string `json:"gpu_type,omitempty"`
}

func gpuMetrics() (int, int, int, error) {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		return 0, 0, 0, fmt.Errorf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
	}
	defer nvml.Shutdown()

	var totalMem, usedMem, totalUtil int

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return 0, 0, 0, fmt.Errorf("Unable to get device count: %v", nvml.ErrorString(ret))
	}
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return 0, 0, 0, fmt.Errorf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		info, ret := nvml.DeviceGetMemoryInfo_v2(device)
		if ret != nvml.SUCCESS {
			return 0, 0, 0, fmt.Errorf("Unable to get memory info for device at index %d: %v", i, nvml.ErrorString(ret))
		}
		totalMem += int(info.Total / 1024 / 1024 / 1024) // to GB
		usedMem += int(info.Used / 1024 / 1024 / 1024)

		// Get GPU utilization rates
		rates, ret := nvml.DeviceGetUtilizationRates(device)
		if ret != nvml.SUCCESS {
			return 0, 0, 0, fmt.Errorf("Unable to get utilization rates for device at index %d: %v", i, nvml.ErrorString(ret))
		} else {
			totalUtil += int(rates.Gpu)
		}
	}

	// Calculate average utilization across all GPUs
	avgUtil := 0
	if count > 0 && totalUtil > 0 {
		avgUtil = totalUtil / count
	}

	return totalMem, usedMem, avgUtil, nil
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if externalConfig.MetricsAPIKey != "" {
		apiKey := strings.TrimPrefix(
			r.Header.Get("Authorization"),
			"Bearer ",
		)
		if apiKey != externalConfig.MetricsAPIKey {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	metrics := Metrics{
		ID:      externalConfig.Metadata.ID,
		Domain:  externalConfig.Metadata.Domain,
		Image:   externalConfig.Metadata.Image,
		CPUType: externalConfig.Metadata.CPU,
	}

	memory, err := memory.Get()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	metrics.CPUMemTotal = int(memory.Total / 1024 / 1024 / 1024) // to GB
	metrics.CPUMemUtil = int(memory.Used / 1024 / 1024 / 1024)

	cpuStats, err := cpu.Get()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	busy := cpuStats.User + cpuStats.System + cpuStats.Nice
	total := busy + cpuStats.Idle
	metrics.CPUUtil = int(float64(busy) / float64(total) * 100)

	// Set GPU metrics if available
	if externalConfig.Metadata.GPU != "" && externalConfig.Metadata.GPU != "none" {
		totalMem, usedMem, gpuUtil, err := gpuMetrics()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		metrics.GPUMemTotal = totalMem
		metrics.GPUMemUtil = usedMem
		metrics.GPUUtil = gpuUtil
		metrics.GPUType = externalConfig.Metadata.GPU
	}

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func newMux(
	validator key.Validator,
	rateLimiter *RateLimiter,
	att *attestation.Document,
	ehbpIdentity *identity.Identity,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware(true)
	mux := http.NewServeMux()

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
			req.Header.Set("Host", "localhost")
			req.Host = "localhost"
			log.Debugf("Proxying request to %+v", req.URL.String())
		},
		Transport: &streamTransport{
			base: http.DefaultTransport,
		},
		ModifyResponse: func(res *http.Response) error {
			res.Header.Del("Access-Control-Allow-Origin")
			return nil
		},
	}

	mux.Handle("/", ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if validator != nil && r.URL.Path == "/v1/chat/completions" {
			if len(apiKey) == 0 {
				http.Error(w, "shim: 401 API key required", http.StatusUnauthorized)
				return
			}

			if err := validator.Validate(apiKey); err != nil {
				log.Warnf("Failed to validate API key: %v", err)
				var validationErr *online.ValidationError
				if errors.As(err, &validationErr) {
					http.Error(w, validationErr.Message, validationErr.StatusCode)
				} else {
					http.Error(w, "shim: 500 validation error", http.StatusInternalServerError)
				}
				return
			}
		}

		if rateLimiter != nil {
			if apiKey == "" {
				http.Error(w, "shim: 401 API key required", http.StatusUnauthorized)
				return
			}
			limiter := rateLimiter.Limit(apiKey)
			if !limiter.Allow() {
				http.Error(w, "shim: 429 rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if len(config.Paths) > 0 && !slices.Contains(config.Paths, r.URL.Path) {
			http.Error(w, "shim: 403 path not allowed", http.StatusForbidden)
			return
		}

		proxy.ServeHTTP(w, r)
	})))

	mux.Handle("/.well-known/tinfoil-attestation", ehbpMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})))

	mux.HandleFunc("/.well-known/tinfoil-metrics", handleMetrics)

	mux.HandleFunc(ehbpProtocol.KeysPath, ehbpIdentity.ConfigHandler)

	return corsMiddleware(mux)
}
