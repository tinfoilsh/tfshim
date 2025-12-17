package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpProtocol "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"
	"github.com/tinfoilsh/tfshim/acpi"
	"github.com/tinfoilsh/tfshim/config"
	"github.com/tinfoilsh/tfshim/key"
	"github.com/tinfoilsh/tfshim/key/online"
	"github.com/tinfoilsh/tfshim/metrics"
	"github.com/tinfoilsh/verifier/attestation"
)

func corsMiddleware(config *config.Config, next http.Handler) http.Handler {
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
			w.Header().Set("Access-Control-Expose-Headers", "Ehbp-Encapsulated-Key, Ehbp-Response-Nonce, Content-Type, Tinfoil-Pt")

			// Echo requested headers or use a safe default
			reqHdr := r.Header.Get("Access-Control-Request-Headers")
			if reqHdr == "" {
				reqHdr = "Authorization, Content-Type, Ehbp-Encapsulated-Key"
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

func NewShimServer(
	validator key.Validator,
	rateLimiter *RateLimiter,
	att *attestation.Document,
	ehbpIdentity *identity.Identity,
	config *config.Config,
	externalConfig *config.ExternalConfig,
) http.Handler {
	ehbpMiddleware := ehbpIdentity.Middleware(true)
	mux := http.NewServeMux()

	proxy := httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := req.Host

			req.URL.Scheme = "http"
			req.URL.Host = fmt.Sprintf("127.0.0.1:%d", config.UpstreamPort)
			req.Header.Set("Host", "localhost")
			req.Host = "localhost"
			req.Header.Del("Ehbp-Fallback")

			// Forward original host and protocol to the upstream
			req.Header.Del("Forwarded")
			req.Header.Del("X-Forwarded-Host")
			req.Header.Set("Forwarded", fmt.Sprintf("host=\"%s\"", originalHost))
			req.Header.Set("X-Forwarded-Host", originalHost)

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

	globalMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Tinfoil-Pt", string(att.Format))
			next.ServeHTTP(w, r)
		})
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

	mux.HandleFunc("/.well-known/tinfoil-metrics", metrics.HandleMetrics(externalConfig))
	mux.HandleFunc("/.well-known/tinfoil-acpi", acpi.HandleQemuACPI(config, externalConfig))
	mux.HandleFunc("/.well-known/metrics", metrics.HandlePrometheusMetrics(&externalConfig.Metadata, externalConfig.MetricsAPIKey))
	mux.HandleFunc(ehbpProtocol.KeysPath, ehbpIdentity.ConfigHandler)

	return corsMiddleware(config, globalMiddleware(mux))
}
