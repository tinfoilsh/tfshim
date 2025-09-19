package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tinfoilsh/stransport/identity"
	ehbpProtocol "github.com/tinfoilsh/stransport/protocol"
	"github.com/tinfoilsh/tfshim/key"
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
				http.Error(w, "shim: 401 invalid API key", http.StatusUnauthorized)
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

	mux.HandleFunc(ehbpProtocol.KeysPath, ehbpIdentity.ConfigHandler)

	return corsMiddleware(mux)
}
