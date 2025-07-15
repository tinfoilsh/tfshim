package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type tokenRequest struct {
	APIKey string `json:"api_key"`
	Tokens int    `json:"tokens"`
	Model  string `json:"model"`
}

type TokenRecorder struct {
	shimCollectURL string
	queue          []tokenRequest
	mutex          sync.Mutex
	ticker         *time.Ticker
}

func NewTokenRecorder(shimCollectURL string) *TokenRecorder {
	return &TokenRecorder{
		shimCollectURL: shimCollectURL,
		queue:          make([]tokenRequest, 0),
	}
}

func (r *TokenRecorder) Record(apiKey, model string, tokens int) {
	go func() {
		r.mutex.Lock()
		r.queue = append(r.queue, tokenRequest{
			APIKey: apiKey,
			Tokens: tokens,
			Model:  model,
		})
		r.mutex.Unlock()
	}()
}

func (r *TokenRecorder) Start() {
	r.ticker = time.NewTicker(2 * time.Second)

	go func() {
		for range r.ticker.C {
			var requests []tokenRequest

			// Get all queued requests atomically
			r.mutex.Lock()
			if len(r.queue) > 0 {
				requests = r.queue
				r.queue = make([]tokenRequest, 0, len(requests)) // Preallocate new slice with same capacity
			}
			r.mutex.Unlock()

			// Process all requests
			for _, req := range requests {
				r.account(req)
			}
		}
	}()
}

func (r *TokenRecorder) Stop() {
	if r.ticker != nil {
		r.ticker.Stop()
	}
}

func (r *TokenRecorder) account(m tokenRequest) {
	body, err := json.Marshal(m)
	if err != nil {
		log.Warnf("Failed to marshal response: %v", err)
		return
	}

	log.Debugf("Sending %d %s tokens to %s", m.Tokens, m.Model, r.shimCollectURL)
	resp, err := http.Post(r.shimCollectURL, "application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Warnf("Failed to post response: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Warnf("Failed to post response: %v", resp.Status)
		return
	}
}
