package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"
)

type ControlServer struct {
	kv sync.Map
}

func newControlServer() *ControlServer {
	return &ControlServer{
		kv: sync.Map{},
	}
}

func (s *ControlServer) Start(listenPort int) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("tinfoil shim"))
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"config": config,
		})
	})

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", listenPort), corsMiddleware(mux)))
}
