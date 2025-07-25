package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type streamingResponse struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Object  string `json:"object"`
	Usage   *usage `json:"usage,omitempty"`

	Choices []struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Delta        struct {
			Role    string `json:"role"`
			Content string `json:"content"`
			Padding string `json:"p"`
		} `json:"delta"`
	} `json:"choices"`
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"` // String or array of content parts
	} `json:"messages"`
}

type streamTransport struct {
	base http.RoundTripper
}

func (t *streamTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/v1/chat/completions" {
		return t.base.RoundTrip(req)
	}

	var cr chatRequest
	if body, err := io.ReadAll(req.Body); err == nil {
		if err := json.Unmarshal(body, &cr); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request body: %w", err)
		}
		// Restore the body
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Make the actual request
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if !cr.Stream {
		log.Debug("Not streaming")
		return resp, nil
	} else {
		log.Debug("Starting stream")
	}

	// SSE headers
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Connection", "keep-alive")
	resp.Header.Del("Content-Length")

	// Create a pipe to modify the response stream
	pr, pw := io.Pipe()
	originalBody := resp.Body
	resp.Body = pr

	go func() {
		defer originalBody.Close()
		defer pw.Close()

		scanner := bufio.NewScanner(originalBody)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") && line != "data: [DONE]" {
				var stream streamingResponse
				data := strings.TrimPrefix(line, "data: ")
				if err := json.Unmarshal([]byte(data), &stream); err != nil {
					pw.Write([]byte(line + "\n"))
					continue
				}

				// Add padding to first choice if available
				if len(stream.Choices) > 0 {
					const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
					minLength := 4
					maxLength := len(charset)
					r, err := rand.Int(rand.Reader, big.NewInt(int64(maxLength-minLength+1)))
					if err != nil {
						log.Warnf("Failed to generate random padding: %v", err)
						continue
					}
					stream.Choices[0].Delta.Padding = charset[:minLength+int(r.Int64())]
				}

				// Write modified data
				modifiedData, err := json.Marshal(stream)
				if err != nil {
					pw.Write([]byte(line + "\n"))
					continue
				}
				pw.Write([]byte("data: " + string(modifiedData) + "\n"))
			} else {
				pw.Write([]byte(line + "\n"))
			}
		}

	}()

	return resp, nil
}
