package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

type aiTestRequest struct {
	ProjectID *string `json:"projectId"`
	Enabled   *bool   `json:"enabled"`
	BaseURL   *string `json:"baseUrl"`
	APIKey    *string `json:"apiKey"`
	Model     *string `json:"model"`
	Prompt    string  `json:"prompt"`
}

func (s *Server) handleTestAI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req aiTestRequest
	if r.Body != nil {
		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
	}

	s.settingsMu.RLock()
	cfg := s.settings.AI
	s.settingsMu.RUnlock()
	cfg = normalizeRuntimeAISettings(cfg)

	projectID := ""
	if req.ProjectID != nil {
		projectID = strings.TrimSpace(*req.ProjectID)
	}
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.BaseURL != nil {
		cfg.BaseURL = strings.TrimSpace(*req.BaseURL)
	}
	if req.APIKey != nil {
		cfg.APIKey = strings.TrimSpace(*req.APIKey)
	}
	if req.Model != nil {
		cfg.Model = strings.TrimSpace(*req.Model)
	}
	cfg = normalizeRuntimeAISettings(cfg)

	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "ai is disabled globally")
		return
	}
	if projectID != "" {
		enabled, err := s.isProjectAIEnabled(projectID)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeError(w, http.StatusNotFound, "project not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to check project ai setting: "+err.Error())
			return
		}
		if !enabled {
			writeError(w, http.StatusBadRequest, "ai is disabled for this project")
			return
		}
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		writeError(w, http.StatusBadRequest, "ai baseUrl is required")
		return
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		writeError(w, http.StatusBadRequest, "ai apiKey is required")
		return
	}
	if strings.TrimSpace(cfg.Model) == "" {
		writeError(w, http.StatusBadRequest, "ai model is required")
		return
	}

	prompt := strings.TrimSpace(req.Prompt)
	if prompt == "" {
		prompt = "Reply with pong only."
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	reply, endpoint, err := s.testOpenAICompatible(ctx, cfg, prompt)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ai test failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ok",
		"provider": "openai-compatible",
		"endpoint": endpoint,
		"baseUrl":  cfg.BaseURL,
		"model":    cfg.Model,
		"reply":    reply,
	})
}

func (s *Server) testOpenAICompatible(ctx context.Context, cfg runtimeAISettings, prompt string) (string, string, error) {
	// Try Responses API first (newer OpenAI-compatible format).
	reply, errResp := s.testResponsesAPI(ctx, cfg, prompt)
	if errResp == nil {
		return reply, "responses", nil
	}

	// Fallback to Chat Completions for broader proxy compatibility.
	reply, errChat := s.testChatCompletionsAPI(ctx, cfg, prompt)
	if errChat != nil {
		return "", "", fmt.Errorf("responses failed: %v; chat/completions failed: %v", errResp, errChat)
	}
	return reply, "chat/completions", nil
}

func (s *Server) testResponsesAPI(ctx context.Context, cfg runtimeAISettings, prompt string) (string, error) {
	body := map[string]interface{}{
		"model":             cfg.Model,
		"input":             prompt,
		"max_output_tokens": 128,
	}
	var resp struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := s.doAIRequestWithRetry(ctx, cfg, "/responses", body, &resp); err != nil {
		return "", err
	}
	if txt := strings.TrimSpace(resp.OutputText); txt != "" {
		return txt, nil
	}
	for _, item := range resp.Output {
		for _, c := range item.Content {
			if strings.TrimSpace(c.Text) != "" {
				return strings.TrimSpace(c.Text), nil
			}
		}
	}
	return "", fmt.Errorf("responses API returned empty text")
}

func (s *Server) testChatCompletionsAPI(ctx context.Context, cfg runtimeAISettings, prompt string) (string, error) {
	body := map[string]interface{}{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0,
		"max_tokens":  128,
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content interface{} `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := s.doAIRequestWithRetry(ctx, cfg, "/chat/completions", body, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("chat completions returned no choices")
	}
	text := extractMessageText(resp.Choices[0].Message.Content)
	if text == "" {
		return "", fmt.Errorf("chat completions returned empty content")
	}
	return text, nil
}

type aiHTTPError struct {
	Path       string
	StatusCode int
	Message    string
}

func (e *aiHTTPError) Error() string {
	return fmt.Sprintf("%s returned %d: %s", e.Path, e.StatusCode, e.Message)
}

func (e *aiHTTPError) retryable() bool {
	switch e.StatusCode {
	case http.StatusTooManyRequests, http.StatusRequestTimeout, http.StatusConflict, http.StatusTooEarly:
		return true
	default:
		return e.StatusCode >= 500 && e.StatusCode <= 599
	}
}

func (s *Server) doAIRequestWithRetry(ctx context.Context, cfg runtimeAISettings, path string, payload interface{}, out interface{}) error {
	totalAttempts := cfg.MaxRetries + 1
	if totalAttempts < 1 {
		totalAttempts = 1
	}
	for attempt := 1; attempt <= totalAttempts; attempt++ {
		ok, waitFor := s.checkAndConsumeAILimit(cfg.RequestsPerMinute)
		if !ok {
			return fmt.Errorf("ai rate limit exceeded (%d req/min), retry after %s", cfg.RequestsPerMinute, waitFor.Truncate(time.Second))
		}

		err := s.doAIRequestOnce(ctx, cfg, path, payload, out)
		if err == nil {
			return nil
		}

		retryable := isRetryableAIError(err)
		logAIRequest(path, cfg, attempt, totalAttempts, retryable, err)
		if !retryable || attempt >= totalAttempts {
			return err
		}

		backoff := time.Duration(300*(attempt*attempt)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
	return fmt.Errorf("ai request failed")
}

func (s *Server) doAIRequestOnce(ctx context.Context, cfg runtimeAISettings, path string, payload interface{}, out interface{}) error {
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	baseURL := strings.TrimSpace(cfg.BaseURL)
	baseURL = strings.TrimRight(baseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(cfg.APIKey))

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respRaw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respRaw))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		if len(msg) > 260 {
			msg = msg[:260] + "..."
		}
		return &aiHTTPError{Path: path, StatusCode: resp.StatusCode, Message: msg}
	}
	if err := json.Unmarshal(respRaw, out); err != nil {
		return fmt.Errorf("decode %s response failed: %v", path, err)
	}
	return nil
}

func extractMessageText(content interface{}) string {
	switch v := content.(type) {
	case string:
		return strings.TrimSpace(v)
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			txt, _ := m["text"].(string)
			if strings.TrimSpace(txt) != "" {
				parts = append(parts, strings.TrimSpace(txt))
			}
		}
		return strings.TrimSpace(strings.Join(parts, "\n"))
	default:
		return ""
	}
}

func isRetryableAIError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var httpErr *aiHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.retryable()
	}
	return false
}

func logAIRequest(path string, cfg runtimeAISettings, attempt, totalAttempts int, retryable bool, err error) {
	base := strings.TrimSpace(cfg.BaseURL)
	base = strings.TrimRight(base, "/")
	if idx := strings.Index(base, "://"); idx > 0 {
		rest := base[idx+3:]
		if slash := strings.Index(rest, "/"); slash > 0 {
			rest = rest[:slash]
		}
		base = rest
	}
	log.Printf("[AI] request failed path=%s host=%s model=%s attempt=%d/%d retryable=%v err=%v",
		path, base, cfg.Model, attempt, totalAttempts, retryable, err)
}
