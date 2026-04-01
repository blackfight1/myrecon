package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type aiTestRequest struct {
	BaseURL *string `json:"baseUrl"`
	APIKey  *string `json:"apiKey"`
	Model   *string `json:"model"`
	Prompt  string  `json:"prompt"`
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

	if req.BaseURL != nil {
		cfg.BaseURL = strings.TrimSpace(*req.BaseURL)
	}
	if req.APIKey != nil {
		cfg.APIKey = strings.TrimSpace(*req.APIKey)
	}
	if req.Model != nil {
		cfg.Model = strings.TrimSpace(*req.Model)
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

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	reply, endpoint, err := testOpenAICompatible(ctx, cfg, prompt)
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

func testOpenAICompatible(ctx context.Context, cfg runtimeAISettings, prompt string) (string, string, error) {
	// Try Responses API first (newer OpenAI-compatible format).
	if reply, err := testResponsesAPI(ctx, cfg, prompt); err == nil {
		return reply, "responses", nil
	}

	// Fallback to Chat Completions for broader proxy compatibility.
	reply, err := testChatCompletionsAPI(ctx, cfg, prompt)
	if err != nil {
		return "", "", err
	}
	return reply, "chat/completions", nil
}

func testResponsesAPI(ctx context.Context, cfg runtimeAISettings, prompt string) (string, error) {
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
	if err := doAIRequest(ctx, cfg, "/responses", body, &resp); err != nil {
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

func testChatCompletionsAPI(ctx context.Context, cfg runtimeAISettings, prompt string) (string, error) {
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
	if err := doAIRequest(ctx, cfg, "/chat/completions", body, &resp); err != nil {
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

func doAIRequest(ctx context.Context, cfg runtimeAISettings, path string, payload interface{}, out interface{}) error {
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

	client := &http.Client{Timeout: 30 * time.Second}
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
		return fmt.Errorf("%s returned %d: %s", path, resp.StatusCode, msg)
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
