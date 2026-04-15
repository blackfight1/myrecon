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
	"sort"
	"strings"
	"time"

	commonpkg "hunter/internal/common"
	dbmodel "hunter/internal/db"

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

type aiSubdictTestRequest struct {
	ProjectID         *string  `json:"projectId"`
	RootDomain        string   `json:"rootDomain"`
	Subdomains        []string `json:"subdomains"`
	Enabled           *bool    `json:"enabled"`
	BaseURL           *string  `json:"baseUrl"`
	APIKey            *string  `json:"apiKey"`
	Model             *string  `json:"model"`
	SubdictEnabled    *bool    `json:"subdictEnabled"`
	SubdictMaxWords   *int     `json:"subdictMaxWords"`
	SubdictSampleSize *int     `json:"subdictSampleSize"`
}

type aiSubdictBuildResult struct {
	Prompt            string
	Reply             string
	Endpoint          string
	Words             []string
	SampledSubdomains []string
}

func (s *Server) handleTestAISubdict(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req aiSubdictTestRequest
	if r.Body != nil {
		defer r.Body.Close()
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil && err != io.EOF {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
	}

	rootDomain := normalizeRootDomain(req.RootDomain)
	if rootDomain == "" {
		writeError(w, http.StatusBadRequest, "rootDomain is required")
		return
	}
	projectID := ""
	if req.ProjectID != nil {
		projectID = strings.TrimSpace(*req.ProjectID)
	}
	if projectID != "" {
		ok, err := s.isDomainInProjectScope(projectID, rootDomain)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
			return
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "domain is not in project scope")
			return
		}
	}

	s.settingsMu.RLock()
	cfg := s.settings.AI
	s.settingsMu.RUnlock()
	cfg = normalizeRuntimeAISettings(cfg)
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
	if req.SubdictEnabled != nil {
		cfg.SubdictEnabled = *req.SubdictEnabled
	}
	if req.SubdictMaxWords != nil {
		cfg.SubdictMaxWords = *req.SubdictMaxWords
	}
	if req.SubdictSampleSize != nil {
		cfg.SubdictSampleSize = *req.SubdictSampleSize
	}
	cfg = normalizeRuntimeAISettings(cfg)

	if !cfg.Enabled {
		writeError(w, http.StatusBadRequest, "ai is disabled globally")
		return
	}
	if !cfg.SubdictEnabled {
		writeError(w, http.StatusBadRequest, "ai subdict is disabled")
		return
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

	passive := normalizeSubdomainSamples(req.Subdomains, []string{rootDomain})
	loadedFromDB := false
	if len(passive) == 0 && projectID != "" {
		items, err := s.listProjectPassiveSubdomains(projectID, rootDomain, cfg.SubdictSampleSize*8)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load project subdomains: "+err.Error())
			return
		}
		passive = items
		loadedFromDB = true
	}
	if len(passive) == 0 {
		writeError(w, http.StatusBadRequest, "subdomains are required (or provide projectId with existing passive assets)")
		return
	}

	maxWords := clampIntRange(cfg.SubdictMaxWords, 20, 5000)
	baselineWords := commonpkg.BuildBruteforceWordlist(passive, []string{rootDomain}, maxWords)

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	aiResult, err := s.generateAISubdictWords(ctx, cfg, []string{rootDomain}, passive, maxWords, cfg.SubdictSampleSize)
	if err != nil {
		writeError(w, http.StatusBadGateway, "ai subdict test failed: "+err.Error())
		return
	}

	mergedWords, aiUsed := blendActiveBruteforceWords(baselineWords, aiResult.Words, maxWords)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":              "ok",
		"projectId":           projectID,
		"rootDomain":          rootDomain,
		"loadedFromProject":   loadedFromDB,
		"sourceSubdomainCnt":  len(passive),
		"sampledSubdomainCnt": len(aiResult.SampledSubdomains),
		"sampledSubdomains":   previewWords(aiResult.SampledSubdomains, 80),
		"endpoint":            aiResult.Endpoint,
		"baselineCount":       len(baselineWords),
		"baselineWords":       previewWords(baselineWords, 120),
		"aiCount":             len(aiResult.Words),
		"aiWords":             previewWords(aiResult.Words, 120),
		"mergedCount":         len(mergedWords),
		"mergedWords":         previewWords(mergedWords, 150),
		"aiWordsUsed":         aiUsed,
		"promptPreview":       trimForNotify(aiResult.Prompt, 1200),
		"replyPreview":        trimForNotify(aiResult.Reply, 1200),
	})
}

func (s *Server) buildActiveBruteforceWordlist(ctx context.Context, projectID string, rootDomains, passiveSubdomains []string, maxWords int) ([]string, int) {
	if maxWords <= 0 {
		maxWords = 800
	}
	baselineWords := commonpkg.BuildBruteforceWordlist(passiveSubdomains, rootDomains, maxWords)

	cfg, aiEnabled, _, err := s.resolveAISubdictRuntimeConfig(projectID)
	if err != nil {
		log.Printf("[AI] active subdict config failed project=%s: %v", projectID, err)
		return baselineWords, 0
	}
	if !aiEnabled {
		return baselineWords, 0
	}
	if len(passiveSubdomains) == 0 {
		return baselineWords, 0
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	aiCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	aiMaxWords := cfg.SubdictMaxWords
	if aiMaxWords > maxWords {
		aiMaxWords = maxWords
	}
	aiResult, err := s.generateAISubdictWords(aiCtx, cfg, rootDomains, passiveSubdomains, aiMaxWords, cfg.SubdictSampleSize)
	if err != nil {
		log.Printf("[AI] active subdict generation failed project=%s roots=%v: %v", projectID, rootDomains, err)
		return baselineWords, 0
	}
	merged, aiUsed := blendActiveBruteforceWords(baselineWords, aiResult.Words, maxWords)
	log.Printf("[AI] active subdict merged project=%s endpoint=%s sampled=%d ai_words=%d used=%d total=%d",
		projectID, aiResult.Endpoint, len(aiResult.SampledSubdomains), len(aiResult.Words), aiUsed, len(merged))
	return merged, aiUsed
}

func (s *Server) resolveAISubdictRuntimeConfig(projectID string) (runtimeAISettings, bool, string, error) {
	// API and worker are separate processes. Reload persisted AI settings so
	// worker-side behavior follows latest settings changes without service restart.
	if err := s.loadPersistedAISettings(); err != nil {
		log.Printf("[AI] reload persisted settings failed: %v", err)
	}

	s.settingsMu.RLock()
	cfg := normalizeRuntimeAISettings(s.settings.AI)
	s.settingsMu.RUnlock()

	if !cfg.Enabled {
		return cfg, false, "ai disabled globally", nil
	}
	if !cfg.SubdictEnabled {
		return cfg, false, "ai subdict disabled", nil
	}
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.APIKey) == "" || strings.TrimSpace(cfg.Model) == "" {
		return cfg, false, "ai settings incomplete", nil
	}
	if strings.TrimSpace(projectID) != "" {
		enabled, err := s.isProjectAIEnabled(projectID)
		if err != nil {
			return cfg, false, "", err
		}
		if !enabled {
			return cfg, false, "project ai disabled", nil
		}
	}
	return cfg, true, "", nil
}

func (s *Server) generateAISubdictWords(ctx context.Context, cfg runtimeAISettings, rootDomains, passiveSubdomains []string, maxWords, sampleSize int) (aiSubdictBuildResult, error) {
	maxWords = clampIntRange(maxWords, 20, 5000)
	sampleSize = clampIntRange(sampleSize, 20, 2000)
	sampled := sampleSubdomainsForPrompt(passiveSubdomains, rootDomains, sampleSize)
	if len(sampled) == 0 {
		return aiSubdictBuildResult{}, fmt.Errorf("no passive subdomains for ai prompt")
	}

	roots := make([]string, 0, len(rootDomains))
	for _, raw := range rootDomains {
		if rd := normalizeRootDomain(raw); rd != "" {
			roots = append(roots, rd)
		}
	}
	if len(roots) == 0 {
		roots = append(roots, commonpkg.EffectiveRootDomain(sampled[0]))
	}

	prompt := buildAISubdictPrompt(roots, sampled, maxWords)
	maxOutputTokens := clampIntRange(maxWords*6, 256, 4096)
	reply, endpoint, err := s.requestOpenAICompatibleText(ctx, cfg, prompt, maxOutputTokens)
	if err != nil {
		return aiSubdictBuildResult{}, err
	}
	words := parseAISubdictWords(reply, maxWords)
	if len(words) == 0 {
		return aiSubdictBuildResult{}, fmt.Errorf("ai returned empty or invalid wordlist")
	}
	return aiSubdictBuildResult{
		Prompt:            prompt,
		Reply:             reply,
		Endpoint:          endpoint,
		Words:             words,
		SampledSubdomains: sampled,
	}, nil
}

func buildAISubdictPrompt(rootDomains, sampledSubdomains []string, maxWords int) string {
	var sb strings.Builder
	sb.WriteString("You are an expert recon assistant for subdomain brute-force strategy.\n")
	sb.WriteString("Task: infer high-value subdomain labels from observed passive subdomains.\n")
	sb.WriteString("Output requirements:\n")
	sb.WriteString("1) Return ONLY JSON, no markdown, no explanation.\n")
	sb.WriteString("2) JSON format: {\"words\":[\"api\",\"admin\"]}\n")
	sb.WriteString("3) Use lowercase letters, numbers, and hyphen only.\n")
	sb.WriteString("4) Each word length: 2-40.\n")
	sb.WriteString("5) Do not include dots, wildcards, spaces, root domains, or TLDs.\n")
	sb.WriteString("6) Avoid generic noise words: www, mail, ftp, autodiscover, localhost.\n")
	sb.WriteString(fmt.Sprintf("7) Return at most %d words.\n", maxWords))
	sb.WriteString("8) Focus on likely business assets and environments (admin, api, dev, staging, auth, gateway, etc.).\n")
	sb.WriteString("Root domains:\n")
	for _, root := range rootDomains {
		sb.WriteString("- ")
		sb.WriteString(strings.TrimSpace(root))
		sb.WriteString("\n")
	}
	sb.WriteString("Observed passive subdomains:\n")
	for _, sub := range sampledSubdomains {
		sb.WriteString("- ")
		sb.WriteString(strings.TrimSpace(sub))
		sb.WriteString("\n")
	}
	return sb.String()
}

func parseAISubdictWords(reply string, maxWords int) []string {
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return nil
	}
	candidates := []string{reply}
	if block := extractCodeBlockJSON(reply); block != "" && block != reply {
		candidates = append(candidates, block)
	}
	if obj := extractJSONEnvelope(reply, '{', '}'); obj != "" && obj != reply {
		candidates = append(candidates, obj)
	}
	if arr := extractJSONEnvelope(reply, '[', ']'); arr != "" && arr != reply {
		candidates = append(candidates, arr)
	}

	for _, raw := range candidates {
		if words := parseAISubdictJSON(raw, maxWords); len(words) > 0 {
			return words
		}
	}

	parts := strings.FieldsFunc(reply, func(r rune) bool {
		switch r {
		case '\n', '\r', '\t', ',', ';', '|':
			return true
		default:
			return false
		}
	})
	return commonpkg.NormalizeBruteforceWords(parts, maxWords)
}

func parseAISubdictJSON(raw string, maxWords int) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(raw), &arr); err == nil {
		return commonpkg.NormalizeBruteforceWords(arr, maxWords)
	}
	var obj struct {
		Words      []string `json:"words"`
		Candidates []string `json:"candidates"`
		Items      []string `json:"items"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal([]byte(raw), &obj); err == nil {
		merged := append([]string{}, obj.Words...)
		merged = append(merged, obj.Candidates...)
		merged = append(merged, obj.Items...)
		merged = append(merged, obj.Subdomains...)
		return commonpkg.NormalizeBruteforceWords(merged, maxWords)
	}
	return nil
}

func extractCodeBlockJSON(raw string) string {
	start := strings.Index(raw, "```")
	if start < 0 {
		return ""
	}
	rest := raw[start+3:]
	end := strings.Index(rest, "```")
	if end < 0 {
		return ""
	}
	block := strings.TrimSpace(rest[:end])
	block = strings.TrimPrefix(block, "json")
	block = strings.TrimPrefix(block, "JSON")
	return strings.TrimSpace(block)
}

func extractJSONEnvelope(raw string, left, right rune) string {
	start := strings.IndexRune(raw, left)
	if start < 0 {
		return ""
	}
	end := strings.LastIndex(raw, string(right))
	if end <= start {
		return ""
	}
	return strings.TrimSpace(raw[start : end+1])
}

func blendActiveBruteforceWords(baselineWords, aiWords []string, maxWords int) ([]string, int) {
	maxWords = clampIntRange(maxWords, 20, 100000)
	baseline := commonpkg.NormalizeBruteforceWords(baselineWords, maxWords)
	ai := commonpkg.NormalizeBruteforceWords(aiWords, maxWords)
	if len(ai) == 0 {
		return baseline, 0
	}

	aiQuota := maxWords / 4
	if aiQuota < 1 {
		aiQuota = 1
	}
	if aiQuota > 300 {
		aiQuota = 300
	}
	if aiQuota > len(ai) {
		aiQuota = len(ai)
	}

	out := commonpkg.MergeBruteforceWordlists(ai[:aiQuota], baseline, maxWords)
	if len(out) < maxWords && aiQuota < len(ai) {
		out = commonpkg.MergeBruteforceWordlists(out, ai[aiQuota:], maxWords)
	}
	aiSet := make(map[string]bool, len(ai))
	for _, w := range ai {
		aiSet[w] = true
	}
	aiUsed := 0
	for _, w := range out {
		if aiSet[w] {
			aiUsed++
		}
	}
	return out, aiUsed
}

func normalizeSubdomainSamples(items, rootDomains []string) []string {
	roots := make([]string, 0, len(rootDomains))
	for _, raw := range rootDomains {
		if rd := normalizeRootDomain(raw); rd != "" {
			roots = append(roots, rd)
		}
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, raw := range items {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" {
			continue
		}
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "https://")
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx >= 0 {
			host = host[:idx]
		}
		host = strings.Trim(host, ".")
		if host == "" || !strings.Contains(host, ".") {
			continue
		}
		if len(roots) > 0 {
			matched := false
			for _, root := range roots {
				if host == root || strings.HasSuffix(host, "."+root) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func sampleSubdomainsForPrompt(subdomains, rootDomains []string, sampleSize int) []string {
	sampleSize = clampIntRange(sampleSize, 20, 2000)
	normalized := normalizeSubdomainSamples(subdomains, rootDomains)
	if len(normalized) <= sampleSize {
		return normalized
	}
	head := sampleSize * 2 / 3
	if head <= 0 {
		head = sampleSize / 2
	}
	if head > sampleSize {
		head = sampleSize
	}
	tail := sampleSize - head
	out := make([]string, 0, sampleSize)
	out = append(out, normalized[:head]...)
	if tail > 0 {
		out = append(out, normalized[len(normalized)-tail:]...)
	}
	return out
}

func previewWords(items []string, limit int) []string {
	if limit <= 0 || len(items) == 0 {
		return []string{}
	}
	if len(items) <= limit {
		out := make([]string, len(items))
		copy(out, items)
		return out
	}
	out := make([]string, limit)
	copy(out, items[:limit])
	return out
}

func (s *Server) listProjectPassiveSubdomains(projectID, rootDomain string, limit int) ([]string, error) {
	projectID = strings.TrimSpace(projectID)
	rootDomain = normalizeRootDomain(rootDomain)
	if projectID == "" || rootDomain == "" {
		return nil, nil
	}
	limit = clampIntRange(limit, 20, 20000)
	pattern := "%." + rootDomain

	collected := make([]string, 0, limit)
	addRows := func(rows []string) {
		collected = append(collected, rows...)
	}

	var candidateRows []string
	if err := s.db.DB.Model(&dbmodel.AssetCandidate{}).
		Distinct("domain").
		Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
		Order("domain asc").
		Limit(limit).
		Pluck("domain", &candidateRows).Error; err != nil {
		return nil, err
	}
	addRows(candidateRows)

	if len(collected) < limit {
		var assetRows []string
		if err := s.db.DB.Model(&dbmodel.Asset{}).
			Distinct("domain").
			Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
			Order("domain asc").
			Limit(limit-len(collected)).
			Pluck("domain", &assetRows).Error; err != nil {
			return nil, err
		}
		addRows(assetRows)
	}
	return normalizeSubdomainSamples(collected, []string{rootDomain}), nil
}

func (s *Server) testOpenAICompatible(ctx context.Context, cfg runtimeAISettings, prompt string) (string, string, error) {
	return s.requestOpenAICompatibleText(ctx, cfg, prompt, 128)
}

func (s *Server) requestOpenAICompatibleText(ctx context.Context, cfg runtimeAISettings, prompt string, maxOutputTokens int) (string, string, error) {
	if maxOutputTokens <= 0 {
		maxOutputTokens = 128
	}
	// Try Responses API first (newer OpenAI-compatible format).
	reply, errResp := s.testResponsesAPI(ctx, cfg, prompt, maxOutputTokens)
	if errResp == nil {
		return reply, "responses", nil
	}

	// Fallback to Chat Completions for broader proxy compatibility.
	reply, errChat := s.testChatCompletionsAPI(ctx, cfg, prompt, maxOutputTokens)
	if errChat != nil {
		return "", "", fmt.Errorf("responses failed: %v; chat/completions failed: %v", errResp, errChat)
	}
	return reply, "chat/completions", nil
}

func (s *Server) testResponsesAPI(ctx context.Context, cfg runtimeAISettings, prompt string, maxOutputTokens int) (string, error) {
	if maxOutputTokens <= 0 {
		maxOutputTokens = 128
	}
	body := map[string]interface{}{
		"model":             cfg.Model,
		"input":             prompt,
		"max_output_tokens": maxOutputTokens,
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

func (s *Server) testChatCompletionsAPI(ctx context.Context, cfg runtimeAISettings, prompt string, maxOutputTokens int) (string, error) {
	if maxOutputTokens <= 0 {
		maxOutputTokens = 128
	}
	body := map[string]interface{}{
		"model": cfg.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": 0,
		"max_tokens":  maxOutputTokens,
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
