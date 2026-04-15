package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	commondomain "hunter/internal/common"
	"hunter/internal/engine"
)

type CorsPlugin struct {
	client        *http.Client
	maxTargets    int
	highRiskOnly  bool
	attackerHost  string
	userAgent     string
	referenceDocs string
}

type corsTarget struct {
	URL        string
	Host       string
	RootDomain string
}

type corsTest struct {
	templateID   string
	templateName string
	severity     string
	rule         string
	origin       string
	description  string
}

// NewCorsPlugin creates a high-risk CORS scanner inspired by Corsy testing logic.
func NewCorsPlugin() *CorsPlugin {
	timeoutMS := envInt("CORS_TIMEOUT_MS", 7000, 1000, 30000)
	maxTargets := envInt("CORS_MAX_TARGETS", 200, 1, 5000)
	highRiskOnly := envBool("CORS_HIGH_RISK_ONLY", true)
	attackerHost := normalizeAttackerHost(envOrDefault("CORS_ATTACKER_HOST", "evil-cors.invalid"))
	userAgent := strings.TrimSpace(envOrDefault("CORS_USER_AGENT", "myrecon-cors/1.0"))
	if userAgent == "" {
		userAgent = "myrecon-cors/1.0"
	}

	return &CorsPlugin{
		client: &http.Client{
			Timeout: time.Duration(timeoutMS) * time.Millisecond,
		},
		maxTargets:    maxTargets,
		highRiskOnly:  highRiskOnly,
		attackerHost:  attackerHost,
		userAgent:     userAgent,
		referenceDocs: "https://portswigger.net/web-security/cors",
	}
}

func (c *CorsPlugin) Name() string {
	return "Cors"
}

// Execute performs CORS checks for live HTTP targets.
// Input format follows other vuln plugins: "url|rootDomain" or plain URL.
func (c *CorsPlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	if !envBool("CORS_SCAN_ENABLED", true) {
		return []engine.Result{}, nil
	}
	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	targets := normalizeCorsTargets(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}
	if len(targets) > c.maxTargets {
		targets = targets[:c.maxTargets]
	}

	fmt.Printf("[Cors] Scanning %d live targets (high-risk-only=%v)\n", len(targets), c.highRiskOnly)

	results := make([]engine.Result, 0, len(targets))
	seen := make(map[string]bool)

	for _, target := range targets {
		tests := c.buildTests(target)
		for _, test := range tests {
			respHeaders, statusCode, err := c.requestWithOrigin(ctx, target.URL, test.origin)
			if err != nil {
				continue
			}
			finding, ok := c.evaluate(test, respHeaders)
			if !ok {
				continue
			}

			dedupeKey := strings.ToLower(strings.TrimSpace(target.URL + "|" + finding.templateID))
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			rawPayload := map[string]interface{}{
				"scanner":                "cors",
				"rule":                   finding.rule,
				"request_origin":         test.origin,
				"response_status_code":   statusCode,
				"access_control_origin":  strings.TrimSpace(respHeaders.Get("Access-Control-Allow-Origin")),
				"access_control_creds":   strings.TrimSpace(respHeaders.Get("Access-Control-Allow-Credentials")),
				"vary":                   strings.TrimSpace(respHeaders.Get("Vary")),
				"high_risk_only":         c.highRiskOnly,
				"evidence_target":        target.URL,
				"evidence_target_domain": target.Host,
			}
			rawJSON, _ := json.Marshal(rawPayload)

			result := engine.Result{
				Type: "vulnerability",
				Data: map[string]interface{}{
					"template_id":   finding.templateID,
					"template_name": finding.templateName,
					"severity":      finding.severity,
					"matched_at":    target.URL,
					"host":          target.Host,
					"domain":        target.Host,
					"root_domain":   target.RootDomain,
					"url":           target.URL,
					"matcher_name":  finding.rule,
					"description":   finding.description,
					"reference":     c.referenceDocs,
					"template_url":  c.referenceDocs,
					"raw":           string(rawJSON),
					"discovered_at": time.Now(),
				},
			}
			results = append(results, result)
			// Keep one high-risk CORS finding per endpoint to avoid noise.
			break
		}
	}

	fmt.Printf("[Cors] Scan complete, high-risk findings=%d\n", len(results))
	return results, nil
}

func (c *CorsPlugin) buildTests(target corsTarget) []corsTest {
	origins := buildCorsOrigins(target.Host, c.attackerHost)
	tests := make([]corsTest, 0, 4)
	tests = append(tests,
		corsTest{
			templateID:   "cors/high-risk-reflection-credentials",
			templateName: "高危 CORS 任意来源反射并允许凭证",
			severity:     "critical",
			rule:         "reflect_any_origin_with_credentials",
			origin:       origins.any,
			description:  "服务端对任意 Origin 反射且允许携带凭证，可能导致跨站读取敏感数据。",
		},
		corsTest{
			templateID:   "cors/high-risk-null-origin-credentials",
			templateName: "高危 CORS 允许 null 来源并允许凭证",
			severity:     "high",
			rule:         "null_origin_with_credentials",
			origin:       "null",
			description:  "服务端接受 null Origin 且允许凭证，可能在沙箱/文件上下文中被利用读取敏感数据。",
		},
	)

	if origins.prefix != "" {
		tests = append(tests, corsTest{
			templateID:   "cors/high-risk-prefix-bypass-credentials",
			templateName: "高危 CORS 前缀校验绕过并允许凭证",
			severity:     "high",
			rule:         "prefix_match_bypass_with_credentials",
			origin:       origins.prefix,
			description:  "服务端可能存在宽松前缀匹配（startsWith）导致的 CORS 绕过，并允许凭证。",
		})
	}
	if origins.suffix != "" {
		tests = append(tests, corsTest{
			templateID:   "cors/high-risk-suffix-bypass-credentials",
			templateName: "高危 CORS 后缀校验绕过并允许凭证",
			severity:     "high",
			rule:         "suffix_match_bypass_with_credentials",
			origin:       origins.suffix,
			description:  "服务端可能存在宽松后缀匹配（endsWith/contains）导致的 CORS 绕过，并允许凭证。",
		})
	}

	return tests
}

func (c *CorsPlugin) evaluate(test corsTest, headers http.Header) (corsTest, bool) {
	acao := strings.TrimSpace(headers.Get("Access-Control-Allow-Origin"))
	if acao == "" {
		return corsTest{}, false
	}
	acac := strings.EqualFold(strings.TrimSpace(headers.Get("Access-Control-Allow-Credentials")), "true")

	if c.highRiskOnly {
		if !acac {
			return corsTest{}, false
		}
		if strings.EqualFold(test.origin, "null") {
			if strings.EqualFold(acao, "null") {
				return test, true
			}
			return corsTest{}, false
		}
		if sameOriginHeader(acao, test.origin) {
			return test, true
		}
		return corsTest{}, false
	}

	// Reserved for future relaxed mode.
	if sameOriginHeader(acao, test.origin) {
		return test, true
	}
	return corsTest{}, false
}

func (c *CorsPlugin) requestWithOrigin(ctx context.Context, targetURL, origin string) (http.Header, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Range", "bytes=0-256")
	req.Header.Set("Connection", "close")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	return resp.Header.Clone(), resp.StatusCode, nil
}

type corsOrigins struct {
	any    string
	prefix string
	suffix string
}

func buildCorsOrigins(targetHost, attackerHost string) corsOrigins {
	targetHost = strings.TrimSpace(strings.ToLower(targetHost))
	attackerHost = normalizeAttackerHost(attackerHost)
	if targetHost == "" || attackerHost == "" {
		return corsOrigins{}
	}
	return corsOrigins{
		any:    "https://" + attackerHost,
		prefix: "https://" + targetHost + "." + attackerHost,
		suffix: "https://" + attackerHost + "." + targetHost,
	}
}

func normalizeCorsTargets(input []string) []corsTarget {
	seen := make(map[string]bool)
	out := make([]corsTarget, 0, len(input))

	for _, item := range input {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}

		targetURL := entry
		rootHint := ""
		if strings.Contains(entry, "|") {
			parts := strings.SplitN(entry, "|", 2)
			targetURL = strings.TrimSpace(parts[0])
			rootHint = strings.TrimSpace(parts[1])
		}
		if targetURL == "" {
			continue
		}
		parsed, err := url.Parse(targetURL)
		if err != nil {
			continue
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			continue
		}
		host := strings.TrimSpace(strings.ToLower(parsed.Hostname()))
		if host == "" {
			continue
		}
		key := normalizeTargetURLKey(parsed)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true

		rootDomain := strings.TrimSpace(strings.ToLower(rootHint))
		if rootDomain == "" {
			rootDomain = commondomain.EffectiveRootDomain(host)
		} else {
			rootDomain = commondomain.EffectiveRootDomain(rootDomain)
		}

		out = append(out, corsTarget{
			URL:        parsed.String(),
			Host:       host,
			RootDomain: rootDomain,
		})
	}
	return out
}

func normalizeTargetURLKey(parsed *url.URL) string {
	if parsed == nil {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	host := strings.ToLower(strings.TrimSpace(parsed.Host))
	if scheme == "" || host == "" {
		return ""
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	rawQuery := parsed.RawQuery
	if rawQuery != "" {
		return scheme + "://" + host + path + "?" + rawQuery
	}
	return scheme + "://" + host + path
}

func sameOriginHeader(headerValue, origin string) bool {
	return strings.EqualFold(strings.TrimSpace(headerValue), strings.TrimSpace(origin))
}

func normalizeAttackerHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimSuffix(value, "/")
	if idx := strings.Index(value, "/"); idx >= 0 {
		value = value[:idx]
	}
	if idx := strings.Index(value, ":"); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func envBool(key string, defaultVal bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultVal
	}
}

func envInt(key string, defaultVal, minVal, maxVal int) int {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return defaultVal
	}
	if n < minVal {
		return minVal
	}
	if n > maxVal {
		return maxVal
	}
	return n
}

func envOrDefault(key, defaultVal string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return defaultVal
}
