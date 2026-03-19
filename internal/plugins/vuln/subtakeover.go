package vuln

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	commondomain "hunter/internal/common"
	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

const defaultSubTakeoverReference = "https://github.com/haccer/subjack"

// SubTakeoverPlugin detects potential subdomain takeover risks via subjack.
type SubTakeoverPlugin struct {
	maxTargets     int
	concurrency    int
	timeoutSec     int
	forceHTTPS     bool
	checkAll       bool
	manualMode     bool
	checkNS        bool
	checkAR        bool
	checkAXFR      bool
	checkMail      bool
	resolverList   string
	severity       string
	excludeEngines map[string]bool
}

type subTakeoverTarget struct {
	host       string
	rootDomain string
}

type subjackResult struct {
	Subdomain  string `json:"subdomain"`
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
	Domain     string `json:"nonexist_domain,omitempty"`
}

// NewSubTakeoverPlugin creates a subdomain takeover plugin instance.
func NewSubTakeoverPlugin() *SubTakeoverPlugin {
	excluded := parseCSVEnv("SUBTAKEOVER_EXCLUDE_ENGINES", nil, true)
	excludedSet := make(map[string]bool, len(excluded))
	for _, v := range excluded {
		k := strings.TrimSpace(strings.ToLower(v))
		if k == "" {
			continue
		}
		excludedSet[k] = true
	}

	severity := strings.TrimSpace(strings.ToLower(envOrDefault("SUBTAKEOVER_SEVERITY", "high")))
	if severity == "" {
		severity = "high"
	}

	return &SubTakeoverPlugin{
		maxTargets:     envInt("SUBTAKEOVER_MAX_TARGETS", 3000, 1, 20000),
		concurrency:    envInt("SUBTAKEOVER_CONCURRENCY", 20, 1, 200),
		timeoutSec:     envInt("SUBTAKEOVER_TIMEOUT_SEC", 10, 1, 60),
		forceHTTPS:     envBool("SUBTAKEOVER_FORCE_HTTPS", true),
		checkAll:       envBool("SUBTAKEOVER_CHECK_ALL", true),
		manualMode:     envBool("SUBTAKEOVER_MANUAL", false),
		checkNS:        envBool("SUBTAKEOVER_CHECK_NS", false),
		checkAR:        envBool("SUBTAKEOVER_CHECK_AR", false),
		checkAXFR:      envBool("SUBTAKEOVER_CHECK_AXFR", false),
		checkMail:      envBool("SUBTAKEOVER_CHECK_MAIL", false),
		resolverList:   strings.TrimSpace(os.Getenv("SUBTAKEOVER_RESOLVER_LIST")),
		severity:       severity,
		excludeEngines: excludedSet,
	}
}

// Name returns plugin name.
func (s *SubTakeoverPlugin) Name() string {
	return "SubTakeover"
}

// Execute runs subjack and converts findings into the unified vulnerability format.
// Input supports either plain host/domain or "target|rootDomain" style.
func (s *SubTakeoverPlugin) Execute(input []string) ([]engine.Result, error) {
	if !envBool("SUBTAKEOVER_SCAN_ENABLED", true) {
		return []engine.Result{}, nil
	}
	if _, err := exec.LookPath("subjack"); err != nil {
		return nil, fmt.Errorf("subjack not found in PATH. Please install subjack and ensure it's in your PATH")
	}
	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	targets := normalizeSubTakeoverTargets(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}
	if len(targets) > s.maxTargets {
		targets = targets[:s.maxTargets]
	}

	hostLines := make([]string, 0, len(targets))
	rootHints := make(map[string]string, len(targets))
	for _, t := range targets {
		hostLines = append(hostLines, t.host)
		if t.rootDomain != "" {
			rootHints[t.host] = t.rootDomain
		}
	}

	fmt.Printf("[SubTakeover] Scanning %d hosts...\n", len(hostLines))

	targetFile, err := common.CreateTempFile("subtakeover_targets_*.txt", hostLines)
	if err != nil {
		return nil, fmt.Errorf("failed to create subjack target file: %v", err)
	}
	defer common.RemoveTempFile(targetFile)

	outputFile, err := os.CreateTemp("", "subtakeover_result_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create subjack output file: %v", err)
	}
	outputPath := outputFile.Name()
	if err := outputFile.Close(); err != nil {
		_ = os.Remove(outputPath)
		return nil, fmt.Errorf("failed to close subjack output file: %v", err)
	}
	defer os.Remove(outputPath)

	args := []string{
		"-w", targetFile,
		"-o", outputPath,
		"-t", strconv.Itoa(s.concurrency),
		"-timeout", strconv.Itoa(s.timeoutSec),
	}
	if s.forceHTTPS {
		args = append(args, "-ssl")
	}
	if s.checkAll {
		args = append(args, "-a")
	}
	if s.manualMode {
		args = append(args, "-m")
	}
	if s.checkNS {
		args = append(args, "-ns")
	}
	if s.checkAR {
		args = append(args, "-ar")
	}
	if s.checkAXFR {
		args = append(args, "-axfr")
	}
	if s.checkMail {
		args = append(args, "-mail")
	}
	if s.resolverList != "" {
		args = append(args, "-r", s.resolverList)
	}

	cmd := exec.Command("subjack", args...)
	output, runErr := cmd.CombinedOutput()

	results, parseErr := s.parseSubjackOutput(outputPath, rootHints)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("subjack execution failed: %v; parse output failed: %v", runErr, parseErr)
		}
		return nil, fmt.Errorf("failed to parse subjack output: %v", parseErr)
	}

	if runErr != nil {
		if len(results) == 0 {
			detail := strings.TrimSpace(string(output))
			if detail == "" {
				return nil, fmt.Errorf("subjack execution failed: %v", runErr)
			}
			return nil, fmt.Errorf("subjack execution failed: %v | output=%s", runErr, compactLog(detail, 280))
		}
		fmt.Printf("[SubTakeover] Command finished with warning: %v\n", runErr)
	}

	fmt.Printf("[SubTakeover] Scan complete, findings=%d\n", len(results))
	return results, nil
}

func (s *SubTakeoverPlugin) parseSubjackOutput(path string, rootHints map[string]string) ([]engine.Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return []engine.Result{}, nil
	}

	rows, err := parseSubjackRows(raw)
	if err != nil {
		return nil, err
	}

	results := make([]engine.Result, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		host := normalizeHostForTakeover(row.Subdomain)
		if host == "" {
			continue
		}

		if !row.Vulnerable {
			continue
		}
		engineName := strings.TrimSpace(row.Service)
		engineKey := strings.ToLower(engineName)
		if engineKey == "" && row.Domain != "" {
			engineKey = "unregistered-domain"
		}
		if engineKey != "" && s.excludeEngines[engineKey] {
			continue
		}
		if engineKey == "" {
			engineKey = "unknown"
		}

		dedupeKey := host + "|" + engineKey
		if seen[dedupeKey] {
			continue
		}
		seen[dedupeKey] = true

		rootDomain := rootHints[host]
		if rootDomain == "" {
			rootDomain = commondomain.EffectiveRootDomain(host)
		}

		templateSuffix := sanitizeTemplateToken(engineKey)
		if templateSuffix == "" {
			templateSuffix = "unknown"
		}
		templateID := "subtakeover/" + templateSuffix
		templateName := "Subdomain Takeover"
		if strings.TrimSpace(engineName) != "" {
			templateName = fmt.Sprintf("Subdomain Takeover - %s", strings.TrimSpace(engineName))
		}

		descriptionParts := []string{
			"Potential subdomain takeover detected by subjack.",
			fmt.Sprintf("host=%s", host),
		}
		if strings.TrimSpace(engineName) != "" {
			descriptionParts = append(descriptionParts, "service="+strings.TrimSpace(engineName))
		}
		if strings.TrimSpace(row.Domain) != "" {
			descriptionParts = append(descriptionParts, "nonexist_domain="+strings.TrimSpace(row.Domain))
		}
		description := strings.Join(descriptionParts, " ")

		reference := defaultSubTakeoverReference

		rowJSON, _ := json.Marshal(row)
		matchedURL := "http://" + host
		if s.forceHTTPS {
			matchedURL = "https://" + host
		}

		results = append(results, engine.Result{
			Type: "vulnerability",
			Data: map[string]interface{}{
				"template_id":   templateID,
				"template_name": templateName,
				"severity":      s.severity,
				"matched_at":    host,
				"host":          host,
				"domain":        host,
				"root_domain":   rootDomain,
				"url":           matchedURL,
				"matcher_name":  "subjack",
				"description":   description,
				"reference":     reference,
				"template_url":  reference,
				"raw":           string(rowJSON),
				"discovered_at": time.Now(),
			},
		})
	}
	return results, nil
}

func parseSubjackRows(raw []byte) ([]subjackResult, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || strings.EqualFold(trimmed, "null") {
		return []subjackResult{}, nil
	}

	if strings.HasPrefix(trimmed, "[") {
		var rows []subjackResult
		if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		var row subjackResult
		if err := json.Unmarshal([]byte(trimmed), &row); err == nil {
			return []subjackResult{row}, nil
		}
	}

	rows := make([]subjackResult, 0, 32)
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row subjackResult
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func normalizeSubTakeoverTargets(input []string) []subTakeoverTarget {
	seen := make(map[string]bool)
	out := make([]subTakeoverTarget, 0, len(input))

	for _, item := range input {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}

		target := entry
		rootHint := ""
		if strings.Contains(entry, "|") {
			parts := strings.SplitN(entry, "|", 2)
			target = strings.TrimSpace(parts[0])
			rootHint = strings.TrimSpace(parts[1])
		}

		host := normalizeHostForTakeover(target)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true

		rootDomain := normalizeHostForTakeover(rootHint)
		if rootDomain == "" {
			rootDomain = commondomain.EffectiveRootDomain(host)
		}

		out = append(out, subTakeoverTarget{
			host:       host,
			rootDomain: rootDomain,
		})
	}
	return out
}

func normalizeHostForTakeover(value string) string {
	s := strings.TrimSpace(strings.ToLower(value))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "|") {
		s = strings.SplitN(s, "|", 2)[0]
	}
	if strings.HasPrefix(s, "*.") {
		s = strings.TrimPrefix(s, "*.")
	}

	if parsed, err := url.Parse(s); err == nil {
		if host := strings.TrimSpace(parsed.Hostname()); host != "" {
			s = host
		}
	}
	if !strings.Contains(s, "://") {
		if parsed, err := url.Parse("http://" + s); err == nil {
			if host := strings.TrimSpace(parsed.Hostname()); host != "" {
				s = host
			}
		}
	}

	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	if idx := strings.Index(s, "/"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	if s == "" {
		return ""
	}
	if net.ParseIP(s) != nil {
		return ""
	}
	if !strings.Contains(s, ".") {
		return ""
	}
	return s
}

func sanitizeTemplateToken(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return ""
	}
	re := regexp.MustCompile(`[^a-z0-9]+`)
	v = re.ReplaceAllString(v, "-")
	return strings.Trim(v, "-")
}

func compactLog(value string, maxLen int) string {
	v := strings.TrimSpace(value)
	if maxLen <= 0 || len(v) <= maxLen {
		return v
	}
	return v[:maxLen] + "..."
}
