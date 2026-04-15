package vuln

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	commondomain "hunter/internal/common"
	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

// NucleiPlugin runs nuclei scans with tuned exclusions for noisy templates.
type NucleiPlugin struct {
	excludeProtocolTypes []string
	excludeTemplateIDs   []string
	excludeSeverities    []string
	excludeTags          []string
}

// NucleiResult is a subset of nuclei JSONL output fields.
type NucleiResult struct {
	TemplateID  string `json:"template-id"`
	Template    string `json:"template"`
	TemplateURL string `json:"template-url"`
	MatcherName string `json:"matcher-name"`
	MatchedAt   string `json:"matched-at"`
	Host        string `json:"host"`
	IP          string `json:"ip"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
	} `json:"info"`
}

// NewNucleiPlugin creates a nuclei plugin instance.
func NewNucleiPlugin() *NucleiPlugin {
	return &NucleiPlugin{
		// Use -ept to exclude protocol/template types (ssl/dns),
		// and -eid to exclude noisy template IDs.
		excludeProtocolTypes: parseCSVEnv("NUCLEI_EXCLUDE_PROTOCOL_TYPES", []string{"ssl", "dns"}, true),
		excludeTemplateIDs: parseCSVEnv("NUCLEI_EXCLUDE_TEMPLATE_IDS", []string{
			"https-to-http-redirect",
			"xss-deprecated-header",
			"form-detection",
			"missing-sri",
			"cookies-without-httponly-secure",
		}, false),
		// Default to removing informational findings unless user overrides.
		excludeSeverities: parseCSVEnv("NUCLEI_EXCLUDE_SEVERITIES", []string{"info", "unknown"}, true),
		excludeTags:       parseCSVEnv("NUCLEI_EXCLUDE_TAGS", nil, true),
	}
}

// Name returns plugin name.
func (n *NucleiPlugin) Name() string {
	return "Nuclei"
}

// Execute runs nuclei against input URLs and emits vulnerability results.
func (n *NucleiPlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH. Please install nuclei and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	targets, rootDomainHints := normalizeNucleiTargets(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Nuclei] Scanning %d live targets...\n", len(targets))

	tmpFile, err := common.CreateTempFile("nuclei_targets_*.txt", targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer common.RemoveTempFile(tmpFile)

	resultFile, err := os.CreateTemp("", "nuclei_result_*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("failed to create nuclei result file: %v", err)
	}
	resultPath := resultFile.Name()
	if err := resultFile.Close(); err != nil {
		_ = os.Remove(resultPath)
		return nil, fmt.Errorf("failed to close nuclei result file: %v", err)
	}
	defer os.Remove(resultPath)

	args := []string{
		"-l", tmpFile,
		"-jsonl",
		"-silent",
		"-o", resultPath,
		"-timeout", "10",
		"-retries", "1",
	}
	if len(n.excludeProtocolTypes) > 0 {
		args = append(args, "-ept", strings.Join(n.excludeProtocolTypes, ","))
	}
	if len(n.excludeTemplateIDs) > 0 {
		args = append(args, "-eid", strings.Join(n.excludeTemplateIDs, ","))
	}
	if len(n.excludeSeverities) > 0 {
		args = append(args, "-es", strings.Join(n.excludeSeverities, ","))
	}
	if len(n.excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(n.excludeTags, ","))
	}
	fmt.Printf("[Nuclei] filters ept=%s eid=%d es=%s etags=%s\n",
		strings.Join(n.excludeProtocolTypes, ","),
		len(n.excludeTemplateIDs),
		strings.Join(n.excludeSeverities, ","),
		strings.Join(n.excludeTags, ","),
	)
	cmd := exec.CommandContext(ctx, "nuclei", args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start nuclei: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if result, ok := parseNucleiJSONLLine(line, rootDomainHints); ok {
			results = append(results, result)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %v", err)
	}

	waitErr := cmd.Wait()
	if len(results) == 0 {
		if fileResults, err := parseNucleiResultFile(resultPath, rootDomainHints); err == nil {
			results = append(results, fileResults...)
		}
	}
	if waitErr != nil && len(results) == 0 {
		return nil, fmt.Errorf("nuclei execution failed: %v", waitErr)
	}
	if waitErr != nil {
		fmt.Printf("[Nuclei] Command finished with warning: %v\n", waitErr)
	}

	fmt.Printf("[Nuclei] Scan complete, found %d potential vulnerabilities\n", len(results))
	return results, nil
}

func parseNucleiResultFile(path string, rootDomainHints map[string]string) ([]engine.Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	results := make([]engine.Result, 0, 64)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if result, ok := parseNucleiJSONLLine(line, rootDomainHints); ok {
			results = append(results, result)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func parseNucleiJSONLLine(line string, rootDomainHints map[string]string) (engine.Result, bool) {
	var nResult NucleiResult
	if err := json.Unmarshal([]byte(line), &nResult); err != nil {
		return engine.Result{}, false
	}
	if strings.TrimSpace(nResult.TemplateID) == "" || strings.TrimSpace(nResult.MatchedAt) == "" {
		return engine.Result{}, false
	}

	domain := extractDomainFromTarget(nResult.MatchedAt)
	if domain == "" {
		domain = extractDomainFromTarget(nResult.Host)
	}
	rootDomain := lookupRootDomain(nResult, domain, rootDomainHints)

	references := ""
	if len(nResult.Info.Reference) > 0 {
		references = strings.Join(nResult.Info.Reference, ",")
	}

	cve := extractCVE(nResult.TemplateID + " " + nResult.Template + " " + nResult.Info.Name + " " + nResult.Info.Description)

	return engine.Result{
		Type: "vulnerability",
		Data: map[string]interface{}{
			"template_id":   nResult.TemplateID,
			"template_name": nResult.Info.Name,
			"severity":      strings.ToLower(nResult.Info.Severity),
			"matched_at":    nResult.MatchedAt,
			"host":          nResult.Host,
			"domain":        domain,
			"root_domain":   rootDomain,
			"ip":            nResult.IP,
			"matcher_name":  nResult.MatcherName,
			"description":   nResult.Info.Description,
			"reference":     references,
			"template_url":  nResult.TemplateURL,
			"cve":           cve,
			"raw":           line,
			"discovered_at": time.Now(),
		},
	}, true
}

func normalizeNucleiTargets(input []string) ([]string, map[string]string) {
	seen := make(map[string]bool)
	targets := make([]string, 0, len(input))
	rootDomainHints := make(map[string]string)

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
		if target == "" {
			continue
		}

		targetKey := normalizeTargetKey(target)
		if targetKey == "" || seen[targetKey] {
			continue
		}
		seen[targetKey] = true
		targets = append(targets, target)

		if rootHint == "" {
			continue
		}
		rootDomain := extractRootDomain(rootHint)
		if rootDomain == "" {
			continue
		}
		rootDomainHints[targetKey] = rootDomain
		targetHost := extractDomainFromTarget(target)
		if targetHost != "" {
			rootDomainHints[targetHost] = rootDomain
		}
	}

	return targets, rootDomainHints
}

func lookupRootDomain(nResult NucleiResult, domain string, rootDomainHints map[string]string) string {
	if len(rootDomainHints) > 0 {
		keys := []string{
			normalizeTargetKey(nResult.MatchedAt),
			normalizeTargetKey(nResult.Host),
			extractDomainFromTarget(nResult.MatchedAt),
			extractDomainFromTarget(nResult.Host),
			strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), ".")),
		}
		for _, key := range keys {
			k := strings.ToLower(strings.TrimSpace(key))
			if k == "" {
				continue
			}
			if rd, ok := rootDomainHints[k]; ok && rd != "" {
				return rd
			}
		}
	}

	if domain != "" {
		return extractRootDomain(domain)
	}
	host := extractDomainFromTarget(nResult.Host)
	return extractRootDomain(host)
}

func extractDomainFromTarget(target string) string {
	if target == "" {
		return ""
	}

	parsed, err := url.Parse(target)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}

	host := strings.TrimSpace(target)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func normalizeTargetKey(target string) string {
	key := strings.ToLower(strings.TrimSpace(target))
	key = strings.TrimSuffix(key, "/")
	return key
}

func extractRootDomain(value string) string {
	host := extractDomainFromTarget(value)
	if host == "" {
		return ""
	}
	return commondomain.EffectiveRootDomain(host)
}

func extractCVE(text string) string {
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	match := re.FindString(text)
	return strings.ToUpper(match)
}

func parseCSVEnv(key string, defaultValues []string, toLower bool) []string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return cloneAndNormalize(defaultValues, toLower)
	}
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	return splitCSV(raw, toLower)
}

func splitCSV(raw string, toLower bool) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 8)
	for _, item := range strings.Split(raw, ",") {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if toLower {
			v = strings.ToLower(v)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func cloneAndNormalize(values []string, toLower bool) []string {
	if len(values) == 0 {
		return []string{}
	}
	joined := strings.Join(values, ",")
	return splitCSV(joined, toLower)
}
