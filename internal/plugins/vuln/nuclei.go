package vuln

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

// NucleiPlugin runs nuclei scans with tuned exclusions for noisy templates.
type NucleiPlugin struct {
	excludeProtocolTypes []string
	excludeTemplateIDs   []string
	outputFile           string
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
		excludeProtocolTypes: []string{"ssl", "dns"},
		excludeTemplateIDs: []string{
			"https-to-http-redirect",
			"xss-deprecated-header",
			"form-detection",
			"missing-sri",
			"cookies-without-httponly-secure",
		},
		outputFile: "result_nuclei",
	}
}

// Name returns plugin name.
func (n *NucleiPlugin) Name() string {
	return "Nuclei"
}

// Execute runs nuclei against input URLs and emits vulnerability results.
func (n *NucleiPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei not found in PATH. Please install nuclei and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var targets []string
	seen := make(map[string]bool)
	for _, item := range input {
		target := strings.TrimSpace(item)
		if target == "" {
			continue
		}
		if strings.Contains(target, "|") {
			target = strings.SplitN(target, "|", 2)[0]
		}
		if target == "" || seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, target)
	}

	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Nuclei] Scanning %d live targets...\n", len(targets))

	tmpFile, err := common.CreateTempFile("nuclei_targets_*.txt", targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer common.RemoveTempFile(tmpFile)

	_ = os.Remove(n.outputFile)

	cmd := exec.Command("nuclei",
		"-l", tmpFile,
		"-jsonl",
		"-silent",
		"-ept", strings.Join(n.excludeProtocolTypes, ","),
		"-eid", strings.Join(n.excludeTemplateIDs, ","),
		"-o", n.outputFile,
		"-timeout", "10",
		"-retries", "1",
	)

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
		if result, ok := parseNucleiJSONLLine(line); ok {
			results = append(results, result)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read nuclei output: %v", err)
	}

	waitErr := cmd.Wait()
	if len(results) == 0 {
		if fileResults, err := parseNucleiResultFile(n.outputFile); err == nil {
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

func parseNucleiResultFile(path string) ([]engine.Result, error) {
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
		if result, ok := parseNucleiJSONLLine(line); ok {
			results = append(results, result)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func parseNucleiJSONLLine(line string) (engine.Result, bool) {
	var nResult NucleiResult
	if err := json.Unmarshal([]byte(line), &nResult); err != nil {
		return engine.Result{}, false
	}

	domain := extractDomainFromTarget(nResult.MatchedAt)
	if domain == "" {
		domain = extractDomainFromTarget(nResult.Host)
	}

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
	return host
}

func extractCVE(text string) string {
	re := regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	match := re.FindString(text)
	return strings.ToUpper(match)
}
