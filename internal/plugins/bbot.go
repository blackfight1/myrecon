package plugins

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"hunter/internal/engine"
)

// BBOTPlugin implements subdomain collection via BBOT.
type BBOTPlugin struct {
	passiveOnly bool
}

// NewBBOTPlugin creates a BBOT plugin instance.
func NewBBOTPlugin(passiveOnly bool) *BBOTPlugin {
	return &BBOTPlugin{passiveOnly: passiveOnly}
}

// Name returns plugin name.
func (b *BBOTPlugin) Name() string {
	return "BBOT"
}

// Execute runs BBOT subdomain enumeration for all input root domains.
func (b *BBOTPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("bbot"); err != nil {
		return nil, fmt.Errorf("bbot not found in PATH. Please install bbot and ensure it's in your PATH")
	}

	targets := normalizeDomains(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[BBOT] Running subdomain enumeration for %d root domains...\n", len(targets))

	scanDir, err := os.MkdirTemp("", "hunter_bbot_scan_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create bbot temp output dir: %v", err)
	}
	defer os.RemoveAll(scanDir)

	outputFile := filepath.Join(scanDir, "subdomains.txt")
	scanName := fmt.Sprintf("hunter_subs_%d", time.Now().UnixNano())

	args := []string{"-t"}
	args = append(args, targets...)
	args = append(args,
		"-p", "subdomain-enum",
		"-om", "subdomains",
		"-n", scanName,
		"-o", scanDir,
		"-c", fmt.Sprintf("modules.subdomains.output_file=%s", outputFile),
	)
	if b.passiveOnly {
		args = append(args, "-rf", "passive", "-ef", "aggressive")
	}

	cmd := exec.Command("bbot", args...)
	rawOutput, runErr := cmd.CombinedOutput()

	subdomains, parseErr := readSubdomainsFile(outputFile)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("bbot execution failed: %v", runErr)
		}
		return nil, fmt.Errorf("failed to parse bbot subdomains output: %v", parseErr)
	}

	if runErr != nil {
		if len(subdomains) == 0 {
			return nil, fmt.Errorf("bbot execution failed: %v", runErr)
		}
		fmt.Printf("[BBOT] Command finished with warning: %v\n", runErr)
	}

	if len(strings.TrimSpace(string(rawOutput))) > 0 {
		lines := strings.Split(strings.TrimSpace(string(rawOutput)), "\n")
		if len(lines) > 0 {
			lastLine := strings.TrimSpace(lines[len(lines)-1])
			if lastLine != "" {
				fmt.Printf("[BBOT] %s\n", lastLine)
			}
		}
	}

	results := make([]engine.Result, 0, len(subdomains))
	for _, subdomain := range subdomains {
		results = append(results, engine.Result{
			Type: "domain",
			Data: subdomain,
		})
	}

	fmt.Printf("[BBOT] Found %d subdomains\n", len(results))
	return results, nil
}

func normalizeDomains(input []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(input))

	for _, item := range input {
		d := strings.ToLower(strings.TrimSpace(item))
		d = strings.TrimSuffix(d, ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}

	return out
}

func readSubdomainsFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := make(map[string]bool)
	out := make([]string, 0, 256)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		line = strings.TrimSuffix(line, ".")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t/\\") || !strings.Contains(line, ".") {
			continue
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		out = append(out, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return out, nil
}
