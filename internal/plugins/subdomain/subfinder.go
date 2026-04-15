package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

// SubfinderPlugin implements subdomain collection via Subfinder.
type SubfinderPlugin struct {
	batchMode bool
}

// SubfinderResult represents one JSON line from Subfinder output.
type SubfinderResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// NewSubfinderPlugin creates a Subfinder plugin instance.
func NewSubfinderPlugin(batchMode bool) *SubfinderPlugin {
	return &SubfinderPlugin{batchMode: batchMode}
}

// Name returns plugin name.
func (s *SubfinderPlugin) Name() string {
	return "Subfinder"
}

// Execute runs Subfinder for one or more root domains.
func (s *SubfinderPlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH. Please install subfinder and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var results []engine.Result
	var allHosts []string

	if s.batchMode && len(input) > 1 {
		fmt.Printf("[Subfinder] Batch mode: collecting subdomains for %d root domains...\n", len(input))

		tmpFile, err := common.CreateTempFile("subfinder_domains_*.txt", input)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %v", err)
		}
		defer common.RemoveTempFile(tmpFile)

		cmd := exec.CommandContext(ctx, "subfinder", "-dL", tmpFile, "-all", "-json", "-silent")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start subfinder: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var subResult SubfinderResult
			if err := json.Unmarshal([]byte(line), &subResult); err != nil {
				continue
			}

			allHosts = append(allHosts, subResult.Host)
		}

		if err := cmd.Wait(); err != nil {
			fmt.Printf("[Subfinder] Command finished with warning\n")
		}

		fmt.Printf("[Subfinder] Batch mode found %d subdomains\n", len(allHosts))
	} else {
		for _, domain := range input {
			fmt.Printf("[Subfinder] Collecting subdomains for: %s\n", domain)

			cmd := exec.CommandContext(ctx, "subfinder", "-d", domain, "-all", "-json", "-silent")
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
			}

			if err := cmd.Start(); err != nil {
				return nil, fmt.Errorf("failed to start subfinder: %v", err)
			}

			scanner := bufio.NewScanner(stdout)
			var hosts []string

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}

				var subResult SubfinderResult
				if err := json.Unmarshal([]byte(line), &subResult); err != nil {
					continue
				}

				hosts = append(hosts, subResult.Host)
				allHosts = append(allHosts, subResult.Host)
			}

			if err := cmd.Wait(); err != nil {
				return nil, fmt.Errorf("subfinder execution failed: %v", err)
			}

			fmt.Printf("[Subfinder] Found %d subdomains\n", len(hosts))
		}
	}

	for _, host := range allHosts {
		results = append(results, engine.Result{Type: "domain", Data: host})
	}

	return results, nil
}
