package subdomain

import (
	"bufio"
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
func (s *SubfinderPlugin) Execute(input []string) ([]engine.Result, error) {
	// Ensure subfinder is installed and available in PATH.
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH. Please install subfinder and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var results []engine.Result
	var allHosts []string

	// Batch mode: run once with -dL for multiple domains.
	if s.batchMode && len(input) > 1 {
		fmt.Printf("[Subfinder] 鎵归噺妯″紡: 姝ｅ湪鎼滈泦 %d 涓煙鍚嶇殑瀛愬煙鍚?..\n", len(input))

		// Write domains into a temp file for Subfinder -dL input.
		tmpFile, err := common.CreateTempFile("subfinder_domains_*.txt", input)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %v", err)
		}
		defer common.RemoveTempFile(tmpFile)

		cmd := exec.Command("subfinder", "-dL", tmpFile, "-all", "-json", "-silent")
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
			fmt.Printf("[Subfinder] 鍛戒护鎵ц瀹屾垚\n")
		}

		fmt.Printf("[Subfinder] 鎵归噺妯″紡鍙戠幇 %d 涓瓙鍩熷悕\n", len(allHosts))
	} else {
		// Single-domain mode: run Subfinder per input domain.
		for _, domain := range input {
			fmt.Printf("[Subfinder] 姝ｅ湪鎼滈泦鍩熷悕: %s\n", domain)

			cmd := exec.Command("subfinder", "-d", domain, "-all", "-json", "-silent")
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

			fmt.Printf("[Subfinder] 鍙戠幇 %d 涓煙鍚峔n", len(hosts))
		}
	}

	// Return all discovered subdomains as engine results.
	for _, host := range allHosts {
		results = append(results, engine.Result{
			Type: "domain",
			Data: host,
		})
	}

	return results, nil
}
