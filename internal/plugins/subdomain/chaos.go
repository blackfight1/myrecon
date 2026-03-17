package subdomain

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

// ChaosPlugin implements passive subdomain collection via ProjectDiscovery chaos.
type ChaosPlugin struct {
	batchMode bool
}

// NewChaosPlugin creates a chaos plugin instance.
func NewChaosPlugin(batchMode bool) *ChaosPlugin {
	return &ChaosPlugin{batchMode: batchMode}
}

// Name returns plugin name.
func (c *ChaosPlugin) Name() string {
	return "Chaos"
}

// Execute runs chaos for one or more root domains.
func (c *ChaosPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("chaos"); err != nil {
		return nil, fmt.Errorf("chaos not found in PATH. Please install chaos and ensure it's in your PATH")
	}

	targets := normalizeDomains(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	apiKey := strings.TrimSpace(os.Getenv("CHAOS_KEY"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("PDCP_API_KEY"))
	}
	if apiKey == "" {
		fmt.Println("[Chaos] CHAOS_KEY/PDCP_API_KEY not set, skip chaos passive source")
		return []engine.Result{}, nil
	}

	fmt.Printf("[Chaos] Running passive enumeration for %d root domains...\n", len(targets))

	seen := make(map[string]bool, 1024)
	results := make([]engine.Result, 0, 1024)

	if c.batchMode && len(targets) > 1 {
		tmpFile, err := common.CreateTempFile("chaos_domains_*.txt", targets)
		if err != nil {
			return nil, fmt.Errorf("failed to create chaos temp file: %v", err)
		}
		defer common.RemoveTempFile(tmpFile)

		args := []string{"-dL", tmpFile, "-silent"}
		if apiKey != "" {
			args = append(args, "-key", apiKey)
		}
		finalResults, err := c.executeOnce(args, seen, results)
		if err != nil {
			return nil, err
		}
		fmt.Printf("[Chaos] Found %d subdomains\n", len(finalResults))
		return finalResults, nil
	}

	for _, domain := range targets {
		args := []string{"-d", domain, "-silent"}
		if apiKey != "" {
			args = append(args, "-key", apiKey)
		}
		partial, err := c.executeOnce(args, seen, nil)
		if err != nil {
			return nil, err
		}
		results = append(results, partial...)
	}

	fmt.Printf("[Chaos] Found %d subdomains\n", len(results))
	return results, nil
}

func (c *ChaosPlugin) executeOnce(args []string, seen map[string]bool, seed []engine.Result) ([]engine.Result, error) {
	results := seed
	if results == nil {
		results = make([]engine.Result, 0, 256)
	}

	cmd := exec.Command("chaos", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create chaos stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start chaos: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		subdomain := strings.ToLower(strings.TrimSpace(scanner.Text()))
		subdomain = strings.TrimSuffix(subdomain, ".")
		if subdomain == "" || seen[subdomain] {
			continue
		}
		if strings.ContainsAny(subdomain, " \t/\\") || !strings.Contains(subdomain, ".") {
			continue
		}
		seen[subdomain] = true
		results = append(results, engine.Result{
			Type: "domain",
			Data: subdomain,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed while reading chaos output: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		if len(results) == 0 {
			fmt.Printf("[Chaos] no result or command warning, skipped: %v\n", err)
			return results, nil
		}
		fmt.Printf("[Chaos] Command finished with warning: %v\n", err)
	}
	return results, nil
}
