package plugins

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// ShosubgoPlugin implements subdomain collection via shosubgo.
type ShosubgoPlugin struct{}

// NewShosubgoPlugin creates a shosubgo plugin instance.
func NewShosubgoPlugin() *ShosubgoPlugin {
	return &ShosubgoPlugin{}
}

// Name returns plugin name.
func (s *ShosubgoPlugin) Name() string {
	return "Shosubgo"
}

// Execute runs shosubgo for all input domains.
func (s *ShosubgoPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("shosubgo"); err != nil {
		return nil, fmt.Errorf("shosubgo not found in PATH. Please install shosubgo and ensure it's in your PATH")
	}

	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SHODAN_API_KEY environment variable is not set")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var results []engine.Result
	seen := make(map[string]bool)
	totalCount := 0

	for _, domain := range input {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}

		fmt.Printf("[Shosubgo] Collecting subdomains from Shodan for: %s\n", domain)

		cmd := exec.Command("shosubgo", "-d", domain, "-s", apiKey)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start shosubgo: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		domainCount := 0

		for scanner.Scan() {
			subdomain := strings.TrimSpace(scanner.Text())
			if subdomain == "" || seen[subdomain] {
				continue
			}

			seen[subdomain] = true
			domainCount++
			totalCount++
			results = append(results, engine.Result{
				Type: "domain",
				Data: subdomain,
			})
		}

		if err := cmd.Wait(); err != nil {
			// Keep existing behavior: tolerate non-zero exit when partial output is available.
			fmt.Printf("[Shosubgo] Command finished with warning for %s\n", domain)
		}

		fmt.Printf("[Shosubgo] %s found %d subdomains\n", domain, domainCount)
	}

	fmt.Printf("[Shosubgo] Total unique subdomains from Shodan: %d\n", totalCount)
	return results, nil
}
