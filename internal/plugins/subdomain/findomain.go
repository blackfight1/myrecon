package subdomain

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// FindomainPlugin implements subdomain collection via findomain.
type FindomainPlugin struct{}

// NewFindomainPlugin creates a findomain plugin instance.
func NewFindomainPlugin() *FindomainPlugin {
	return &FindomainPlugin{}
}

// Name returns plugin name.
func (f *FindomainPlugin) Name() string {
	return "Findomain"
}

// Execute runs findomain for one or more root domains.
func (f *FindomainPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("findomain"); err != nil {
		return nil, fmt.Errorf("findomain not found in PATH. Please install findomain and ensure it's in your PATH")
	}

	targets := normalizeDomains(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Findomain] Running passive enumeration for %d root domains...\n", len(targets))

	outputTmp, err := os.CreateTemp("", "findomain_subdomains_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create findomain output file: %v", err)
	}
	outputFile := outputTmp.Name()
	if err := outputTmp.Close(); err != nil {
		os.Remove(outputFile)
		return nil, fmt.Errorf("failed to close findomain output file: %v", err)
	}
	defer os.Remove(outputFile)

	cmd := exec.Command("findomain", "--stdin", "-q", "-u", outputFile)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
	}

	go func() {
		defer stdin.Close()
		for _, target := range targets {
			_, _ = io.WriteString(stdin, target+"\n")
		}
	}()

	rawOutput, runErr := cmd.CombinedOutput()

	subdomains, parseErr := readSubdomainsFile(outputFile)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("findomain execution failed: %v", runErr)
		}
		return nil, fmt.Errorf("failed to parse findomain output: %v", parseErr)
	}

	if runErr != nil {
		if len(subdomains) == 0 {
			return nil, fmt.Errorf("findomain execution failed: %v", runErr)
		}
		fmt.Printf("[Findomain] Command finished with warning: %v\n", runErr)
	}

	if len(strings.TrimSpace(string(rawOutput))) > 0 {
		lines := strings.Split(strings.TrimSpace(string(rawOutput)), "\n")
		if len(lines) > 0 {
			lastLine := strings.TrimSpace(lines[len(lines)-1])
			if lastLine != "" {
				fmt.Printf("[Findomain] %s\n", lastLine)
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

	fmt.Printf("[Findomain] Found %d subdomains\n", len(results))
	return results, nil
}
