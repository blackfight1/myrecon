package plugins

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// AmassPlugin implements subdomain collection via amass.
type AmassPlugin struct {
	passiveOnly bool
}

// NewAmassPlugin creates an amass plugin instance.
func NewAmassPlugin(passiveOnly bool) *AmassPlugin {
	return &AmassPlugin{passiveOnly: passiveOnly}
}

// Name returns plugin name.
func (a *AmassPlugin) Name() string {
	return "Amass"
}

// Execute runs amass enum for one or more root domains.
func (a *AmassPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("amass"); err != nil {
		return nil, fmt.Errorf("amass not found in PATH. Please install amass and ensure it's in your PATH")
	}

	targets := normalizeDomains(input)
	if len(targets) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Amass] Running %s enumeration for %d root domains...\n", map[bool]string{true: "passive", false: "active+passive"}[a.passiveOnly], len(targets))

	targetFile, err := createTempFile("amass_targets_*.txt", targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create amass target file: %v", err)
	}
	defer removeTempFile(targetFile)

	outputTmp, err := os.CreateTemp("", "amass_subdomains_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create amass output file: %v", err)
	}
	outputFile := outputTmp.Name()
	if err := outputTmp.Close(); err != nil {
		removeTempFile(outputFile)
		return nil, fmt.Errorf("failed to close amass output temp file: %v", err)
	}
	defer removeTempFile(outputFile)

	args := []string{"enum", "-df", targetFile, "-silent", "-o", outputFile}
	if a.passiveOnly {
		args = append(args, "-passive")
	}

	cmd := exec.Command("amass", args...)
	rawOutput, runErr := cmd.CombinedOutput()

	subdomains, parseErr := readSubdomainsFile(outputFile)
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("amass execution failed: %v", runErr)
		}
		return nil, fmt.Errorf("failed to parse amass subdomains output: %v", parseErr)
	}

	if runErr != nil {
		if len(subdomains) == 0 {
			return nil, fmt.Errorf("amass execution failed: %v", runErr)
		}
		fmt.Printf("[Amass] Command finished with warning: %v\n", runErr)
	}

	if len(strings.TrimSpace(string(rawOutput))) > 0 {
		lines := strings.Split(strings.TrimSpace(string(rawOutput)), "\n")
		if len(lines) > 0 {
			lastLine := strings.TrimSpace(lines[len(lines)-1])
			if lastLine != "" {
				fmt.Printf("[Amass] %s\n", lastLine)
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

	fmt.Printf("[Amass] Found %d subdomains\n", len(results))
	return results, nil
}
