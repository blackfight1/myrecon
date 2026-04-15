package subdomain

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"hunter/internal/engine"
	"hunter/internal/plugins/common"
)

const (
	defaultDNSXThreads = 100
)

// DNSXBruteforcePlugin performs active subdomain brute-force using dnsx.
type DNSXBruteforcePlugin struct {
	rootDomains   []string
	resolversFile string
	threads       int
}

// NewDNSXBruteforcePlugin creates a dnsx active brute-force plugin.
func NewDNSXBruteforcePlugin(rootDomains []string, resolversFile string) *DNSXBruteforcePlugin {
	threads := defaultDNSXThreads
	return &DNSXBruteforcePlugin{
		rootDomains:   normalizeDomains(rootDomains),
		resolversFile: strings.TrimSpace(resolversFile),
		threads:       threads,
	}
}

// Name returns plugin name.
func (d *DNSXBruteforcePlugin) Name() string {
	return "DNSXBruteforce"
}

// Execute runs dnsx brute-force with root domains and dictionary words.
func (d *DNSXBruteforcePlugin) Execute(ctx context.Context, input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("dnsx"); err != nil {
		return nil, fmt.Errorf("dnsx not found in PATH. Please install dnsx and ensure it's in your PATH")
	}

	words := normalizeWordList(input)
	if len(d.rootDomains) == 0 || len(words) == 0 {
		return []engine.Result{}, nil
	}

	rootFile, err := common.CreateTempFile("dnsx_roots_*.txt", d.rootDomains)
	if err != nil {
		return nil, fmt.Errorf("failed to create dnsx root domain file: %v", err)
	}
	defer common.RemoveTempFile(rootFile)

	wordFile, err := common.CreateTempFile("dnsx_words_*.txt", words)
	if err != nil {
		return nil, fmt.Errorf("failed to create dnsx dictionary file: %v", err)
	}
	defer common.RemoveTempFile(wordFile)

	fmt.Printf("[DNSXBruteforce] Running active brute-force for %d root domains with %d words...\n", len(d.rootDomains), len(words))

	args := []string{
		"-silent",
		"-d", rootFile,
		"-w", wordFile,
		"-threads", fmt.Sprintf("%d", d.threads),
	}
	if d.resolversFile != "" {
		args = append(args, "-r", d.resolversFile)
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create dnsx stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start dnsx: %v", err)
	}

	seen := map[string]bool{}
	results := make([]engine.Result, 0, 256)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		subdomain := strings.ToLower(strings.TrimSpace(scanner.Text()))
		subdomain = strings.TrimSuffix(subdomain, ".")
		if subdomain == "" || seen[subdomain] {
			continue
		}
		seen[subdomain] = true
		results = append(results, engine.Result{
			Type: "domain",
			Data: subdomain,
		})
	}

	if scanErr := scanner.Err(); scanErr != nil {
		_ = cmd.Wait()
		return nil, fmt.Errorf("failed while reading dnsx output: %v", scanErr)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("dnsx execution failed: %v", err)
	}

	fmt.Printf("[DNSXBruteforce] Found %d active subdomains\n", len(results))
	return results, nil
}

func normalizeWordList(input []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(input))

	for _, item := range input {
		word := strings.ToLower(strings.TrimSpace(item))
		word = strings.Trim(word, ".-")
		if !isValidWordToken(word) || seen[word] {
			continue
		}
		seen[word] = true
		out = append(out, word)
	}

	return out
}
