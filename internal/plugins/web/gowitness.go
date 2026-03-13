package web

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"hunter/internal/engine"
)

// GowitnessPlugin captures screenshots for live URLs grouped by root domain.
type GowitnessPlugin struct {
	baseDir string
}

// NewGowitnessPlugin creates a Gowitness plugin instance.
func NewGowitnessPlugin(baseDir string) *GowitnessPlugin {
	if baseDir == "" {
		baseDir = "screenshots"
	}
	return &GowitnessPlugin{baseDir: baseDir}
}

// Name returns plugin name.
func (g *GowitnessPlugin) Name() string {
	return "Gowitness"
}

// Execute runs gowitness screenshots.
// Input format: []string{"url|root_domain", ...}.
func (g *GowitnessPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("gowitness"); err != nil {
		return nil, fmt.Errorf("gowitness not found in PATH. Please install gowitness and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	domainURLs := make(map[string][]string)
	for _, item := range input {
		parts := strings.SplitN(item, "|", 2)
		if len(parts) != 2 {
			continue
		}
		u := parts[0]
		rootDomain := parts[1]
		domainURLs[rootDomain] = append(domainURLs[rootDomain], u)
	}

	var results []engine.Result
	totalScreenshots := 0

	for rootDomain, urls := range domainURLs {
		fmt.Printf("[Gowitness] Capturing %d URLs for %s...\n", len(urls), rootDomain)

		domainDir := filepath.Join(g.baseDir, rootDomain)
		if err := os.MkdirAll(domainDir, 0755); err != nil {
			fmt.Printf("[Gowitness] Failed to create directory %s: %v\n", domainDir, err)
			continue
		}

		tmpFile, err := os.CreateTemp("", "gowitness_urls_*.txt")
		if err != nil {
			fmt.Printf("[Gowitness] Failed to create temp file: %v\n", err)
			continue
		}

		for _, u := range urls {
			if _, err := tmpFile.WriteString(u + "\n"); err != nil {
				fmt.Printf("[Gowitness] Failed to write temp file: %v\n", err)
			}
		}
		_ = tmpFile.Close()

		cmd := exec.Command("gowitness",
			"scan", "file",
			"-f", tmpFile.Name(),
			"--ports-small",
			"--threads", "10",
			"--write-db",
			"-q",
			"--http-code-filter", "200,403,401",
		)
		cmd.Dir = domainDir

		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("[Gowitness] Screenshot run failed for %s: %v\n%s\n", rootDomain, err, string(output))
		}

		_ = os.Remove(tmpFile.Name())

		screenshotDir := filepath.Join(domainDir, "screenshots")
		count := countFiles(screenshotDir)
		totalScreenshots += count

		fmt.Printf("[Gowitness] %s completed with %d screenshots\n", rootDomain, count)

		results = append(results, engine.Result{
			Type: "screenshot",
			Data: map[string]interface{}{
				"root_domain":      rootDomain,
				"screenshot_count": count,
				"screenshot_dir":   screenshotDir,
				"database":         filepath.Join(domainDir, "gowitness.sqlite3"),
			},
		})
	}

	fmt.Printf("[Gowitness] Screenshot task finished, total %d screenshots\n", totalScreenshots)
	return results, nil
}

// StartReportServer starts a gowitness report server for one root domain.
func StartReportServer(baseDir, rootDomain, host string, port int) error {
	if _, err := exec.LookPath("gowitness"); err != nil {
		return fmt.Errorf("gowitness not found in PATH")
	}

	domainDir := filepath.Join(baseDir, rootDomain)
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		return fmt.Errorf("screenshot directory does not exist: %s", domainDir)
	}

	dbFile := filepath.Join(domainDir, "gowitness.sqlite3")
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return fmt.Errorf("database file does not exist: %s", dbFile)
	}

	fmt.Printf("Starting report server for %s: http://%s:%d\n", rootDomain, host, port)

	cmd := exec.Command("gowitness",
		"report", "server",
		"--host", host,
		"--port", fmt.Sprintf("%d", port),
	)
	cmd.Dir = domainDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ListScreenshotDomains returns domains that already have screenshot databases.
func ListScreenshotDomains(baseDir string) ([]string, error) {
	if baseDir == "" {
		baseDir = "screenshots"
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			dbFile := filepath.Join(baseDir, entry.Name(), "gowitness.sqlite3")
			if _, err := os.Stat(dbFile); err == nil {
				domains = append(domains, entry.Name())
			}
		}
	}

	return domains, nil
}

// ScreenshotItem represents one screenshot entry.
type ScreenshotItem struct {
	URL        string
	Filename   string
	Title      string
	StatusCode int
}

// ListScreenshots lists screenshot image files for a given root domain.
func ListScreenshots(baseDir, rootDomain string) ([]ScreenshotItem, error) {
	ssDir := filepath.Join(baseDir, rootDomain, "screenshots")
	entries, err := os.ReadDir(ssDir)
	if err != nil {
		return nil, err
	}
	var items []ScreenshotItem
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg") {
			items = append(items, ScreenshotItem{
				Filename: name,
			})
		}
	}
	return items, nil
}

// countFiles counts files under a directory (non-recursive).
func countFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}

// ExtractRootDomain extracts a rough root domain from a subdomain.
func ExtractRootDomain(subdomain string) string {
	parts := strings.Split(subdomain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return subdomain
}
