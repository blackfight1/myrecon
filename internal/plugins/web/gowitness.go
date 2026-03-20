package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

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
			"--threads", "5",
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
	ProbedAt   string
}

type screenshotCacheEntry struct {
	DBModTime time.Time
	Items     []ScreenshotItem
}

var (
	screenshotCacheMu sync.RWMutex
	screenshotCache   = make(map[string]screenshotCacheEntry)
)

// ListScreenshots lists screenshot image files for a given root domain.
func ListScreenshots(baseDir, rootDomain string) ([]ScreenshotItem, error) {
	rootDomain = strings.TrimSpace(rootDomain)
	if rootDomain == "" {
		return []ScreenshotItem{}, nil
	}
	domainDir := filepath.Join(baseDir, rootDomain)
	ssDir := filepath.Join(domainDir, "screenshots")
	dbPath := filepath.Join(domainDir, "gowitness.sqlite3")

	var dbModTime time.Time
	if dbInfo, err := os.Stat(dbPath); err == nil {
		dbModTime = dbInfo.ModTime()
		if cached, ok := getCachedScreenshots(dbPath, dbModTime); ok {
			return cached, nil
		}
	}

	if items, err := listScreenshotsFromGowitnessDB(dbPath, ssDir); err == nil && len(items) > 0 {
		if !dbModTime.IsZero() {
			setCachedScreenshots(dbPath, dbModTime, items)
		}
		return items, nil
	}

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

func getCachedScreenshots(dbPath string, dbModTime time.Time) ([]ScreenshotItem, bool) {
	screenshotCacheMu.RLock()
	defer screenshotCacheMu.RUnlock()

	entry, ok := screenshotCache[dbPath]
	if !ok {
		return nil, false
	}
	if !entry.DBModTime.Equal(dbModTime) {
		return nil, false
	}
	return cloneScreenshotItems(entry.Items), true
}

func setCachedScreenshots(dbPath string, dbModTime time.Time, items []ScreenshotItem) {
	screenshotCacheMu.Lock()
	defer screenshotCacheMu.Unlock()
	screenshotCache[dbPath] = screenshotCacheEntry{
		DBModTime: dbModTime,
		Items:     cloneScreenshotItems(items),
	}
}

// InvalidateScreenshotCache clears cached screenshot rows for one root domain.
func InvalidateScreenshotCache(baseDir, rootDomain string) {
	rootDomain = strings.TrimSpace(rootDomain)
	if rootDomain == "" {
		return
	}
	dbPath := filepath.Join(baseDir, rootDomain, "gowitness.sqlite3")
	screenshotCacheMu.Lock()
	defer screenshotCacheMu.Unlock()
	delete(screenshotCache, dbPath)
}

func cloneScreenshotItems(items []ScreenshotItem) []ScreenshotItem {
	if len(items) == 0 {
		return []ScreenshotItem{}
	}
	out := make([]ScreenshotItem, len(items))
	copy(out, items)
	return out
}

type gowitnessReportRow struct {
	ID           int    `json:"id"`
	URL          string `json:"url"`
	FinalURL     string `json:"final_url"`
	Title        string `json:"title"`
	ResponseCode int    `json:"response_code"`
	FileName     string `json:"file_name"`
	ProbedAt     string `json:"probed_at"`
}

type screenshotRankedItem struct {
	RowID int
	Item  ScreenshotItem
}

func listScreenshotsFromGowitnessDB(dbPath, screenshotDir string) ([]ScreenshotItem, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("gowitness"); err != nil {
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "gowitness_report_*.jsonl")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command("gowitness", "report", "convert", "--from-file", dbPath, "--to-file", tmpPath, "-q")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("gowitness report convert failed: %v, output=%s", err, strings.TrimSpace(string(output)))
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	byFile := make(map[string]screenshotRankedItem)
	reader := bufio.NewReader(f)
	for {
		line, readErr := reader.ReadBytes('\n')
		trimmed := strings.TrimSpace(string(line))
		if trimmed != "" {
			var row gowitnessReportRow
			if err := json.Unmarshal([]byte(trimmed), &row); err == nil {
				filename := filepath.Base(strings.TrimSpace(row.FileName))
				if isImageFile(filename) {
					filePath := filepath.Join(screenshotDir, filename)
					if _, err := os.Stat(filePath); err == nil {
						url := strings.TrimSpace(row.FinalURL)
						if url == "" {
							url = strings.TrimSpace(row.URL)
						}
						item := ScreenshotItem{
							URL:        url,
							Filename:   filename,
							Title:      strings.TrimSpace(row.Title),
							StatusCode: row.ResponseCode,
							ProbedAt:   strings.TrimSpace(row.ProbedAt),
						}
						existing, ok := byFile[filename]
						if !ok || row.ID >= existing.RowID {
							byFile[filename] = screenshotRankedItem{RowID: row.ID, Item: item}
						}
					}
				}
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}

	items := make([]ScreenshotItem, 0, len(byFile))
	for _, ranked := range byFile {
		items = append(items, ranked.Item)
	}

	sort.SliceStable(items, func(i, j int) bool {
		ti, okI := parseProbedAt(items[i].ProbedAt)
		tj, okJ := parseProbedAt(items[j].ProbedAt)
		switch {
		case okI && okJ:
			if ti.Equal(tj) {
				return items[i].Filename < items[j].Filename
			}
			return ti.After(tj)
		case okI && !okJ:
			return true
		case !okI && okJ:
			return false
		default:
			return items[i].Filename < items[j].Filename
		}
	})

	return items, nil
}

func parseProbedAt(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func isImageFile(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(lower, ".png") || strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg")
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
