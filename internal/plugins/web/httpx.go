package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"hunter/internal/engine"
)

// HttpxPlugin probes live web services and basic metadata.
type HttpxPlugin struct{}

// HttpxResult represents one JSONL line from httpx output.
type HttpxResult struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title"`
	Tech        []string `json:"tech"`    // httpx uses "tech"
	Host        string   `json:"host"`    // hostname/domain
	HostIP      string   `json:"host_ip"` // resolved IP
	A           []string `json:"a"`       // A records
	ContentType string   `json:"content_type"`
	Method      string   `json:"method"`
	Input       string   `json:"input"`
	Webserver   string   `json:"webserver"`
	CDN         bool     `json:"cdn"`
	CDNName     string   `json:"cdn_name"`
}

// NewHttpxPlugin creates an Httpx plugin instance.
func NewHttpxPlugin() *HttpxPlugin {
	return &HttpxPlugin{}
}

// Name returns plugin name.
func (h *HttpxPlugin) Name() string {
	return "Httpx"
}

// Execute runs httpx against domains/subdomains and returns live web service results.
func (h *HttpxPlugin) Execute(input []string) ([]engine.Result, error) {
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not found in PATH. Please install httpx and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Httpx] Probing %d domains...\n", len(input))

	tmpFile, err := os.CreateTemp("", "httpx_input_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, domain := range input {
		if _, err := tmpFile.WriteString(domain + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %v", err)
		}
	}
	_ = tmpFile.Close()

	cmd := exec.Command("httpx",
		"-l", tmpFile.Name(),
		"-json",
		"-sc",
		"-title",
		"-td",
		"-ip",
		"-silent",
		"-timeout", "10",
		"-retries", "2",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	liveCount := 0
	seenURLs := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var httpxResult HttpxResult
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			fmt.Printf("[Httpx] Failed to parse JSON line: %s\n", line)
			continue
		}

		ip := httpxResult.HostIP
		if ip == "" && len(httpxResult.A) > 0 {
			ip = httpxResult.A[0]
		}
		url := strings.TrimSpace(httpxResult.URL)
		if url == "" || seenURLs[url] {
			continue
		}
		seenURLs[url] = true
		liveCount++

		results = append(results, engine.Result{
			Type: "web_service",
			Data: map[string]interface{}{
				"url":           url,
				"status_code":   httpxResult.StatusCode,
				"title":         httpxResult.Title,
				"technologies":  httpxResult.Tech,
				"ip":            ip,
				"domain":        httpxResult.Host,
				"discovered_at": time.Now(),
			},
		})
	}

	if err := cmd.Wait(); err != nil {
		// Keep behavior tolerant: partial results are still useful.
		fmt.Printf("[Httpx] Command finished with warning\n")
	}

	fmt.Printf("[Httpx] Probe completed, found %d live services\n", liveCount)
	return results, nil
}
