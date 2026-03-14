package engine

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"hunter/internal/common"
)

// Result represents a scanner output item.
type Result struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Scanner defines scanner plugin behavior.
type Scanner interface {
	Name() string
	Execute(input []string) ([]Result, error)
}

// Pipeline orchestrates scan stages.
type Pipeline struct {
	domainScanners    []Scanner
	nextScanners      []Scanner
	httpxScanner      Scanner
	portScanners      []Scanner
	vulnScanner       Scanner
	screenshotScanner Scanner
}

// NewPipeline creates a new pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		domainScanners: make([]Scanner, 0),
		nextScanners:   make([]Scanner, 0),
		portScanners:   make([]Scanner, 0),
	}
}

// SetScreenshotScanner sets screenshot scanner.
func (p *Pipeline) SetScreenshotScanner(scanner Scanner) {
	p.screenshotScanner = scanner
}

// AddDomainScanner adds a domain discovery scanner (parallel).
func (p *Pipeline) AddDomainScanner(scanner Scanner) {
	p.domainScanners = append(p.domainScanners, scanner)
}

// AddScanner adds a generic sequential scanner.
func (p *Pipeline) AddScanner(scanner Scanner) {
	p.nextScanners = append(p.nextScanners, scanner)
}

// SetHttpxScanner sets httpx scanner.
func (p *Pipeline) SetHttpxScanner(scanner Scanner) {
	p.httpxScanner = scanner
}

// AddPortScanner adds a chained port scanner.
func (p *Pipeline) AddPortScanner(scanner Scanner) {
	p.portScanners = append(p.portScanners, scanner)
}

// SetVulnScanner sets vulnerability scanner (runs after httpx).
func (p *Pipeline) SetVulnScanner(scanner Scanner) {
	p.vulnScanner = scanner
}

type scannerResult struct {
	name     string
	results  []Result
	err      error
	statuses []Result
}

// Execute runs the full pipeline from root domains.
func (p *Pipeline) Execute(input []string) ([]Result, error) {
	var allResults []Result
	var currentInput []string

	if len(p.domainScanners) > 0 {
		var wg sync.WaitGroup
		resultChan := make(chan scannerResult, len(p.domainScanners))

		for _, scanner := range p.domainScanners {
			wg.Add(1)
			go func(s Scanner) {
				defer wg.Done()
				start := time.Now()
				results, err := s.Execute(input)
				status := buildPluginStatusResult(s.Name(), len(results), err, time.Since(start))
				resultChan <- scannerResult{
					name:     s.Name(),
					results:  results,
					err:      err,
					statuses: []Result{status},
				}
			}(scanner)
		}

		go func() {
			wg.Wait()
			close(resultChan)
		}()

		domainMap := make(map[string]bool)
		for sr := range resultChan {
			allResults = append(allResults, sr.statuses...)

			if sr.err != nil {
				if strings.Contains(sr.err.Error(), "not found in PATH") {
					fmt.Printf("[WARN] [%s] tool not found in PATH, skipped\n", sr.name)
					continue
				}
				return nil, sr.err
			}

			for _, result := range sr.results {
				if result.Type != "domain" {
					continue
				}
				domain, ok := result.Data.(string)
				if !ok || domain == "" || domainMap[domain] {
					continue
				}
				domainMap[domain] = true
				currentInput = append(currentInput, domain)
				allResults = append(allResults, result)
			}
		}
	} else {
		currentInput = input
	}

	networkResults, err := p.runNetworkStage(currentInput)
	if err != nil {
		return nil, err
	}
	allResults = append(allResults, networkResults...)

	for _, scanner := range p.nextScanners {
		start := time.Now()
		results, err := scanner.Execute(currentInput)
		allResults = append(allResults, buildPluginStatusResult(scanner.Name(), len(results), err, time.Since(start)))
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)

		var nextInput []string
		for _, result := range results {
			if data, ok := result.Data.(string); ok {
				nextInput = append(nextInput, data)
			}
		}
		currentInput = nextInput
	}

	return allResults, nil
}

// ExecuteFromSubdomains starts from known subdomains.
func (p *Pipeline) ExecuteFromSubdomains(subdomains []string) ([]Result, error) {
	return p.runNetworkStage(subdomains)
}

func (p *Pipeline) runNetworkStage(input []string) ([]Result, error) {
	var allResults []Result

	if p.httpxScanner == nil && len(p.portScanners) == 0 {
		return allResults, nil
	}

	var wg sync.WaitGroup
	resultChan := make(chan scannerResult, 2)

	if p.httpxScanner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			results, err := p.httpxScanner.Execute(input)
			status := buildPluginStatusResult(p.httpxScanner.Name(), len(results), err, time.Since(start))
			resultChan <- scannerResult{name: p.httpxScanner.Name(), results: results, err: err, statuses: []Result{status}}
		}()
	}

	if len(p.portScanners) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var portResults []Result
			var statusResults []Result
			portInput := input

			for _, scanner := range p.portScanners {
				start := time.Now()
				results, err := scanner.Execute(portInput)
				statusResults = append(statusResults, buildPluginStatusResult(scanner.Name(), len(results), err, time.Since(start)))

				if err != nil {
					if strings.Contains(err.Error(), "not found in PATH") {
						fmt.Printf("[WARN] [%s] tool not found in PATH, port scan skipped\n", scanner.Name())
						break
					}
					resultChan <- scannerResult{name: "PortScan", err: err, statuses: statusResults, results: portResults}
					return
				}

				portResults = append(portResults, results...)

				var nextInput []string
				for _, result := range results {
					if result.Type != "open_port" {
						continue
					}
					data, ok := result.Data.(map[string]interface{})
					if !ok {
						continue
					}
					ip, _ := data["ip"].(string)
					port, _ := data["port"].(int)
					host, _ := data["host"].(string)
					if ip == "" || port <= 0 {
						continue
					}
					nextInput = append(nextInput, fmt.Sprintf("%s:%d:%s", ip, port, host))
				}
				portInput = nextInput
			}

			resultChan <- scannerResult{name: "PortScan", results: portResults, statuses: statusResults}
		}()
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var screenshotInputs []string
	var vulnInputs []string

	for sr := range resultChan {
		allResults = append(allResults, sr.statuses...)

		if sr.err != nil {
			if strings.Contains(sr.err.Error(), "not found in PATH") {
				fmt.Printf("[WARN] [%s] tool not found in PATH, skipped\n", sr.name)
				continue
			}
			return nil, sr.err
		}

		allResults = append(allResults, sr.results...)

		if sr.name != "Httpx" {
			continue
		}

		for _, result := range sr.results {
			if result.Type != "web_service" {
				continue
			}
			data, ok := result.Data.(map[string]interface{})
			if !ok {
				continue
			}
			url, _ := data["url"].(string)
			domain, _ := data["domain"].(string)
			if url == "" {
				continue
			}
			rootDomain := extractRootDomain(domain)
			screenshotInputs = append(screenshotInputs, url+"|"+rootDomain)
			vulnInputs = append(vulnInputs, url+"|"+rootDomain)
		}
	}

	if p.vulnScanner != nil && len(vulnInputs) > 0 {
		fmt.Printf("[Vuln] scanning %d live URLs...\n", len(vulnInputs))
		start := time.Now()
		vulnResults, err := p.vulnScanner.Execute(vulnInputs)
		allResults = append(allResults, buildPluginStatusResult(p.vulnScanner.Name(), len(vulnResults), err, time.Since(start)))
		if err != nil {
			if strings.Contains(err.Error(), "not found in PATH") {
				fmt.Printf("[WARN] [%s] tool not found in PATH, vulnerability scan skipped\n", p.vulnScanner.Name())
			} else {
				fmt.Printf("[WARN] vulnerability scan failed: %v\n", err)
			}
		} else {
			allResults = append(allResults, vulnResults...)
		}
	}

	if p.screenshotScanner != nil && len(screenshotInputs) > 0 {
		fmt.Printf("[Screenshot] capturing %d live URLs...\n", len(screenshotInputs))
		start := time.Now()
		screenshotResults, err := p.screenshotScanner.Execute(screenshotInputs)
		allResults = append(allResults, buildPluginStatusResult(p.screenshotScanner.Name(), len(screenshotResults), err, time.Since(start)))
		if err != nil {
			if strings.Contains(err.Error(), "not found in PATH") {
				fmt.Printf("[WARN] [%s] tool not found in PATH, screenshot skipped\n", p.screenshotScanner.Name())
			} else {
				fmt.Printf("[WARN] screenshot failed: %v\n", err)
			}
		} else {
			allResults = append(allResults, screenshotResults...)
		}
	}

	return allResults, nil
}

// extractRootDomain extracts a rough root domain from subdomain.
func extractRootDomain(subdomain string) string {
	return common.EffectiveRootDomain(subdomain)
}

func buildPluginStatusResult(scannerName string, successCount int, err error, duration time.Duration) Result {
	failureCount := 0
	timeoutCount := 0
	errMsg := ""
	status := "ok"

	if err != nil {
		failureCount = 1
		errMsg = err.Error()
		status = "error"
		if isTimeoutError(err) {
			timeoutCount = 1
		}
	}

	return Result{
		Type: "plugin_status",
		Data: map[string]interface{}{
			"scanner":       scannerName,
			"status":        status,
			"success_count": successCount,
			"failure_count": failureCount,
			"timeout_count": timeoutCount,
			"duration_ms":   duration.Milliseconds(),
			"error":         errMsg,
		},
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}
