package engine

import (
	"fmt"
	"strings"
	"sync"
)

// Result 表示扫描结果
type Result struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Scanner 定义扫描器接口
type Scanner interface {
	Name() string
	Execute(input []string) ([]Result, error)
}

// Pipeline 表示扫描流水线
type Pipeline struct {
	domainScanners    []Scanner // 子域名搜集器（并行执行）
	nextScanners      []Scanner // 后续扫描器（串行执行）
	httpxScanner      Scanner   // Httpx 扫描器（与端口扫描并行）
	portScanners      []Scanner // 端口扫描链（Naabu → Nmap，串行执行，与 Httpx 并行）
	screenshotScanner Scanner   // 截图扫描器（httpx 完成后执行）
}

// NewPipeline 创建新的流水线
func NewPipeline() *Pipeline {
	return &Pipeline{
		domainScanners: make([]Scanner, 0),
		nextScanners:   make([]Scanner, 0),
		portScanners:   make([]Scanner, 0),
	}
}

// SetScreenshotScanner 设置截图扫描器
func (p *Pipeline) SetScreenshotScanner(scanner Scanner) {
	p.screenshotScanner = scanner
}

// AddDomainScanner 添加子域名搜集器（会并行执行）
func (p *Pipeline) AddDomainScanner(scanner Scanner) {
	p.domainScanners = append(p.domainScanners, scanner)
}

// AddScanner 添加后续扫描器（串行执行）
func (p *Pipeline) AddScanner(scanner Scanner) {
	p.nextScanners = append(p.nextScanners, scanner)
}

// SetHttpxScanner 设置 Httpx 扫描器（与端口扫描并行执行）
func (p *Pipeline) SetHttpxScanner(scanner Scanner) {
	p.httpxScanner = scanner
}

// AddPortScanner 添加端口扫描器（Naabu → Nmap 串行执行）
func (p *Pipeline) AddPortScanner(scanner Scanner) {
	p.portScanners = append(p.portScanners, scanner)
}

// scannerResult 用于收集并行扫描的结果
type scannerResult struct {
	name    string
	results []Result
	err     error
}

// Execute 执行流水线
func (p *Pipeline) Execute(input []string) ([]Result, error) {
	var allResults []Result
	var currentInput []string

	// 第一阶段：并行执行所有子域名搜集器
	if len(p.domainScanners) > 0 {
		var wg sync.WaitGroup
		resultChan := make(chan scannerResult, len(p.domainScanners))

		// 并行启动所有扫描器
		for _, scanner := range p.domainScanners {
			wg.Add(1)
			go func(s Scanner) {
				defer wg.Done()
				results, err := s.Execute(input)
				resultChan <- scannerResult{
					name:    s.Name(),
					results: results,
					err:     err,
				}
			}(scanner)
		}

		// 等待所有扫描器完成后关闭 channel
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// 收集结果并去重
		domainMap := make(map[string]bool)
		for sr := range resultChan {
			if sr.err != nil {
				// 如果工具不存在，打印警告并跳过
				if strings.Contains(sr.err.Error(), "not found in PATH") {
					fmt.Printf("⚠️  [%s] 工具未安装，跳过\n", sr.name)
					continue
				}
				// 其他错误则返回
				return nil, sr.err
			}

			// 收集所有域名结果并去重
			for _, result := range sr.results {
				if result.Type == "domain" {
					if domain, ok := result.Data.(string); ok {
						if !domainMap[domain] {
							domainMap[domain] = true
							currentInput = append(currentInput, domain)
							allResults = append(allResults, result)
						}
					}
				}
			}
		}
	} else {
		currentInput = input
	}

	// 第二阶段：并行执行 Httpx 和端口扫描链
	if p.httpxScanner != nil || len(p.portScanners) > 0 {
		var wg sync.WaitGroup
		resultChan := make(chan scannerResult, 2)

		// 启动 Httpx 扫描（如果设置了）
		if p.httpxScanner != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results, err := p.httpxScanner.Execute(currentInput)
				resultChan <- scannerResult{
					name:    p.httpxScanner.Name(),
					results: results,
					err:     err,
				}
			}()
		}

		// 启动端口扫描链（Naabu → Nmap）
		if len(p.portScanners) > 0 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var portResults []Result
				portInput := currentInput

				for _, scanner := range p.portScanners {
					results, err := scanner.Execute(portInput)
					if err != nil {
						if strings.Contains(err.Error(), "not found in PATH") {
							fmt.Printf("⚠️  [%s] 工具未安装，跳过端口扫描链\n", scanner.Name())
							break
						}
						resultChan <- scannerResult{
							name: "PortScan",
							err:  err,
						}
						return
					}

					portResults = append(portResults, results...)

					// 准备下一阶段的输入（Naabu → Nmap）
					// 将 open_port 结果转换为 "ip:port:host" 格式
					var nextInput []string
					for _, result := range results {
						if result.Type == "open_port" {
							if data, ok := result.Data.(map[string]interface{}); ok {
								ip := ""
								port := 0
								host := ""
								if v, ok := data["ip"].(string); ok {
									ip = v
								}
								if v, ok := data["port"].(int); ok {
									port = v
								}
								if v, ok := data["host"].(string); ok {
									host = v
								}
								if ip != "" && port > 0 {
									nextInput = append(nextInput, fmt.Sprintf("%s:%d:%s", ip, port, host))
								}
							}
						}
					}
					portInput = nextInput
				}

				resultChan <- scannerResult{
					name:    "PortScan",
					results: portResults,
				}
			}()
		}

		// 等待所有扫描器完成后关闭 channel
		go func() {
			wg.Wait()
			close(resultChan)
		}()

		// 收集结果，同时收集 httpx 的 URL 用于截图
		var httpxURLs []string
		for sr := range resultChan {
			if sr.err != nil {
				if strings.Contains(sr.err.Error(), "not found in PATH") {
					fmt.Printf("⚠️  [%s] 工具未安装，跳过\n", sr.name)
					continue
				}
				return nil, sr.err
			}
			allResults = append(allResults, sr.results...)

			// 收集 httpx 结果中的 URL 用于截图
			if sr.name == "Httpx" {
				for _, result := range sr.results {
					if result.Type == "web_service" {
						if data, ok := result.Data.(map[string]interface{}); ok {
							if url, ok := data["url"].(string); ok && url != "" {
								// 获取域名并提取根域名
								domain := ""
								if d, ok := data["domain"].(string); ok {
									domain = d
								}
								// 格式: url|root_domain
								rootDomain := extractRootDomain(domain)
								httpxURLs = append(httpxURLs, url+"|"+rootDomain)
							}
						}
					}
				}
			}
		}

		// 第三阶段：执行截图（如果设置了截图扫描器）
		if p.screenshotScanner != nil && len(httpxURLs) > 0 {
			fmt.Printf("📸 开始对 %d 个存活 URL 进行截图...\n", len(httpxURLs))
			screenshotResults, err := p.screenshotScanner.Execute(httpxURLs)
			if err != nil {
				if strings.Contains(err.Error(), "not found in PATH") {
					fmt.Printf("⚠️  [%s] 工具未安装，跳过截图\n", p.screenshotScanner.Name())
				} else {
					fmt.Printf("⚠️  截图执行失败: %v\n", err)
				}
			} else {
				allResults = append(allResults, screenshotResults...)
			}
		}
	}

	// 第三阶段：串行执行其他后续扫描器
	for _, scanner := range p.nextScanners {
		results, err := scanner.Execute(currentInput)
		if err != nil {
			return nil, err
		}

		allResults = append(allResults, results...)

		// 准备下一阶段的输入
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

// extractRootDomain 从子域名提取根域名
func extractRootDomain(subdomain string) string {
	parts := strings.Split(subdomain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return subdomain
}
