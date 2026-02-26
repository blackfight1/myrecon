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
	domainScanners []Scanner // 子域名搜集器（并行执行）
	nextScanners   []Scanner // 后续扫描器（串行执行）
}

// NewPipeline 创建新的流水线
func NewPipeline() *Pipeline {
	return &Pipeline{
		domainScanners: make([]Scanner, 0),
		nextScanners:   make([]Scanner, 0),
	}
}

// AddDomainScanner 添加子域名搜集器（会并行执行）
func (p *Pipeline) AddDomainScanner(scanner Scanner) {
	p.domainScanners = append(p.domainScanners, scanner)
}

// AddScanner 添加后续扫描器（串行执行）
func (p *Pipeline) AddScanner(scanner Scanner) {
	p.nextScanners = append(p.nextScanners, scanner)
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

	// 第二阶段：串行执行后续扫描器
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
