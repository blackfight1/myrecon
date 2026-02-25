package engine

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

// Execute 执行流水线
func (p *Pipeline) Execute(input []string) ([]Result, error) {
	var allResults []Result
	var currentInput []string

	// 第一阶段：并行执行所有子域名搜集器
	if len(p.domainScanners) > 0 {
		domainMap := make(map[string]bool) // 用于去重

		for _, scanner := range p.domainScanners {
			results, err := scanner.Execute(input)
			if err != nil {
				return nil, err
			}

			// 收集所有域名结果并去重
			for _, result := range results {
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
