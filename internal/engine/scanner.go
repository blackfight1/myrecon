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
	scanners []Scanner
}

// NewPipeline 创建新的流水线
func NewPipeline() *Pipeline {
	return &Pipeline{
		scanners: make([]Scanner, 0),
	}
}

// AddScanner 添加扫描器到流水线
func (p *Pipeline) AddScanner(scanner Scanner) {
	p.scanners = append(p.scanners, scanner)
}

// Execute 执行流水线
func (p *Pipeline) Execute(input []string) ([]Result, error) {
	currentInput := input
	var allResults []Result

	for _, scanner := range p.scanners {
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
