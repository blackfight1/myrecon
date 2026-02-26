package plugins

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// ShosubgoPlugin 实现 Shosubgo 子域名搜集器（从 Shodan 查找子域名）
type ShosubgoPlugin struct{}

// NewShosubgoPlugin 创建 Shosubgo 插件实例
func NewShosubgoPlugin() *ShosubgoPlugin {
	return &ShosubgoPlugin{}
}

// Name 返回插件名称
func (s *ShosubgoPlugin) Name() string {
	return "Shosubgo"
}

// Execute 执行 Shosubgo 子域名搜集
func (s *ShosubgoPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 shosubgo 是否存在
	if _, err := exec.LookPath("shosubgo"); err != nil {
		return nil, fmt.Errorf("shosubgo not found in PATH. Please install shosubgo and ensure it's in your PATH")
	}

	// 获取 Shodan API Key
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("SHODAN_API_KEY environment variable is not set")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	domain := input[0]
	fmt.Printf("[Shosubgo] 正在从 Shodan 搜集 %s 的子域名...\n", domain)

	// 执行 shosubgo 命令
	cmd := exec.Command("shosubgo", "-d", domain, "-s", apiKey)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start shosubgo: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	count := 0

	// 逐行读取输出
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain == "" {
			continue
		}

		count++
		results = append(results, engine.Result{
			Type: "domain",
			Data: subdomain,
		})
	}

	if err := cmd.Wait(); err != nil {
		// shosubgo 可能会因为某些原因返回非零退出码
		fmt.Printf("[Shosubgo] 命令执行完成\n")
	}

	fmt.Printf("[Shosubgo] 从 Shodan 发现 %d 个子域名\n", count)
	return results, nil
}
