package plugins

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// SubfinderPlugin 实现 Subfinder 扫描器
type SubfinderPlugin struct{}

// SubfinderResult Subfinder 输出结果结构
type SubfinderResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// NewSubfinderPlugin 创建 Subfinder 插件实例
func NewSubfinderPlugin() *SubfinderPlugin {
	return &SubfinderPlugin{}
}

// Name 返回插件名称
func (s *SubfinderPlugin) Name() string {
	return "Subfinder"
}

// Execute 执行 Subfinder 扫描
func (s *SubfinderPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 subfinder 是否存在
	if _, err := exec.LookPath("subfinder"); err != nil {
		return nil, fmt.Errorf("subfinder not found in PATH. Please install subfinder and ensure it's in your PATH")
	}

	var results []engine.Result
	var allHosts []string

	for _, domain := range input {
		fmt.Printf("[Subfinder] 正在搜集域名: %s\n", domain)

		cmd := exec.Command("subfinder", "-d", domain, "-json", "-silent")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start subfinder: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		var hosts []string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			var subResult SubfinderResult
			if err := json.Unmarshal([]byte(line), &subResult); err != nil {
				continue // 跳过无效的 JSON 行
			}

			hosts = append(hosts, subResult.Host)
			allHosts = append(allHosts, subResult.Host)
		}

		if err := cmd.Wait(); err != nil {
			return nil, fmt.Errorf("subfinder execution failed: %v", err)
		}

		fmt.Printf("[Subfinder] 发现 %d 个域名\n", len(hosts))
	}

	// 将所有发现的域名作为结果返回
	for _, host := range allHosts {
		results = append(results, engine.Result{
			Type: "domain",
			Data: host,
		})
	}

	return results, nil
}
