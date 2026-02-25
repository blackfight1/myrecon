package plugins

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// SamoscoutPlugin 实现 Samoscout 扫描器
type SamoscoutPlugin struct{}

// SamoscoutResult Samoscout 输出结果结构
type SamoscoutResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// NewSamoscoutPlugin 创建 Samoscout 插件实例
func NewSamoscoutPlugin() *SamoscoutPlugin {
	return &SamoscoutPlugin{}
}

// Name 返回插件名称
func (s *SamoscoutPlugin) Name() string {
	return "Samoscout"
}

// Execute 执行 Samoscout 扫描
func (s *SamoscoutPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 samoscout 是否存在
	if _, err := exec.LookPath("samoscout"); err != nil {
		return nil, fmt.Errorf("samoscout not found in PATH. Please install samoscout and ensure it's in your PATH")
	}

	var results []engine.Result
	var allHosts []string

	for _, domain := range input {
		fmt.Printf("[Samoscout] 正在搜集域名: %s\n", domain)

		cmd := exec.Command("samoscout", "-d", domain, "-silent", "-json")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start samoscout: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		var hosts []string
		skipInvalidLines := true

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// 跳过前面的日志行（不是有效的 JSON）
			if skipInvalidLines {
				// 检查是否是日志行
				if strings.HasPrefix(line, "[INF]") ||
					strings.HasPrefix(line, "[WARN]") ||
					strings.HasPrefix(line, "[ERR]") ||
					!strings.HasPrefix(line, "{") {
					continue
				}
				// 遇到第一个有效 JSON 后，不再跳过
				skipInvalidLines = false
			}

			var samoResult SamoscoutResult
			if err := json.Unmarshal([]byte(line), &samoResult); err != nil {
				// 如果解析失败，可能还是日志行，继续跳过
				continue
			}

			// 去重
			if !contains(hosts, samoResult.Host) {
				hosts = append(hosts, samoResult.Host)
				allHosts = append(allHosts, samoResult.Host)
			}
		}

		if err := cmd.Wait(); err != nil {
			// samoscout 可能会返回非零退出码，但这是正常的
			fmt.Printf("[Samoscout] 命令执行完成\n")
		}

		fmt.Printf("[Samoscout] 发现 %d 个域名\n", len(hosts))
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

// contains 检查字符串切片是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
