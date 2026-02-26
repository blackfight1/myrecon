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
type SamoscoutPlugin struct {
	batchMode bool
}

// SamoscoutResult Samoscout 输出结果结构
type SamoscoutResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

// NewSamoscoutPlugin 创建 Samoscout 插件实例
func NewSamoscoutPlugin(batchMode bool) *SamoscoutPlugin {
	return &SamoscoutPlugin{batchMode: batchMode}
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

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var results []engine.Result
	var allHosts []string

	// 批量模式：使用 -dL 参数
	if s.batchMode && len(input) > 1 {
		fmt.Printf("[Samoscout] 批量模式: 正在搜集 %d 个域名的子域名...\n", len(input))

		// 创建临时文件存储域名列表
		tmpFile, err := createTempFile("samoscout_domains_*.txt", input)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %v", err)
		}
		defer removeTempFile(tmpFile)

		cmd := exec.Command("samoscout", "-dL", tmpFile, "-silent", "-json")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start samoscout: %v", err)
		}

		scanner := bufio.NewScanner(stdout)
		hostSet := make(map[string]bool)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}

			var samoResult SamoscoutResult
			if err := json.Unmarshal([]byte(line), &samoResult); err != nil {
				continue
			}

			if !hostSet[samoResult.Host] {
				hostSet[samoResult.Host] = true
				allHosts = append(allHosts, samoResult.Host)
			}
		}

		if err := cmd.Wait(); err != nil {
			fmt.Printf("[Samoscout] 命令执行完成\n")
		}

		fmt.Printf("[Samoscout] 批量模式发现 %d 个子域名\n", len(allHosts))
	} else {
		// 单域名模式
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

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || !strings.HasPrefix(line, "{") {
					continue
				}

				var samoResult SamoscoutResult
				if err := json.Unmarshal([]byte(line), &samoResult); err != nil {
					continue
				}

				if !contains(hosts, samoResult.Host) {
					hosts = append(hosts, samoResult.Host)
					allHosts = append(allHosts, samoResult.Host)
				}
			}

			if err := cmd.Wait(); err != nil {
				fmt.Printf("[Samoscout] 命令执行完成\n")
			}

			fmt.Printf("[Samoscout] 发现 %d 个域名\n", len(hosts))
		}
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
