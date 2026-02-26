package plugins

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// SubdogPlugin 实现 Subdog 扫描器
type SubdogPlugin struct {
	batchMode bool
}

// NewSubdogPlugin 创建 Subdog 插件实例
func NewSubdogPlugin(batchMode bool) *SubdogPlugin {
	return &SubdogPlugin{batchMode: batchMode}
}

// Name 返回插件名称
func (s *SubdogPlugin) Name() string {
	return "Subdog"
}

// Execute 执行 Subdog 扫描
func (s *SubdogPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 subdog 是否存在
	if _, err := exec.LookPath("subdog"); err != nil {
		return nil, fmt.Errorf("subdog not found in PATH. Please install subdog and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	var results []engine.Result
	var allHosts []string

	// 批量模式：一次性将所有域名通过 stdin 传入
	if s.batchMode && len(input) > 1 {
		fmt.Printf("[Subdog] 批量模式: 正在搜集 %d 个域名的子域名...\n", len(input))

		cmd := exec.Command("subdog", "--silent")

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
		}

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("failed to start subdog: %v", err)
		}

		// 写入所有域名到 stdin
		go func() {
			defer stdin.Close()
			for _, domain := range input {
				io.WriteString(stdin, domain+"\n")
			}
		}()

		scanner := bufio.NewScanner(stdout)
		hostSet := make(map[string]bool)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if !hostSet[line] {
				hostSet[line] = true
				allHosts = append(allHosts, line)
			}
		}

		if err := cmd.Wait(); err != nil {
			fmt.Printf("[Subdog] 命令执行完成\n")
		}

		fmt.Printf("[Subdog] 批量模式发现 %d 个子域名\n", len(allHosts))
	} else {
		// 单域名模式
		for _, domain := range input {
			fmt.Printf("[Subdog] 正在搜集域名: %s\n", domain)

			cmd := exec.Command("subdog", "--silent")

			stdin, err := cmd.StdinPipe()
			if err != nil {
				return nil, fmt.Errorf("failed to create stdin pipe: %v", err)
			}

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
			}

			if err := cmd.Start(); err != nil {
				return nil, fmt.Errorf("failed to start subdog: %v", err)
			}

			go func() {
				defer stdin.Close()
				io.WriteString(stdin, domain+"\n")
			}()

			scanner := bufio.NewScanner(stdout)
			var hosts []string

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}

				if !contains(hosts, line) {
					hosts = append(hosts, line)
					allHosts = append(allHosts, line)
				}
			}

			if err := cmd.Wait(); err != nil {
				fmt.Printf("[Subdog] 命令执行完成\n")
			}

			fmt.Printf("[Subdog] 发现 %d 个域名\n", len(hosts))
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
