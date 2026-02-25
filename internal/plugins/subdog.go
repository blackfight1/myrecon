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
type SubdogPlugin struct{}

// NewSubdogPlugin 创建 Subdog 插件实例
func NewSubdogPlugin() *SubdogPlugin {
	return &SubdogPlugin{}
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

	var results []engine.Result
	var allHosts []string

	for _, domain := range input {
		fmt.Printf("[Subdog] 正在搜集域名: %s\n", domain)

		// subdog 需要通过 stdin 接收输入
		cmd := exec.Command("subdog", "--silent")

		// 创建管道
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

		// 写入域名到 stdin
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, domain+"\n")
		}()

		// 读取输出
		scanner := bufio.NewScanner(stdout)
		var hosts []string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			// subdog 输出的是纯文本域名，每行一个
			// 去重
			if !contains(hosts, line) {
				hosts = append(hosts, line)
				allHosts = append(allHosts, line)
			}
		}

		if err := cmd.Wait(); err != nil {
			// subdog 可能会返回非零退出码，但这是正常的
			fmt.Printf("[Subdog] 命令执行完成\n")
		}

		fmt.Printf("[Subdog] 发现 %d 个域名\n", len(hosts))
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
