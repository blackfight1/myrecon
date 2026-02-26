package plugins

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"hunter/internal/engine"
)

const (
	resolversURL  = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	resolversFile = "resolvers.txt"
)

// PurednsPlugin 实现 Puredns DNS 解析和泛解析过滤
type PurednsPlugin struct{}

// NewPurednsPlugin 创建 Puredns 插件实例
func NewPurednsPlugin() *PurednsPlugin {
	return &PurednsPlugin{}
}

// Name 返回插件名称
func (p *PurednsPlugin) Name() string {
	return "Puredns"
}

// Execute 执行 Puredns DNS 解析和泛解析过滤
func (p *PurednsPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 puredns 是否存在
	if _, err := exec.LookPath("puredns"); err != nil {
		return nil, fmt.Errorf("puredns not found in PATH. Install: go install github.com/d3mondev/puredns/v2@latest")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Puredns] 正在更新 resolvers.txt...\n")

	// 更新 resolvers.txt
	if err := updateResolvers(); err != nil {
		fmt.Printf("[Puredns] 警告: 更新 resolvers.txt 失败: %v，尝试使用本地文件\n", err)
	}

	// 检查 resolvers.txt 是否存在
	resolversPath := getResolversPath()
	if _, err := os.Stat(resolversPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("resolvers.txt not found. Please ensure network connectivity")
	}

	fmt.Printf("[Puredns] 正在对 %d 个子域名进行 DNS 解析和泛解析过滤...\n", len(input))

	// 创建临时文件存储子域名列表
	tmpInput, err := createTempFile("puredns_input_*.txt", input)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp input file: %v", err)
	}
	defer removeTempFile(tmpInput)

	// 创建临时输出文件
	tmpOutput, err := os.CreateTemp("", "puredns_output_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp output file: %v", err)
	}
	tmpOutputPath := tmpOutput.Name()
	tmpOutput.Close()
	defer removeTempFile(tmpOutputPath)

	// 执行 puredns resolve
	cmd := exec.Command("puredns", "resolve", tmpInput,
		"-r", resolversPath,
		"-w", tmpOutputPath,
		"--wildcard-batch", "1000000",
		"-q", // quiet mode
	)

	// 捕获 stderr 用于调试
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start puredns: %v", err)
	}

	// 读取 stderr（可选，用于调试）
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "wildcard") {
				fmt.Printf("[Puredns] %s\n", line)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		// puredns 可能返回非零退出码，但结果仍然有效
		fmt.Printf("[Puredns] 命令执行完成\n")
	}

	// 读取输出文件
	outputFile, err := os.Open(tmpOutputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %v", err)
	}
	defer outputFile.Close()

	var results []engine.Result
	scanner := bufio.NewScanner(outputFile)
	count := 0

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

	filtered := len(input) - count
	fmt.Printf("[Puredns] DNS 解析完成: %d 个有效子域名，过滤了 %d 个无效/泛解析子域名\n", count, filtered)

	return results, nil
}

// updateResolvers 从 GitHub 下载最新的 resolvers.txt
func updateResolvers() error {
	resolversPath := getResolversPath()

	// 创建 HTTP 客户端，设置超时
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(resolversURL)
	if err != nil {
		return fmt.Errorf("failed to download resolvers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download resolvers: HTTP %d", resp.StatusCode)
	}

	// 创建临时文件
	tmpFile, err := os.CreateTemp(filepath.Dir(resolversPath), "resolvers_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()

	// 写入内容
	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write resolvers: %v", err)
	}

	// 原子替换
	if err := os.Rename(tmpPath, resolversPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to replace resolvers: %v", err)
	}

	fmt.Printf("[Puredns] resolvers.txt 更新成功\n")
	return nil
}

// getResolversPath 获取 resolvers.txt 的路径
func getResolversPath() string {
	// 优先使用当前目录
	if _, err := os.Stat(resolversFile); err == nil {
		return resolversFile
	}

	// 使用用户主目录下的 .hunter 目录
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return resolversFile
	}

	hunterDir := filepath.Join(homeDir, ".hunter")
	os.MkdirAll(hunterDir, 0755)

	return filepath.Join(hunterDir, resolversFile)
}
