package plugins

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"hunter/internal/engine"
)

// HttpxPlugin 实现 Httpx 扫描器
type HttpxPlugin struct{}

// HttpxResult Httpx 输出结果结构
type HttpxResult struct {
	URL         string   `json:"url"`
	StatusCode  int      `json:"status_code"`
	Title       string   `json:"title"`
	Tech        []string `json:"tech"`    // httpx 使用 tech 而不是 technologies
	Host        string   `json:"host"`    // 域名
	HostIP      string   `json:"host_ip"` // IP 地址
	A           []string `json:"a"`       // A 记录列表
	ContentType string   `json:"content_type"`
	Method      string   `json:"method"`
	Input       string   `json:"input"`
	Webserver   string   `json:"webserver"`
	CDN         bool     `json:"cdn"`
	CDNName     string   `json:"cdn_name"`
}

// NewHttpxPlugin 创建 Httpx 插件实例
func NewHttpxPlugin() *HttpxPlugin {
	return &HttpxPlugin{}
}

// Name 返回插件名称
func (h *HttpxPlugin) Name() string {
	return "Httpx"
}

// Execute 执行 Httpx 扫描
func (h *HttpxPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 httpx 是否存在
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not found in PATH. Please install httpx and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Httpx] 正在对 %d 个域名进行测活...\n", len(input))

	// 创建临时文件存储域名列表
	tmpFile, err := os.CreateTemp("", "httpx_input_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// 写入域名到临时文件
	for _, domain := range input {
		if _, err := tmpFile.WriteString(domain + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %v", err)
		}
	}
	tmpFile.Close()

	// 执行 httpx 命令
	cmd := exec.Command("httpx",
		"-l", tmpFile.Name(),
		"-json",
		"-sc",    // status code
		"-title", // page title
		"-td",    // tech detect
		"-ip",    // resolve IP
		"-silent",
		"-timeout", "10",
		"-retries", "2",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start httpx: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	liveCount := 0

	// 实时解析 JSONL 输出
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var httpxResult HttpxResult
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			fmt.Printf("[Httpx] 解析 JSON 失败: %s\n", line)
			continue
		}

		liveCount++

		// 实时显示进度
		if liveCount%10 == 0 || liveCount == 1 {
			fmt.Printf("[Httpx] 已发现 %d 个存活服务\n", liveCount)
		}

		// 使用 host_ip 或 A 记录中的第一个 IP
		ip := httpxResult.HostIP
		if ip == "" && len(httpxResult.A) > 0 {
			ip = httpxResult.A[0]
		}

		results = append(results, engine.Result{
			Type: "web_service",
			Data: map[string]interface{}{
				"url":           httpxResult.URL,
				"status_code":   httpxResult.StatusCode,
				"title":         httpxResult.Title,
				"technologies":  httpxResult.Tech, // 使用 tech 字段
				"ip":            ip,
				"domain":        httpxResult.Host, // 使用 host 字段作为域名
				"discovered_at": time.Now(),
			},
		})
	}

	if err := cmd.Wait(); err != nil {
		// httpx 可能会因为某些域名无法访问而返回非零退出码，但这是正常的
		fmt.Printf("[Httpx] 命令执行完成，可能有部分域名无法访问\n")
	}

	fmt.Printf("[Httpx] 测活完成，发现 %d 个存活服务\n", liveCount)
	return results, nil
}
