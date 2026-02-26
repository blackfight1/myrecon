package plugins

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"hunter/internal/engine"
)

// NaabuPlugin 实现 Naabu 端口扫描器
type NaabuPlugin struct{}

// NaabuResult Naabu 输出结果结构
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// NewNaabuPlugin 创建 Naabu 插件实例
func NewNaabuPlugin() *NaabuPlugin {
	return &NaabuPlugin{}
}

// Name 返回插件名称
func (n *NaabuPlugin) Name() string {
	return "Naabu"
}

// Execute 执行 Naabu 端口扫描（排除 80/443 端口）
func (n *NaabuPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 naabu 是否存在
	if _, err := exec.LookPath("naabu"); err != nil {
		return nil, fmt.Errorf("naabu not found in PATH. Please install naabu and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Naabu] 正在对 %d 个目标进行端口扫描（top1000，排除80/443）...\n", len(input))

	// 创建临时文件存储目标列表
	tmpFile, err := os.CreateTemp("", "naabu_input_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// 写入目标到临时文件
	for _, target := range input {
		if _, err := tmpFile.WriteString(target + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to temp file: %v", err)
		}
	}
	tmpFile.Close()

	// 执行 naabu 命令
	// -top-ports 1000: 扫描 top 1000 端口
	// -exclude-ports 80,443: 排除 80 和 443 端口（httpx 已处理）
	// -json: JSON 输出
	// -silent: 静默模式
	cmd := exec.Command("naabu",
		"-list", tmpFile.Name(),
		"-top-ports", "1000",
		"-exclude-ports", "80,443",
		"-json",
		"-silent",
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start naabu: %v", err)
	}

	var results []engine.Result
	scanner := bufio.NewScanner(stdout)
	portCount := 0

	// 实时解析 JSONL 输出
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var naabuResult NaabuResult
		if err := json.Unmarshal([]byte(line), &naabuResult); err != nil {
			continue
		}

		portCount++

		// 实时显示进度
		if portCount%10 == 0 || portCount == 1 {
			fmt.Printf("[Naabu] 已发现 %d 个开放端口\n", portCount)
		}

		results = append(results, engine.Result{
			Type: "open_port",
			Data: map[string]interface{}{
				"host": naabuResult.Host,
				"ip":   naabuResult.IP,
				"port": naabuResult.Port,
			},
		})
	}

	if err := cmd.Wait(); err != nil {
		// naabu 可能会因为某些目标无法访问而返回非零退出码
		fmt.Printf("[Naabu] 命令执行完成\n")
	}

	fmt.Printf("[Naabu] 端口扫描完成，发现 %d 个开放端口\n", portCount)
	return results, nil
}
