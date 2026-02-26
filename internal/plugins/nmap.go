package plugins

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"hunter/internal/engine"
)

// NmapPlugin 实现 Nmap 服务识别扫描器
type NmapPlugin struct{}

// NewNmapPlugin 创建 Nmap 插件实例
func NewNmapPlugin() *NmapPlugin {
	return &NmapPlugin{}
}

// Name 返回插件名称
func (n *NmapPlugin) Name() string {
	return "Nmap"
}

// Execute 执行 Nmap 服务识别
// 输入格式：从 Naabu 结果中提取的 IP:Port 信息
func (n *NmapPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 nmap 是否存在
	if _, err := exec.LookPath("nmap"); err != nil {
		return nil, fmt.Errorf("nmap not found in PATH. Please install nmap and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	// 解析输入，按 IP 分组端口
	// 输入格式: "ip:port:host" 或 "ip:port"
	ipPorts := make(map[string][]int)  // IP -> []Port
	ipHosts := make(map[string]string) // IP -> Host (域名)

	for _, item := range input {
		parts := strings.Split(item, ":")
		if len(parts) < 2 {
			continue
		}
		ip := parts[0]
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		ipPorts[ip] = append(ipPorts[ip], port)
		if len(parts) >= 3 && parts[2] != "" {
			ipHosts[ip] = parts[2]
		}
	}

	if len(ipPorts) == 0 {
		return []engine.Result{}, nil
	}

	fmt.Printf("[Nmap] 正在对 %d 个 IP 进行服务识别...\n", len(ipPorts))

	var results []engine.Result
	scannedCount := 0

	// 对每个 IP 执行 nmap 服务识别
	for ip, ports := range ipPorts {
		scannedCount++

		// 构建端口列表字符串
		portStrs := make([]string, len(ports))
		for i, p := range ports {
			portStrs[i] = strconv.Itoa(p)
		}
		portList := strings.Join(portStrs, ",")

		fmt.Printf("[Nmap] (%d/%d) 扫描 %s 的 %d 个端口...\n", scannedCount, len(ipPorts), ip, len(ports))

		// 执行 nmap 命令
		// -sV: 服务版本探测
		// -Pn: 跳过主机发现（已知端口开放）
		// -T4: 加快扫描速度
		// --open: 只显示开放端口
		cmd := exec.Command("nmap",
			"-sV",
			"-Pn",
			"-T4",
			"--open",
			"-p", portList,
			ip,
		)

		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("[Nmap] 扫描 %s 时出错: %v\n", ip, err)
			continue
		}

		// 解析 nmap 输出
		host := ipHosts[ip]
		portResults := parseNmapOutput(string(output), ip, host)
		results = append(results, portResults...)
	}

	fmt.Printf("[Nmap] 服务识别完成，共识别 %d 个服务\n", len(results))
	return results, nil
}

// parseNmapOutput 解析 nmap 输出
func parseNmapOutput(output string, ip string, host string) []engine.Result {
	var results []engine.Result

	// 匹配端口行，格式如: "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu"
	// 正则: 端口/协议  状态  服务名  版本信息(可选)
	portRegex := regexp.MustCompile(`(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)`)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		matches := portRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		port, _ := strconv.Atoi(matches[1])
		protocol := matches[2]
		service := matches[3]
		version := strings.TrimSpace(matches[4])

		results = append(results, engine.Result{
			Type: "port_service",
			Data: map[string]interface{}{
				"ip":       ip,
				"port":     port,
				"protocol": protocol,
				"service":  service,
				"version":  version,
				"domain":   host,
			},
		})
	}

	return results
}
