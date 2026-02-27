package plugins

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"hunter/internal/engine"
)

// GowitnessPlugin 实现 Gowitness 截图扫描器
type GowitnessPlugin struct {
	baseDir string // 截图存储基础目录
}

// NewGowitnessPlugin 创建 Gowitness 插件实例
func NewGowitnessPlugin(baseDir string) *GowitnessPlugin {
	if baseDir == "" {
		baseDir = "screenshots"
	}
	return &GowitnessPlugin{baseDir: baseDir}
}

// Name 返回插件名称
func (g *GowitnessPlugin) Name() string {
	return "Gowitness"
}

// Execute 执行 Gowitness 截图
// input 格式: []string{"url|root_domain", ...}
func (g *GowitnessPlugin) Execute(input []string) ([]engine.Result, error) {
	// 检查 gowitness 是否存在
	if _, err := exec.LookPath("gowitness"); err != nil {
		return nil, fmt.Errorf("gowitness not found in PATH. Please install gowitness and ensure it's in your PATH")
	}

	if len(input) == 0 {
		return []engine.Result{}, nil
	}

	// 按根域名分组 URL
	domainURLs := make(map[string][]string)
	for _, item := range input {
		parts := strings.SplitN(item, "|", 2)
		if len(parts) != 2 {
			continue
		}
		url := parts[0]
		rootDomain := parts[1]
		domainURLs[rootDomain] = append(domainURLs[rootDomain], url)
	}

	var results []engine.Result
	totalScreenshots := 0

	// 对每个根域名分别执行截图
	for rootDomain, urls := range domainURLs {
		fmt.Printf("[Gowitness] 正在对 %s 的 %d 个 URL 进行截图...\n", rootDomain, len(urls))

		// 创建域名专属目录
		domainDir := filepath.Join(g.baseDir, rootDomain)
		if err := os.MkdirAll(domainDir, 0755); err != nil {
			fmt.Printf("[Gowitness] 创建目录失败 %s: %v\n", domainDir, err)
			continue
		}

		// 创建临时文件存储 URL 列表
		tmpFile, err := os.CreateTemp("", "gowitness_urls_*.txt")
		if err != nil {
			fmt.Printf("[Gowitness] 创建临时文件失败: %v\n", err)
			continue
		}

		// 写入 URL 到临时文件
		for _, url := range urls {
			if _, err := tmpFile.WriteString(url + "\n"); err != nil {
				fmt.Printf("[Gowitness] 写入临时文件失败: %v\n", err)
			}
		}
		tmpFile.Close()

		// 执行 gowitness 命令
		// 在域名目录下执行，这样 gowitness.sqlite3 和 screenshots 都会在该目录下
		cmd := exec.Command("gowitness",
			"scan", "file",
			"-f", tmpFile.Name(),
			"--ports-small",
			"--threads", "10",
			"--write-db",
			"-q",
			"--http-code-filter", "200,403,401",
		)
		cmd.Dir = domainDir // 设置工作目录

		// 执行命令
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("[Gowitness] %s 截图执行出错: %v\n%s\n", rootDomain, err, string(output))
		}

		// 清理临时文件
		os.Remove(tmpFile.Name())

		// 统计截图数量
		screenshotDir := filepath.Join(domainDir, "screenshots")
		count := countFiles(screenshotDir)
		totalScreenshots += count

		fmt.Printf("[Gowitness] %s 截图完成，生成 %d 张截图\n", rootDomain, count)

		// 记录结果
		results = append(results, engine.Result{
			Type: "screenshot",
			Data: map[string]interface{}{
				"root_domain":      rootDomain,
				"screenshot_count": count,
				"screenshot_dir":   screenshotDir,
				"database":         filepath.Join(domainDir, "gowitness.sqlite3"),
			},
		})
	}

	fmt.Printf("[Gowitness] 截图任务完成，共生成 %d 张截图\n", totalScreenshots)
	return results, nil
}

// StartReportServer 启动截图查看服务
func StartReportServer(baseDir, rootDomain, host string, port int) error {
	// 检查 gowitness 是否存在
	if _, err := exec.LookPath("gowitness"); err != nil {
		return fmt.Errorf("gowitness not found in PATH")
	}

	domainDir := filepath.Join(baseDir, rootDomain)

	// 检查目录是否存在
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		return fmt.Errorf("截图目录不存在: %s", domainDir)
	}

	// 检查数据库文件是否存在
	dbFile := filepath.Join(domainDir, "gowitness.sqlite3")
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		return fmt.Errorf("数据库文件不存在: %s", dbFile)
	}

	fmt.Printf("🖼️  启动 %s 的截图查看服务: http://%s:%d\n", rootDomain, host, port)

	// 执行 gowitness report server
	cmd := exec.Command("gowitness",
		"report", "server",
		"--host", host,
		"--port", fmt.Sprintf("%d", port),
	)
	cmd.Dir = domainDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// ListScreenshotDomains 列出所有有截图的域名
func ListScreenshotDomains(baseDir string) ([]string, error) {
	if baseDir == "" {
		baseDir = "screenshots"
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var domains []string
	for _, entry := range entries {
		if entry.IsDir() {
			// 检查是否有 gowitness.sqlite3 文件
			dbFile := filepath.Join(baseDir, entry.Name(), "gowitness.sqlite3")
			if _, err := os.Stat(dbFile); err == nil {
				domains = append(domains, entry.Name())
			}
		}
	}

	return domains, nil
}

// countFiles 统计目录下的文件数量
func countFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}

// ExtractRootDomain 从子域名提取根域名
func ExtractRootDomain(subdomain string) string {
	parts := strings.Split(subdomain, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return subdomain
}
