package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

func main() {
	// 基础参数
	domain := flag.String("d", "", "单个目标域名")
	domainList := flag.String("dL", "", "域名列表文件")
	inputFile := flag.String("i", "", "输入文件（用于 ports/witness 模块独立运行）")

	// 模块选择
	modules := flag.String("m", "", "选择模块: subs,ports,witness（逗号分隔，默认全部）")

	// 控制参数
	dryRun := flag.Bool("dry-run", false, "测试模式，不写入数据库")
	screenshotDir := flag.String("screenshot-dir", "screenshots", "截图存储目录")

	// 截图服务参数
	reportDomain := flag.String("report", "", "启动截图查看服务")
	reportHost := flag.String("report-host", "0.0.0.0", "截图服务监听地址")
	reportPort := flag.Int("report-port", 7070, "截图服务监听端口")
	listScreenshots := flag.Bool("list-screenshots", false, "列出所有有截图的域名")

	flag.Parse()

	// 列出所有有截图的域名
	if *listScreenshots {
		domains, err := plugins.ListScreenshotDomains(*screenshotDir)
		if err != nil {
			log.Fatalf("获取截图域名列表失败: %v", err)
		}
		if len(domains) == 0 {
			fmt.Println("暂无截图数据")
		} else {
			fmt.Println("📸 已有截图的域名:")
			for _, d := range domains {
				fmt.Printf("  • %s\n", d)
			}
			fmt.Printf("\n使用 -report {domain} 启动查看服务\n")
		}
		return
	}

	// 启动截图查看服务
	if *reportDomain != "" {
		if err := plugins.StartReportServer(*screenshotDir, *reportDomain, *reportHost, *reportPort); err != nil {
			log.Fatalf("启动截图服务失败: %v", err)
		}
		return
	}

	// 解析模块选择
	enableSubs := false
	enablePorts := false
	enableWitness := false

	if *modules == "" {
		// 默认启用所有模块
		enableSubs = true
		enablePorts = true
		enableWitness = true
	} else {
		modList := strings.Split(strings.ToLower(*modules), ",")
		for _, m := range modList {
			m = strings.TrimSpace(m)
			switch m {
			case "subs":
				enableSubs = true
			case "ports":
				enablePorts = true
			case "witness":
				enableWitness = true
			default:
				log.Fatalf("未知模块: %s（可用: subs, ports, witness）", m)
			}
		}
	}

	// 验证输入参数
	if !validateInput(*domain, *domainList, *inputFile, enableSubs, enablePorts, enableWitness) {
		printUsage()
		os.Exit(1)
	}

	// 获取输入数据
	var input []string
	var err error

	if enableSubs {
		// subs 模块需要域名输入
		input, err = getDomainsInput(*domain, *domainList)
	} else if *inputFile != "" {
		// ports/witness 模块使用 -i 输入
		input, err = readLinesFromFile(*inputFile)
	} else {
		// 从 stdin 读取
		input, err = readLinesFromStdin()
	}

	if err != nil {
		log.Fatalf("读取输入失败: %v", err)
	}

	if len(input) == 0 {
		log.Fatalf("输入为空")
	}

	// 打印运行信息
	printRunInfo(enableSubs, enablePorts, enableWitness, *dryRun, len(input))

	// 连接数据库（如果需要）
	var database *db.Database
	var beforeAssetCount, beforePortCount int64

	if !*dryRun {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err = db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("数据库连接失败: %v", err)
		}
		beforeAssetCount, _ = database.GetAssetCount()
		beforePortCount, _ = database.GetPortCount()
	} else {
		fmt.Println("🧪 测试模式：结果不会写入数据库")
	}

	scanStartTime := time.Now()

	// 根据模块组合执行不同流程
	var results []engine.Result

	if enableSubs && !enablePorts && !enableWitness {
		// 仅子域名收集
		results, err = runSubsOnly(input)
	} else if !enableSubs && enablePorts && !enableWitness {
		// 仅端口扫描
		results, err = runPortsOnly(input)
	} else if !enableSubs && !enablePorts && enableWitness {
		// 仅截图
		results, err = runWitnessOnly(input, *screenshotDir)
	} else if enableSubs && enablePorts && !enableWitness {
		// 子域名 + 端口
		results, err = runSubsAndPorts(input)
	} else if enableSubs && !enablePorts && enableWitness {
		// 子域名 + 截图（需要先 httpx）
		results, err = runSubsAndWitness(input, *screenshotDir)
	} else if !enableSubs && enablePorts && enableWitness {
		// 端口 + 截图
		results, err = runPortsAndWitness(input, *screenshotDir)
	} else {
		// 完整流程
		results, err = runFullPipeline(input, *screenshotDir)
	}

	if err != nil {
		log.Fatalf("执行失败: %v", err)
	}

	// 保存结果
	if !*dryRun && database != nil {
		saveResults(database, results, input)
	}

	// 打印统计
	printSummary(results, input, scanStartTime, *dryRun, database, beforeAssetCount, beforePortCount, *screenshotDir, enableWitness)
}

// validateInput 验证输入参数
func validateInput(domain, domainList, inputFile string, subs, ports, witness bool) bool {
	if subs {
		// subs 模块需要 -d 或 -dL
		return domain != "" || domainList != ""
	}
	// ports/witness 模块需要 -i 或 stdin
	return inputFile != "" || !isTerminal()
}

// isTerminal 检查是否为终端输入
func isTerminal() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// getDomainsInput 获取域名输入
func getDomainsInput(domain, domainList string) ([]string, error) {
	if domainList != "" {
		return readLinesFromFile(domainList)
	}
	return []string{domain}, nil
}

// readLinesFromFile 从文件读取行
func readLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// readLinesFromStdin 从 stdin 读取行
func readLinesFromStdin() ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// printUsage 打印使用说明
func printUsage() {
	fmt.Println("Hunter - 资产搜集引擎")
	fmt.Println()
	fmt.Println("使用方法:")
	fmt.Println("  完整扫描:     hunter -d example.com")
	fmt.Println("  批量扫描:     hunter -dL domains.txt")
	fmt.Println()
	fmt.Println("模块选择 (-m):")
	fmt.Println("  subs          子域名收集（输入: 域名）")
	fmt.Println("  ports         端口扫描（输入: 子域名）")
	fmt.Println("  witness       Web 截图（输入: URL）")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  hunter -m subs -d example.com              # 仅子域名收集")
	fmt.Println("  hunter -m ports -i subdomains.txt          # 仅端口扫描")
	fmt.Println("  hunter -m witness -i urls.txt              # 仅截图")
	fmt.Println("  hunter -m subs,ports -d example.com        # 子域名+端口")
	fmt.Println("  cat subs.txt | hunter -m ports             # 管道输入")
	fmt.Println()
	fmt.Println("其他参数:")
	fmt.Println("  --dry-run           测试模式，不写入数据库")
	fmt.Println("  -screenshot-dir     截图存储目录（默认: screenshots）")
	fmt.Println("  -report {domain}    启动截图查看服务")
	fmt.Println("  -list-screenshots   列出所有有截图的域名")
}

// printRunInfo 打印运行信息
func printRunInfo(subs, ports, witness, dryRun bool, inputCount int) {
	var mods []string
	if subs {
		mods = append(mods, "subs")
	}
	if ports {
		mods = append(mods, "ports")
	}
	if witness {
		mods = append(mods, "witness")
	}

	fmt.Printf("🎯 输入: %d 条\n", inputCount)
	fmt.Printf("📦 模块: %s\n", strings.Join(mods, " → "))
	if dryRun {
		fmt.Println("🧪 模式: 测试（不写入数据库）")
	}
	fmt.Println()
}

// runSubsOnly 仅运行子域名收集
func runSubsOnly(domains []string) ([]engine.Result, error) {
	fmt.Println("📡 子域名收集...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	return pipeline.Execute(domains)
}

// runPortsOnly 仅运行端口扫描
func runPortsOnly(subdomains []string) ([]engine.Result, error) {
	fmt.Println("🔌 端口扫描...")

	// 先用 httpx 测活，再用 naabu+nmap 扫描
	pipeline := engine.NewPipeline()
	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())

	// 直接使用子域名作为输入（跳过子域名收集阶段）
	return pipeline.ExecuteFromSubdomains(subdomains)
}

// runWitnessOnly 仅运行截图
func runWitnessOnly(urls []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("📸 Web 截图...")

	gowitnessPlugin := plugins.NewGowitnessPlugin(screenshotDir)

	// 将 URL 转换为 "url|root_domain" 格式
	var input []string
	for _, url := range urls {
		// 从 URL 提取域名
		domain := extractDomainFromURL(url)
		rootDomain := plugins.ExtractRootDomain(domain)
		input = append(input, url+"|"+rootDomain)
	}

	return gowitnessPlugin.Execute(input)
}

// runSubsAndPorts 子域名 + 端口扫描
func runSubsAndPorts(domains []string) ([]engine.Result, error) {
	fmt.Println("📡 子域名收集 + 🔌 端口扫描...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())

	return pipeline.Execute(domains)
}

// runSubsAndWitness 子域名 + 截图
func runSubsAndWitness(domains []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("📡 子域名收集 + 📸 截图...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))

	return pipeline.Execute(domains)
}

// runPortsAndWitness 端口扫描 + 截图
func runPortsAndWitness(subdomains []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("🔌 端口扫描 + 📸 截图...")
	pipeline := engine.NewPipeline()

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))

	return pipeline.ExecuteFromSubdomains(subdomains)
}

// runFullPipeline 完整流程
func runFullPipeline(domains []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("🚀 完整扫描流程...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))

	return pipeline.Execute(domains)
}

// extractDomainFromURL 从 URL 提取域名
func extractDomainFromURL(url string) string {
	// 移除协议
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	// 移除路径
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	// 移除端口
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}
	return url
}

// saveResults 保存结果到数据库
func saveResults(database *db.Database, results []engine.Result, domains []string) {
	fmt.Println("💾 保存结果到数据库...")

	for _, result := range results {
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				data := map[string]interface{}{"domain": subdomain}
				database.SaveOrUpdateAsset(data)
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				database.SaveOrUpdateAsset(data)
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				database.SaveOrUpdatePort(data)
			}
		}
	}
}

// printSummary 打印统计摘要
func printSummary(results []engine.Result, domains []string, startTime time.Time, dryRun bool, database *db.Database, beforeAsset, beforePort int64, screenshotDir string, witnessEnabled bool) {
	// 统计结果
	subdomainCount := 0
	webServiceCount := 0
	portCount := 0
	screenshotCount := 0

	for _, result := range results {
		switch result.Type {
		case "domain":
			subdomainCount++
		case "web_service":
			webServiceCount++
		case "port_service", "open_port":
			portCount++
		case "screenshot":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if count, ok := data["screenshot_count"].(int); ok {
					screenshotCount += count
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      📊 扫描完成总结                          ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  ⏱️  耗时: %-52v ║\n", time.Since(startTime).Round(time.Second))
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	if subdomainCount > 0 {
		fmt.Printf("║  📡 子域名: %-50d ║\n", subdomainCount)
	}
	if webServiceCount > 0 {
		fmt.Printf("║  🌐 Web 服务: %-48d ║\n", webServiceCount)
	}
	if portCount > 0 {
		fmt.Printf("║  🔌 开放端口: %-48d ║\n", portCount)
	}
	if screenshotCount > 0 {
		fmt.Printf("║  📸 截图: %-52d ║\n", screenshotCount)
	}

	if !dryRun && database != nil {
		afterAsset, _ := database.GetAssetCount()
		afterPort, _ := database.GetPortCount()
		fmt.Println("╠══════════════════════════════════════════════════════════════╣")
		fmt.Printf("║  💾 资产: %d → %-47d ║\n", beforeAsset, afterAsset)
		fmt.Printf("║  💾 端口: %d → %-47d ║\n", beforePort, afterPort)
	}

	if witnessEnabled {
		screenshotDomains, _ := plugins.ListScreenshotDomains(screenshotDir)
		if len(screenshotDomains) > 0 {
			fmt.Println("╠══════════════════════════════════════════════════════════════╣")
			fmt.Printf("║  💡 查看截图: hunter -report {domain}                        ║\n")
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
