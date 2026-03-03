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
	domain := flag.String("d", "", "单个目标域名")
	domainList := flag.String("dL", "", "域名列表文件")
	inputFile := flag.String("i", "", "输入文件（ports/witness 模块独立运行）")

	modules := flag.String("m", "", "选择模块: subs,ports,witness（逗号分隔，默认全部）")

	dryRun := flag.Bool("dry-run", false, "测试模式，不写入数据库")
	screenshotDir := flag.String("screenshot-dir", "screenshots", "截图存储目录")
	enableNuclei := flag.Bool("nuclei", false, "启用 Nuclei 漏洞扫描（CVE 优先）")

	reportDomain := flag.String("report", "", "启动截图查看服务")
	reportHost := flag.String("report-host", "0.0.0.0", "截图服务监听地址")
	reportPort := flag.Int("report-port", 7070, "截图服务监听端口")
	listScreenshots := flag.Bool("list-screenshots", false, "列出所有有截图的域名")

	flag.Parse()

	if *listScreenshots {
		domains, err := plugins.ListScreenshotDomains(*screenshotDir)
		if err != nil {
			log.Fatalf("获取截图域名列表失败: %v", err)
		}
		if len(domains) == 0 {
			fmt.Println("暂无截图数据")
		} else {
			fmt.Println("📷 已有截图的域名:")
			for _, d := range domains {
				fmt.Printf("  - %s\n", d)
			}
			fmt.Println("\n使用 go run main.go -report <domain> 启动查看服务")
		}
		return
	}

	if *reportDomain != "" {
		if err := plugins.StartReportServer(*screenshotDir, *reportDomain, *reportHost, *reportPort); err != nil {
			log.Fatalf("启动截图服务失败: %v", err)
		}
		return
	}

	enableSubs, enablePorts, enableWitness := parseModules(*modules)

	if !validateInput(*domain, *domainList, *inputFile, enableSubs, enablePorts, enableWitness) {
		printUsage()
		os.Exit(1)
	}

	var input []string
	var err error
	if enableSubs {
		input, err = getDomainsInput(*domain, *domainList)
	} else if *inputFile != "" {
		input, err = readLinesFromFile(*inputFile)
	} else {
		input, err = readLinesFromStdin()
	}
	if err != nil {
		log.Fatalf("读取输入失败: %v", err)
	}
	if len(input) == 0 {
		log.Fatalf("输入为空")
	}

	printRunInfo(enableSubs, enablePorts, enableWitness, *enableNuclei, *dryRun, len(input))

	var database *db.Database
	var beforeAssetCount, beforePortCount, beforeVulnCount int64
	if !*dryRun {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err = db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("数据库连接失败: %v", err)
		}
		beforeAssetCount, _ = database.GetAssetCount()
		beforePortCount, _ = database.GetPortCount()
		beforeVulnCount, _ = database.GetVulnerabilityCount()
	} else {
		fmt.Println("🧪 测试模式：结果不会写入数据库")
	}

	scanStartTime := time.Now()

	var results []engine.Result
	switch {
	case enableSubs && !enablePorts && !enableWitness:
		results, err = runSubsOnly(input)
	case !enableSubs && enablePorts && !enableWitness:
		results, err = runPortsOnly(input, *enableNuclei)
	case !enableSubs && !enablePorts && enableWitness:
		results, err = runWitnessOnly(input, *screenshotDir)
	case enableSubs && enablePorts && !enableWitness:
		results, err = runSubsAndPorts(input, *enableNuclei)
	case enableSubs && !enablePorts && enableWitness:
		results, err = runSubsAndWitness(input, *screenshotDir, *enableNuclei)
	case !enableSubs && enablePorts && enableWitness:
		results, err = runPortsAndWitness(input, *screenshotDir, *enableNuclei)
	default:
		results, err = runFullPipeline(input, *screenshotDir, *enableNuclei)
	}

	if err != nil {
		log.Fatalf("执行失败: %v", err)
	}

	if !*dryRun && database != nil {
		saveResults(database, results)
	}

	printSummary(results, scanStartTime, *dryRun, database, beforeAssetCount, beforePortCount, beforeVulnCount, *screenshotDir, enableWitness)
}

func parseModules(modules string) (bool, bool, bool) {
	enableSubs := false
	enablePorts := false
	enableWitness := false

	if modules == "" {
		return true, true, true
	}

	modList := strings.Split(strings.ToLower(modules), ",")
	for _, m := range modList {
		switch strings.TrimSpace(m) {
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

	return enableSubs, enablePorts, enableWitness
}

func validateInput(domain, domainList, inputFile string, subs, ports, witness bool) bool {
	if subs {
		return domain != "" || domainList != ""
	}
	return inputFile != "" || !isTerminal()
}

func isTerminal() bool {
	fi, _ := os.Stdin.Stat()
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func getDomainsInput(domain, domainList string) ([]string, error) {
	if domainList != "" {
		return readLinesFromFile(domainList)
	}
	return []string{domain}, nil
}

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

func printUsage() {
	fmt.Println("Hunter - 资产搜集引擎")
	fmt.Println()
	fmt.Println("使用方法:")
	fmt.Println("  完整扫描:     go run main.go -d example.com")
	fmt.Println("  批量扫描:     go run main.go -dL domains.txt")
	fmt.Println()
	fmt.Println("模块选择 (-m):")
	fmt.Println("  subs          子域名收集（输入: 域名）")
	fmt.Println("  ports         端口扫描（输入: 子域名）")
	fmt.Println("  witness       Web 截图（输入: URL）")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  go run main.go -m subs -d example.com")
	fmt.Println("  go run main.go -m ports -i subdomains.txt")
	fmt.Println("  go run main.go -m witness -i urls.txt")
	fmt.Println("  go run main.go -m subs,ports -d example.com")
	fmt.Println()
	fmt.Println("其他参数:")
	fmt.Println("  --dry-run           测试模式，不写入数据库")
	fmt.Println("  -nuclei             启用 Nuclei 漏洞扫描（CVE 优先）")
	fmt.Println("  -screenshot-dir     截图存储目录（默认 screenshots）")
	fmt.Println("  -report <domain>    启动截图查看服务")
	fmt.Println("  -list-screenshots   列出所有有截图的域名")
}

func printRunInfo(subs, ports, witness, nuclei, dryRun bool, inputCount int) {
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
	if nuclei {
		mods = append(mods, "nuclei")
	}

	fmt.Printf("🎯 输入: %d 条\n", inputCount)
	fmt.Printf("📋 模块: %s\n", strings.Join(mods, " -> "))
	if dryRun {
		fmt.Println("🧪 模式: 测试（不写入数据库）")
	}
	fmt.Println()
}

func runSubsOnly(domains []string) ([]engine.Result, error) {
	fmt.Println("📗 子域名收集...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	return pipeline.Execute(domains)
}

func runPortsOnly(subdomains []string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("📲 端口扫描...")
	pipeline := engine.NewPipeline()

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.ExecuteFromSubdomains(subdomains)
}

func runWitnessOnly(urls []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("📷 Web 截图...")
	gowitnessPlugin := plugins.NewGowitnessPlugin(screenshotDir)

	var input []string
	for _, u := range urls {
		domain := extractDomainFromURL(u)
		rootDomain := plugins.ExtractRootDomain(domain)
		input = append(input, u+"|"+rootDomain)
	}

	return gowitnessPlugin.Execute(input)
}

func runSubsAndPorts(domains []string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("📗 子域名收集 + 📲 端口扫描...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.Execute(domains)
}

func runSubsAndWitness(domains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("📗 子域名收集 + 📷 截图...")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSamoscoutPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewSubdogPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.Execute(domains)
}

func runPortsAndWitness(subdomains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("📲 端口扫描 + 📷 截图...")
	pipeline := engine.NewPipeline()

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.ExecuteFromSubdomains(subdomains)
}

func runFullPipeline(domains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("🔍 完整扫描流程...")
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
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.Execute(domains)
}

func extractDomainFromURL(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "http://")
	rawURL = strings.TrimPrefix(rawURL, "https://")
	if idx := strings.Index(rawURL, "/"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	if idx := strings.Index(rawURL, ":"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func saveResults(database *db.Database, results []engine.Result) {
	fmt.Println("💾 保存结果到数据库...")

	for _, result := range results {
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				_ = database.SaveOrUpdateAsset(map[string]interface{}{"domain": subdomain})
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				_ = database.SaveOrUpdateAsset(data)
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				_ = database.SaveOrUpdatePort(data)
			}
		case "vulnerability":
			if data, ok := result.Data.(map[string]interface{}); ok {
				_ = database.SaveOrUpdateVulnerability(data)
			}
		}
	}
}

func printSummary(results []engine.Result, startTime time.Time, dryRun bool, database *db.Database, beforeAsset, beforePort, beforeVuln int64, screenshotDir string, witnessEnabled bool) {
	subdomainCount := 0
	webServiceCount := 0
	portCount := 0
	screenshotCount := 0
	vulnCount := 0

	for _, result := range results {
		switch result.Type {
		case "domain":
			subdomainCount++
		case "web_service":
			webServiceCount++
		case "port_service", "open_port":
			portCount++
		case "vulnerability":
			vulnCount++
		case "screenshot":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if count, ok := data["screenshot_count"].(int); ok {
					screenshotCount += count
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("================= 📊 扫描完成 =================")
	fmt.Printf("⏱️  耗时: %v\n", time.Since(startTime).Round(time.Second))
	if subdomainCount > 0 {
		fmt.Printf("📗 子域名: %d\n", subdomainCount)
	}
	if webServiceCount > 0 {
		fmt.Printf("🌐 Web 服务: %d\n", webServiceCount)
	}
	if portCount > 0 {
		fmt.Printf("📲 开放端口: %d\n", portCount)
	}
	if vulnCount > 0 {
		fmt.Printf("🛡️  漏洞候选: %d\n", vulnCount)
	}
	if screenshotCount > 0 {
		fmt.Printf("📷 截图: %d\n", screenshotCount)
	}

	if !dryRun && database != nil {
		afterAsset, _ := database.GetAssetCount()
		afterPort, _ := database.GetPortCount()
		afterVuln, _ := database.GetVulnerabilityCount()
		fmt.Printf("💾 资产: %d -> %d\n", beforeAsset, afterAsset)
		fmt.Printf("💾 端口: %d -> %d\n", beforePort, afterPort)
		fmt.Printf("💾 漏洞: %d -> %d\n", beforeVuln, afterVuln)
	}

	if witnessEnabled {
		screenshotDomains, _ := plugins.ListScreenshotDomains(screenshotDir)
		if len(screenshotDomains) > 0 {
			fmt.Println("🔎 查看截图: go run main.go -report <domain>")
		}
	}
	fmt.Println("================================================")
}
