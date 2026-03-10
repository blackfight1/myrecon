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
	runMode := flag.String("mode", "scan", "运行模式: scan 或 monitor")
	domain := flag.String("d", "", "单个目标域名")
	domainList := flag.String("dL", "", "域名列表文件")
	inputFile := flag.String("i", "", "输入文件（ports/witness 模块独立运行）")

	modules := flag.String("m", "", "选择模块: subs,ports,witness（逗号分隔，默认全部）")

	dryRun := flag.Bool("dry-run", false, "测试模式，不写入数据库")
	screenshotDir := flag.String("screenshot-dir", "screenshots", "截图存储目录")
	enableNuclei := flag.Bool("nuclei", false, "启用 Nuclei 漏洞扫描（CVE 优先）")
	enableNotify := flag.Bool("notify", false, "启用钉钉开始/结束通知（读取 DINGTALK_WEBHOOK）")
	monitorInterval := flag.String("monitor-interval", "6h", "监控间隔，例如 30m / 1h / 6h")
	monitorList := flag.Bool("monitor-list", false, "列出当前监控域名")
	monitorStop := flag.String("monitor-stop", "", "停止某个域名监控（例如 -monitor-stop example.com）")
	monitorDelete := flag.String("monitor-delete", "", "删除某个域名监控数据（例如 -monitor-delete example.com）")
	scanListDomains := flag.Bool("scan-list-domains", false, "列出 scan 数据中的所有域名")
	scanDeleteDomain := flag.String("scan-delete-domain", "", "删除某个域名的所有数据（例如 -scan-delete-domain example.com）")

	reportDomain := flag.String("report", "", "启动截图查看服务")
	reportHost := flag.String("report-host", "0.0.0.0", "截图服务监听地址")
	reportPort := flag.Int("report-port", 7070, "截图服务监听端口")
	listScreenshots := flag.Bool("list-screenshots", false, "列出所有有截图的域名")

	flag.Parse()
	mode := strings.ToLower(strings.TrimSpace(*runMode))
	if err := validateModeAndConflicts(mode, *domain, *domainList, *inputFile, *modules, *reportDomain, *listScreenshots, *monitorList, *monitorStop, *monitorDelete, *scanListDomains, *scanDeleteDomain); err != nil {
		log.Fatalf("参数冲突: %v", err)
	}

	if mode == "monitor" && (*monitorList || strings.TrimSpace(*monitorStop) != "" || strings.TrimSpace(*monitorDelete) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("数据库连接失败: %v", err)
		}

		if *monitorList {
			targets, err := database.ListMonitorTargets()
			if err != nil {
				log.Fatalf("获取监控域名失败: %v", err)
			}
			if len(targets) == 0 {
				fmt.Println("暂无监控域名")
			} else {
				fmt.Println("当前监控域名:")
				for _, t := range targets {
					status := "stopped"
					if t.Enabled {
						status = "running"
					}
					baseline := "no"
					if t.BaselineDone {
						baseline = "yes"
					}
					lastRun := "-"
					if t.LastRunAt != nil {
						lastRun = t.LastRunAt.Format("2006-01-02 15:04:05")
					}
					fmt.Printf("- %s | status=%s | baseline_done=%s | last_run=%s\n", t.RootDomain, status, baseline, lastRun)
				}
			}
		}

		if strings.TrimSpace(*monitorStop) != "" {
			target := strings.TrimSpace(*monitorStop)
			if err := database.StopMonitorTarget(target); err != nil {
				log.Fatalf("停止监控失败: %v", err)
			}
			fmt.Printf("已停止监控: %s\n", target)
		}

		if strings.TrimSpace(*monitorDelete) != "" {
			target := strings.TrimSpace(*monitorDelete)
			if err := database.DeleteMonitorDataByRootDomain(target); err != nil {
				log.Fatalf("删除监控数据失败: %v", err)
			}
			fmt.Printf("已删除监控数据: %s\n", target)
		}
		return
	}

	if mode == "scan" && (*scanListDomains || strings.TrimSpace(*scanDeleteDomain) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("数据库连接失败: %v", err)
		}

		if *scanListDomains {
			domains, err := database.ListAssetDomains()
			if err != nil {
				log.Fatalf("获取域名列表失败: %v", err)
			}
			if len(domains) == 0 {
				fmt.Println("暂无域名数据")
			} else {
				fmt.Println("已有域名:")
				for _, d := range domains {
					fmt.Printf("- %s\n", d)
				}
			}
		}

		if strings.TrimSpace(*scanDeleteDomain) != "" {
			target := strings.TrimSpace(*scanDeleteDomain)
			if err := database.DeleteAllDataByRootDomain(target); err != nil {
				log.Fatalf("删除域名数据失败: %v", err)
			}
			fmt.Printf("已删除域名全部数据: %s\n", target)
		}
		return
	}

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

	if mode == "monitor" {
		interval, err := time.ParseDuration(*monitorInterval)
		if err != nil || interval <= 0 {
			log.Fatalf("monitor-interval 无效: %s", *monitorInterval)
		}
		notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
		runMonitorLoop(strings.TrimSpace(*domain), interval, *dryRun, notifier)
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
	modulesList := buildModules(enableSubs, enablePorts, enableWitness, *enableNuclei)
	notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
	scanStartTime := time.Now()
	if notifier.Enabled() {
		if err := notifier.SendReconStart(len(input), modulesList, *dryRun); err != nil {
			fmt.Printf("⚠️  钉钉通知发送失败(开始): %v\n", err)
		}
	}

	failExit := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if notifier.Enabled() {
			if err := notifier.SendReconEnd(false, time.Since(scanStartTime), map[string]int{}, msg); err != nil {
				fmt.Printf("⚠️  钉钉通知发送失败(结束): %v\n", err)
			}
		}
		log.Fatalf("❌ 扫描失败: %s", msg)
	}

	var database *db.Database
	var beforeAssetCount, beforePortCount, beforeVulnCount int64
	if !*dryRun {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err = db.NewDatabase(dsn)
		if err != nil {
			failExit("数据库连接失败: %v", err)
		}
		beforeAssetCount, _ = database.GetAssetCount()
		beforePortCount, _ = database.GetPortCount()
		beforeVulnCount, _ = database.GetVulnerabilityCount()
	} else {
		fmt.Println("🧪 测试模式：结果不会写入数据库")
	}

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
		failExit("执行失败: %v", err)
	}

	if !*dryRun && database != nil {
		saveResults(database, results)
	}

	if notifier.Enabled() {
		stats := collectResultCounts(results)
		if err := notifier.SendReconEnd(true, time.Since(scanStartTime), stats, ""); err != nil {
			fmt.Printf("⚠️  钉钉通知发送失败(结束): %v\n", err)
		}
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
	fmt.Println("  普通扫描:     go run . -mode scan -d example.com")
	fmt.Println("  监控模式:     go run . -mode monitor -d example.com -monitor-interval 6h")
	fmt.Println("  scan管理:     go run . -mode scan -scan-list-domains")
	fmt.Println("  scan删除:     go run . -mode scan -scan-delete-domain example.com")
	fmt.Println("  列出监控:     go run . -mode monitor -monitor-list")
	fmt.Println("  停止监控:     go run . -mode monitor -monitor-stop example.com")
	fmt.Println("  删除监控:     go run . -mode monitor -monitor-delete example.com")
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
	fmt.Println("  -mode              运行模式: scan 或 monitor（默认 scan）")
	fmt.Println("  --dry-run           测试模式，不写入数据库")
	fmt.Println("  -nuclei             启用 Nuclei 漏洞扫描（CVE 优先）")
	fmt.Println("  -notify             启用钉钉开始/结束通知（环境变量 DINGTALK_WEBHOOK）")
	fmt.Println("  -monitor-interval   监控间隔（默认 6h）")
	fmt.Println("  -monitor-list       列出当前监控域名")
	fmt.Println("  -monitor-stop       停止某个域名监控")
	fmt.Println("  -monitor-delete     删除某个域名监控数据")
	fmt.Println("  -scan-list-domains  列出 scan 数据中的所有域名")
	fmt.Println("  -scan-delete-domain 删除某个域名的所有数据")
	fmt.Println("  -screenshot-dir     截图存储目录（默认 screenshots）")
	fmt.Println("  -report <domain>    启动截图查看服务")
	fmt.Println("  -list-screenshots   列出所有有截图的域名")
}

func validateModeAndConflicts(mode, domain, domainList, inputFile, modules, reportDomain string, listScreenshots bool, monitorList bool, monitorStop, monitorDelete string, scanListDomains bool, scanDeleteDomain string) error {
	switch mode {
	case "scan", "monitor":
	default:
		return fmt.Errorf("未知 mode: %s（可用: scan, monitor）", mode)
	}

	if reportDomain != "" && listScreenshots {
		return fmt.Errorf("-report 与 -list-screenshots 不能同时使用")
	}

	monitorOps := 0
	if monitorList {
		monitorOps++
	}
	if strings.TrimSpace(monitorStop) != "" {
		monitorOps++
	}
	if strings.TrimSpace(monitorDelete) != "" {
		monitorOps++
	}
	if monitorOps > 1 {
		return fmt.Errorf("-monitor-list/-monitor-stop/-monitor-delete 只能使用一个")
	}
	if monitorOps > 0 {
		if mode != "monitor" {
			return fmt.Errorf("监控管理参数需要在 -mode monitor 下使用")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("监控管理参数不支持与 -report/-list-screenshots 同时使用")
		}
		if strings.TrimSpace(domain) != "" || strings.TrimSpace(domainList) != "" || strings.TrimSpace(inputFile) != "" || strings.TrimSpace(modules) != "" {
			return fmt.Errorf("监控管理参数不支持与 -d/-dL/-i/-m 同时使用")
		}
		return nil
	}

	scanOps := 0
	if scanListDomains {
		scanOps++
	}
	if strings.TrimSpace(scanDeleteDomain) != "" {
		scanOps++
	}
	if scanOps > 1 {
		return fmt.Errorf("-scan-list-domains/-scan-delete-domain 只能使用一个")
	}
	if scanOps > 0 {
		if mode != "scan" {
			return fmt.Errorf("scan 管理参数需要在 -mode scan 下使用")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("scan 管理参数不支持与 -report/-list-screenshots 同时使用")
		}
		if strings.TrimSpace(domain) != "" || strings.TrimSpace(domainList) != "" || strings.TrimSpace(inputFile) != "" || strings.TrimSpace(modules) != "" {
			return fmt.Errorf("scan 管理参数不支持与 -d/-dL/-i/-m 同时使用")
		}
		return nil
	}

	if mode == "monitor" {
		if domain == "" {
			return fmt.Errorf("monitor 模式必须使用 -d 指定单个域名")
		}
		if domainList != "" {
			return fmt.Errorf("monitor 模式不支持 -dL")
		}
		if inputFile != "" {
			return fmt.Errorf("monitor 模式不支持 -i")
		}
		if strings.TrimSpace(modules) != "" {
			return fmt.Errorf("monitor 模式不支持 -m（固定执行 subs+ports）")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("monitor 模式不支持 -report/-list-screenshots")
		}
	}

	return nil
}

func buildModules(subs, ports, witness, nuclei bool) []string {
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
	return mods
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

	modeText := "normal"
	if dryRun {
		modeText = "dry-run"
	}

	fmt.Println("================================================")
	fmt.Println("🚀 开始执行 scan 模式")
	fmt.Printf("📥 输入数量: %d\n", inputCount)
	fmt.Printf("🧩 执行模块: %s\n", strings.Join(mods, " -> "))
	fmt.Printf("🛠️  运行模式: %s\n", modeText)
	if dryRun {
		fmt.Println("🧪 测试模式：结果不会写入数据库")
	}
	fmt.Println("================================================")
	fmt.Println()
}

func runSubsOnly(domains []string) ([]engine.Result, error) {
	fmt.Println("==> [阶段] 子域名收集")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewAmassPlugin(true))
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	return pipeline.Execute(domains)
}

func runPortsOnly(subdomains []string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("==> [阶段] 端口扫描")
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
	fmt.Println("==> [阶段] Web 截图")
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
	fmt.Println("==> [阶段] 子域名收集 + 端口扫描")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewAmassPlugin(true))
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
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
	fmt.Println("==> [阶段] 子域名收集 + Web 截图")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewAmassPlugin(true))
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.Execute(domains)
}

func runPortsAndWitness(subdomains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("==> [阶段] 端口扫描 + Web 截图")
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
	fmt.Println("==> [阶段] 完整扫描流程")
	pipeline := engine.NewPipeline()

	isBatchMode := len(domains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewAmassPlugin(true))
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
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
	fmt.Println("==> [入库] 写入结果到数据库")

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
	fmt.Println("==> [入库] 写入完成")
}

func printSummary(results []engine.Result, startTime time.Time, dryRun bool, database *db.Database, beforeAsset, beforePort, beforeVuln int64, screenshotDir string, witnessEnabled bool) {
	counts := collectResultCounts(results)
	type pluginStatus struct {
		Scanner      string
		SuccessCount int
		FailureCount int
		TimeoutCount int
		DurationMS   int64
		Status       string
		Error        string
	}
	var pluginStatuses []pluginStatus

	for _, result := range results {
		switch result.Type {
		case "plugin_status":
			data, ok := result.Data.(map[string]interface{})
			if !ok {
				continue
			}
			ps := pluginStatus{
				Scanner:      getStringFromMap(data, "scanner"),
				SuccessCount: getIntFromMap(data, "success_count"),
				FailureCount: getIntFromMap(data, "failure_count"),
				TimeoutCount: getIntFromMap(data, "timeout_count"),
				DurationMS:   int64(getIntFromMap(data, "duration_ms")),
				Status:       getStringFromMap(data, "status"),
				Error:        getStringFromMap(data, "error"),
			}
			pluginStatuses = append(pluginStatuses, ps)
		}
	}

	fmt.Println()
	fmt.Println("================================================")
	fmt.Println("✅ 扫描完成")
	fmt.Printf("⏱️  总耗时: %v\n", time.Since(startTime).Round(time.Second))
	fmt.Printf("📗 子域名: %d\n", counts["subdomains"])
	fmt.Printf("🌐 Web 服务: %d\n", counts["web_services"])
	fmt.Printf("📲 开放端口: %d\n", counts["ports"])
	fmt.Printf("🛡️  漏洞候选: %d\n", counts["vulnerabilities"])
	fmt.Printf("📷 截图: %d\n", counts["screenshots"])

	if !dryRun && database != nil {
		afterAsset, _ := database.GetAssetCount()
		afterPort, _ := database.GetPortCount()
		afterVuln, _ := database.GetVulnerabilityCount()
		fmt.Println("💾 数据库变化:")
		fmt.Printf("- assets: %d -> %d\n", beforeAsset, afterAsset)
		fmt.Printf("- ports: %d -> %d\n", beforePort, afterPort)
		fmt.Printf("- vulnerabilities: %d -> %d\n", beforeVuln, afterVuln)
	}

	if witnessEnabled {
		screenshotDomains, _ := plugins.ListScreenshotDomains(screenshotDir)
		if len(screenshotDomains) > 0 {
			fmt.Println("🔎 查看截图: go run main.go -report <domain>")
		}
	}
	if len(pluginStatuses) > 0 {
		fmt.Println()
		fmt.Println("🧩 插件运行状态:")
		for _, ps := range pluginStatuses {
			line := fmt.Sprintf("- %s | status=%s | success=%d fail=%d timeout=%d | duration=%dms",
				ps.Scanner, ps.Status, ps.SuccessCount, ps.FailureCount, ps.TimeoutCount, ps.DurationMS)
			fmt.Println(line)
			if ps.Error != "" {
				fmt.Printf("  error: %s\n", ps.Error)
			}
		}
	}
	fmt.Println("================================================")
}

func collectResultCounts(results []engine.Result) map[string]int {
	counts := map[string]int{
		"subdomains":      0,
		"web_services":    0,
		"ports":           0,
		"vulnerabilities": 0,
		"screenshots":     0,
	}

	for _, result := range results {
		switch result.Type {
		case "domain":
			counts["subdomains"]++
		case "web_service":
			counts["web_services"]++
		case "port_service", "open_port":
			counts["ports"]++
		case "vulnerability":
			counts["vulnerabilities"]++
		case "screenshot":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if count, ok := data["screenshot_count"].(int); ok {
					counts["screenshots"] += count
				}
			}
		}
	}

	return counts
}

func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getIntFromMap(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch vv := v.(type) {
		case int:
			return vv
		case int64:
			return int(vv)
		case float64:
			return int(vv)
		}
	}
	return 0
}
