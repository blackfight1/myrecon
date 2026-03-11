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
	runMode := flag.String("mode", "scan", "Run mode: scan or monitor")
	domain := flag.String("d", "", "Single target root domain")
	domainList := flag.String("dL", "", "Root domain list file")
	inputFile := flag.String("i", "", "Input file for ports/witness modules")

	modules := flag.String("m", "", "Modules: subs,ports,witness (comma-separated)")

	dryRun := flag.Bool("dry-run", false, "Dry-run mode; do not write database")
	screenshotDir := flag.String("screenshot-dir", "screenshots", "Screenshot output directory")
	enableNuclei := flag.Bool("nuclei", false, "Enable Nuclei vulnerability scanning")
	enableActiveSubs := flag.Bool("active-subs", false, "Enable active subdomain bruteforce after passive stage")
	dictSize := flag.Int("dict-size", 1500, "Dictionary size cap for active subdomain bruteforce")
	dnsResolvers := flag.String("dns-resolvers", "", "Optional dnsx resolvers file path")
	enableNotify := flag.Bool("notify", false, "Enable DingTalk start/end notification")
	monitorInterval := flag.String("monitor-interval", "6h", "Monitor interval, e.g. 30m / 1h / 6h")
	monitorList := flag.Bool("monitor-list", false, "List current monitor targets")
	monitorStop := flag.String("monitor-stop", "", "Stop a monitor target, e.g. -monitor-stop example.com")
	monitorDelete := flag.String("monitor-delete", "", "Delete monitor data of a target")
	scanListDomains := flag.Bool("scan-list-domains", false, "List all domains in scan data")
	scanDeleteDomain := flag.String("scan-delete-domain", "", "Delete all scan data by root domain")

	reportDomain := flag.String("report", "", "Start screenshot report server for domain")
	reportHost := flag.String("report-host", "0.0.0.0", "Report server host")
	reportPort := flag.Int("report-port", 7070, "Report server port")
	listScreenshots := flag.Bool("list-screenshots", false, "List domains with screenshots")

	flag.Parse()
	if *enableNotify && strings.TrimSpace(os.Getenv("DINGTALK_WEBHOOK")) == "" {
		fmt.Println("[WARN] -notify is enabled but DINGTALK_WEBHOOK is not set; notifications will be disabled.")
	}

	mode := strings.ToLower(strings.TrimSpace(*runMode))
	if err := validateModeAndConflicts(mode, *domain, *domainList, *inputFile, *modules, *reportDomain, *listScreenshots, *monitorList, *monitorStop, *monitorDelete, *scanListDomains, *scanDeleteDomain); err != nil {
		log.Fatalf("鍙傛暟鍐茬獊: %v", err)
	}

	if mode == "monitor" && (*monitorList || strings.TrimSpace(*monitorStop) != "" || strings.TrimSpace(*monitorDelete) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("鏁版嵁搴撹繛鎺ュけ璐? %v", err)
		}

		if *monitorList {
			targets, err := database.ListMonitorTargets()
			if err != nil {
				log.Fatalf("鑾峰彇鐩戞帶鍩熷悕澶辫触: %v", err)
			}
			if len(targets) == 0 {
				fmt.Println("鏆傛棤鐩戞帶鍩熷悕")
			} else {
				fmt.Println("褰撳墠鐩戞帶鍩熷悕:")
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
				log.Fatalf("鍋滄鐩戞帶澶辫触: %v", err)
			}
			fmt.Printf("宸插仠姝㈢洃鎺? %s\n", target)
		}

		if strings.TrimSpace(*monitorDelete) != "" {
			target := strings.TrimSpace(*monitorDelete)
			if err := database.DeleteMonitorDataByRootDomain(target); err != nil {
				log.Fatalf("鍒犻櫎鐩戞帶鏁版嵁澶辫触: %v", err)
			}
			fmt.Printf("宸插垹闄ょ洃鎺ф暟鎹? %s\n", target)
		}
		return
	}

	if mode == "scan" && (*scanListDomains || strings.TrimSpace(*scanDeleteDomain) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("鏁版嵁搴撹繛鎺ュけ璐? %v", err)
		}

		if *scanListDomains {
			domains, err := database.ListAssetDomains()
			if err != nil {
				log.Fatalf("鑾峰彇鍩熷悕鍒楄〃澶辫触: %v", err)
			}
			if len(domains) == 0 {
				fmt.Println("鏆傛棤鍩熷悕鏁版嵁")
			} else {
				fmt.Println("宸叉湁鍩熷悕:")
				for _, d := range domains {
					fmt.Printf("- %s\n", d)
				}
			}
		}

		if strings.TrimSpace(*scanDeleteDomain) != "" {
			target := strings.TrimSpace(*scanDeleteDomain)
			if err := database.DeleteAllDataByRootDomain(target); err != nil {
				log.Fatalf("鍒犻櫎鍩熷悕鏁版嵁澶辫触: %v", err)
			}
			fmt.Printf("宸插垹闄ゅ煙鍚嶅叏閮ㄦ暟鎹? %s\n", target)
		}
		return
	}

	if *listScreenshots {
		domains, err := plugins.ListScreenshotDomains(*screenshotDir)
		if err != nil {
			log.Fatalf("鑾峰彇鎴浘鍩熷悕鍒楄〃澶辫触: %v", err)
		}
		if len(domains) == 0 {
			fmt.Println("鏆傛棤鎴浘鏁版嵁")
		} else {
			fmt.Println("馃摲 宸叉湁鎴浘鐨勫煙鍚?")
			for _, d := range domains {
				fmt.Printf("  - %s\n", d)
			}
			fmt.Println("\n浣跨敤 go run main.go -report <domain> 鍚姩鏌ョ湅鏈嶅姟")
		}
		return
	}

	if mode == "monitor" {
		interval, err := time.ParseDuration(*monitorInterval)
		if err != nil || interval <= 0 {
			log.Fatalf("monitor-interval 鏃犳晥: %s", *monitorInterval)
		}
		notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
		runMonitorLoop(
			strings.TrimSpace(*domain),
			interval,
			*dryRun,
			*enableActiveSubs,
			clampDictSize(*dictSize),
			strings.TrimSpace(*dnsResolvers),
			notifier,
		)
		return
	}

	if *reportDomain != "" {
		if err := plugins.StartReportServer(*screenshotDir, *reportDomain, *reportHost, *reportPort); err != nil {
			log.Fatalf("鍚姩鎴浘鏈嶅姟澶辫触: %v", err)
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
		log.Fatalf("璇诲彇杈撳叆澶辫触: %v", err)
	}
	if len(input) == 0 {
		log.Fatalf("杈撳叆涓虹┖")
	}

	printRunInfo(enableSubs, enablePorts, enableWitness, *enableNuclei, *enableActiveSubs, *dryRun, len(input))
	modulesList := buildModules(enableSubs, enablePorts, enableWitness, *enableNuclei, *enableActiveSubs)
	notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
	scanStartTime := time.Now()
	if notifier.Enabled() {
		if err := notifier.SendReconStart(len(input), modulesList, *dryRun); err != nil {
			fmt.Printf("鈿狅笍  閽夐拤閫氱煡鍙戦€佸け璐?寮€濮?: %v\n", err)
		}
	}

	failExit := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if notifier.Enabled() {
			if err := notifier.SendReconEnd(false, time.Since(scanStartTime), map[string]int{}, msg); err != nil {
				fmt.Printf("鈿狅笍  閽夐拤閫氱煡鍙戦€佸け璐?缁撴潫): %v\n", err)
			}
		}
		log.Fatalf("鉂?鎵弿澶辫触: %s", msg)
	}

	var database *db.Database
	var beforeAssetCount, beforePortCount, beforeVulnCount int64
	if !*dryRun {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err = db.NewDatabase(dsn)
		if err != nil {
			failExit("鏁版嵁搴撹繛鎺ュけ璐? %v", err)
		}
		beforeAssetCount, _ = database.GetAssetCount()
		beforePortCount, _ = database.GetPortCount()
		beforeVulnCount, _ = database.GetVulnerabilityCount()
	} else {
		fmt.Println("馃И 娴嬭瘯妯″紡锛氱粨鏋滀笉浼氬啓鍏ユ暟鎹簱")
	}

	var results []engine.Result
	clampedDictSize := clampDictSize(*dictSize)
	dnsResolversFile := strings.TrimSpace(*dnsResolvers)
	switch {
	case enableSubs && !enablePorts && !enableWitness:
		results, err = runSubsOnly(input, *enableActiveSubs, clampedDictSize, dnsResolversFile)
	case !enableSubs && enablePorts && !enableWitness:
		results, err = runPortsOnly(input, *enableNuclei)
	case !enableSubs && !enablePorts && enableWitness:
		results, err = runWitnessOnly(input, *screenshotDir)
	case enableSubs && enablePorts && !enableWitness:
		results, err = runSubsAndPorts(input, *enableNuclei, *enableActiveSubs, clampedDictSize, dnsResolversFile)
	case enableSubs && !enablePorts && enableWitness:
		results, err = runSubsAndWitness(input, *screenshotDir, *enableNuclei, *enableActiveSubs, clampedDictSize, dnsResolversFile)
	case !enableSubs && enablePorts && enableWitness:
		results, err = runPortsAndWitness(input, *screenshotDir, *enableNuclei)
	default:
		results, err = runFullPipeline(input, *screenshotDir, *enableNuclei, *enableActiveSubs, clampedDictSize, dnsResolversFile)
	}

	if err != nil {
		failExit("鎵ц澶辫触: %v", err)
	}

	if !*dryRun && database != nil {
		saveResults(database, results)
	}

	if notifier.Enabled() {
		stats := collectResultCounts(results)
		if err := notifier.SendReconEnd(true, time.Since(scanStartTime), stats, ""); err != nil {
			fmt.Printf("鈿狅笍  閽夐拤閫氱煡鍙戦€佸け璐?缁撴潫): %v\n", err)
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
			log.Fatalf("unknown module: %s (valid: subs, ports, witness)", m)
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
	fmt.Println("Hunter - Recon Backend")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Scan:              go run . -mode scan -d example.com")
	fmt.Println("  Monitor:           go run . -mode monitor -d example.com -monitor-interval 6h")
	fmt.Println("  Batch scan:        go run . -mode scan -dL domains.txt")
	fmt.Println("  List scan domains: go run . -mode scan -scan-list-domains")
	fmt.Println("  Delete scan data:  go run . -mode scan -scan-delete-domain example.com")
	fmt.Println()
	fmt.Println("Modules (-m): subs, ports, witness")
	fmt.Println("Examples:")
	fmt.Println("  go run . -m subs -d example.com")
	fmt.Println("  go run . -m ports -i subdomains.txt -nuclei")
	fmt.Println("  go run . -m witness -i urls.txt")
	fmt.Println("  go run . -m subs,ports -d example.com -active-subs -dict-size 800")
	fmt.Println()
	fmt.Println("Main flags:")
	fmt.Println("  -active-subs       Enable active subdomain bruteforce (dictgen + dnsx)")
	fmt.Println("  -dict-size         Dictionary cap for active bruteforce (default 800)")
	fmt.Println("  -dns-resolvers     Optional resolvers file for dnsx")
	fmt.Println("  -nuclei            Enable nuclei scanning")
	fmt.Println("  -notify            Enable DingTalk notifications")
}

func validateModeAndConflicts(mode, domain, domainList, inputFile, modules, reportDomain string, listScreenshots bool, monitorList bool, monitorStop, monitorDelete string, scanListDomains bool, scanDeleteDomain string) error {
	switch mode {
	case "scan", "monitor":
	default:
		return fmt.Errorf("unknown mode: %s (valid: scan, monitor)", mode)
	}

	if reportDomain != "" && listScreenshots {
		return fmt.Errorf("-report and -list-screenshots cannot be used together")
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
		return fmt.Errorf("use only one of -monitor-list/-monitor-stop/-monitor-delete")
	}
	if monitorOps > 0 {
		if mode != "monitor" {
			return fmt.Errorf("monitor management flags require -mode monitor")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("monitor management flags cannot be used with -report/-list-screenshots")
		}
		if strings.TrimSpace(domain) != "" || strings.TrimSpace(domainList) != "" || strings.TrimSpace(inputFile) != "" || strings.TrimSpace(modules) != "" {
			return fmt.Errorf("monitor management flags cannot be used with -d/-dL/-i/-m")
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
		return fmt.Errorf("use only one of -scan-list-domains/-scan-delete-domain")
	}
	if scanOps > 0 {
		if mode != "scan" {
			return fmt.Errorf("scan management flags require -mode scan")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("scan management flags cannot be used with -report/-list-screenshots")
		}
		if strings.TrimSpace(domain) != "" || strings.TrimSpace(domainList) != "" || strings.TrimSpace(inputFile) != "" || strings.TrimSpace(modules) != "" {
			return fmt.Errorf("scan management flags cannot be used with -d/-dL/-i/-m")
		}
		return nil
	}

	if mode == "monitor" {
		if domain == "" {
			return fmt.Errorf("monitor mode requires -d")
		}
		if domainList != "" {
			return fmt.Errorf("monitor mode does not support -dL")
		}
		if inputFile != "" {
			return fmt.Errorf("monitor mode does not support -i")
		}
		if strings.TrimSpace(modules) != "" {
			return fmt.Errorf("monitor mode does not support -m (fixed to subs+ports)")
		}
		if reportDomain != "" || listScreenshots {
			return fmt.Errorf("monitor mode does not support -report/-list-screenshots")
		}
	}

	return nil
}

func buildModules(subs, ports, witness, nuclei, activeSubs bool) []string {
	var mods []string
	if subs {
		mods = append(mods, "subs")
		if activeSubs {
			mods = append(mods, "subs-active")
		}
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

func printRunInfo(subs, ports, witness, nuclei, activeSubs, dryRun bool, inputCount int) {
	var mods []string
	if subs {
		mods = append(mods, "subs")
		if activeSubs {
			mods = append(mods, "subs-active")
		}
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
	fmt.Println("馃殌 寮€濮嬫墽琛?scan 妯″紡")
	fmt.Printf("馃摜 杈撳叆鏁伴噺: %d\n", inputCount)
	fmt.Printf("馃З 鎵ц妯″潡: %s\n", strings.Join(mods, " -> "))
	fmt.Printf("馃洜锔? 杩愯妯″紡: %s\n", modeText)
	if dryRun {
		fmt.Println("馃И 娴嬭瘯妯″紡锛氱粨鏋滀笉浼氬啓鍏ユ暟鎹簱")
	}
	fmt.Println("================================================")
	fmt.Println()
}

func runSubsOnly(domains []string, activeSubs bool, dictSize int, dnsResolvers string) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Subdomain Collection")
	results, _, err := collectSubdomainsWithOptionalActive(domains, activeSubs, dictSize, dnsResolvers)
	return results, err
}

func runPortsOnly(subdomains []string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("==> [闃舵] 绔彛鎵弿")
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
	fmt.Println("==> [闃舵] Web 鎴浘")
	gowitnessPlugin := plugins.NewGowitnessPlugin(screenshotDir)

	var input []string
	for _, u := range urls {
		domain := extractDomainFromURL(u)
		rootDomain := plugins.ExtractRootDomain(domain)
		input = append(input, u+"|"+rootDomain)
	}

	return gowitnessPlugin.Execute(input)
}

func runSubsAndPorts(domains []string, nucleiEnabled, activeSubs bool, dictSize int, dnsResolvers string) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Subdomain Collection + Port Scan")
	subResults, subdomains, err := collectSubdomainsWithOptionalActive(domains, activeSubs, dictSize, dnsResolvers)
	if err != nil {
		return subResults, err
	}

	pipeline := engine.NewPipeline()
	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	networkResults, err := pipeline.ExecuteFromSubdomains(subdomains)
	return append(subResults, networkResults...), err
}

func runSubsAndWitness(domains []string, screenshotDir string, nucleiEnabled, activeSubs bool, dictSize int, dnsResolvers string) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Subdomain Collection + Web Screenshot")
	subResults, subdomains, err := collectSubdomainsWithOptionalActive(domains, activeSubs, dictSize, dnsResolvers)
	if err != nil {
		return subResults, err
	}

	pipeline := engine.NewPipeline()
	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	networkResults, err := pipeline.ExecuteFromSubdomains(subdomains)
	return append(subResults, networkResults...), err
}

func runPortsAndWitness(subdomains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("==> [闃舵] 绔彛鎵弿 + Web 鎴浘")
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

func runFullPipeline(domains []string, screenshotDir string, nucleiEnabled, activeSubs bool, dictSize int, dnsResolvers string) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Full Pipeline")
	subResults, subdomains, err := collectSubdomainsWithOptionalActive(domains, activeSubs, dictSize, dnsResolvers)
	if err != nil {
		return subResults, err
	}

	pipeline := engine.NewPipeline()
	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	networkResults, err := pipeline.ExecuteFromSubdomains(subdomains)
	return append(subResults, networkResults...), err
}

func collectSubdomainsWithOptionalActive(rootDomains []string, activeSubs bool, dictSize int, dnsResolvers string) ([]engine.Result, []string, error) {
	passiveResults, passiveSubdomains, err := runPassiveSubdomainCollection(rootDomains)
	if err != nil {
		return passiveResults, nil, err
	}

	allResults := append([]engine.Result{}, passiveResults...)
	finalSubdomains := append([]string{}, passiveSubdomains...)

	if !activeSubs {
		return allResults, finalSubdomains, nil
	}

	activeResults, activeSubdomains, err := runActiveSubdomainExpansion(rootDomains, passiveSubdomains, dictSize, dnsResolvers)
	allResults = append(allResults, activeResults...)
	if err != nil {
		return allResults, nil, err
	}

	finalSubdomains = mergeUniqueDomains(passiveSubdomains, activeSubdomains)
	added := len(finalSubdomains) - len(passiveSubdomains)
	if added < 0 {
		added = 0
	}
	fmt.Printf("[ActiveSubs] Added %d active subdomains (total=%d)\n", added, len(finalSubdomains))
	return allResults, finalSubdomains, nil
}

func runPassiveSubdomainCollection(domains []string) ([]engine.Result, []string, error) {
	pipeline := engine.NewPipeline()
	isBatchMode := len(domains) > 1

	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewFindomainPlugin())
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	results, err := pipeline.Execute(domains)
	subdomains := extractDomainResults(results)
	return results, subdomains, err
}

func runActiveSubdomainExpansion(rootDomains, passiveSubdomains []string, dictSize int, dnsResolvers string) ([]engine.Result, []string, error) {
	var allResults []engine.Result

	dictPlugin := plugins.NewDictgenPlugin(clampDictSize(dictSize))
	dictInput := append([]string{}, passiveSubdomains...)
	dictInput = append(dictInput, rootDomains...)

	dictResults, dictErr := executeScannerWithStatus(dictPlugin, dictInput)
	allResults = append(allResults, dictResults...)
	if dictErr != nil {
		return allResults, nil, dictErr
	}

	var words []string
	for _, r := range dictResults {
		if r.Type != "dict_word" {
			continue
		}
		if w, ok := r.Data.(string); ok && strings.TrimSpace(w) != "" {
			words = append(words, w)
		}
	}
	if len(words) == 0 {
		return allResults, []string{}, nil
	}

	brutePlugin := plugins.NewDNSXBruteforcePlugin(rootDomains, dnsResolvers)
	bruteResults, bruteErr := executeScannerWithStatus(brutePlugin, words)
	allResults = append(allResults, bruteResults...)

	if bruteErr != nil {
		if strings.Contains(bruteErr.Error(), "not found in PATH") {
			fmt.Printf("[DNSXBruteforce] Tool missing, skip active brute-force: %v\n", bruteErr)
			return allResults, []string{}, nil
		}
		return allResults, nil, bruteErr
	}

	return allResults, extractDomainResults(bruteResults), nil
}

func executeScannerWithStatus(scanner engine.Scanner, input []string) ([]engine.Result, error) {
	start := time.Now()
	results, err := scanner.Execute(input)
	status := buildLocalPluginStatusResult(scanner.Name(), len(results), err, time.Since(start))
	out := make([]engine.Result, 0, len(results)+1)
	out = append(out, status)
	out = append(out, results...)
	return out, err
}

func buildLocalPluginStatusResult(scannerName string, successCount int, err error, duration time.Duration) engine.Result {
	failureCount := 0
	timeoutCount := 0
	errMsg := ""
	status := "ok"

	if err != nil {
		failureCount = 1
		errMsg = err.Error()
		status = "error"
		if isTimeoutErrorLocal(err) {
			timeoutCount = 1
		}
	}

	return engine.Result{
		Type: "plugin_status",
		Data: map[string]interface{}{
			"scanner":       scannerName,
			"status":        status,
			"success_count": successCount,
			"failure_count": failureCount,
			"timeout_count": timeoutCount,
			"duration_ms":   duration.Milliseconds(),
			"error":         errMsg,
		},
	}
}

func isTimeoutErrorLocal(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded")
}

func extractDomainResults(results []engine.Result) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 512)

	for _, result := range results {
		if result.Type != "domain" {
			continue
		}
		subdomain, ok := result.Data.(string)
		if !ok {
			continue
		}
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		subdomain = strings.TrimSuffix(subdomain, ".")
		if subdomain == "" || seen[subdomain] {
			continue
		}
		seen[subdomain] = true
		out = append(out, subdomain)
	}
	return out
}

func mergeUniqueDomains(base []string, extra []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(base)+len(extra))

	appendDomain := func(items []string) {
		for _, item := range items {
			d := strings.ToLower(strings.TrimSpace(item))
			d = strings.TrimSuffix(d, ".")
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}

	appendDomain(base)
	appendDomain(extra)
	return out
}

func clampDictSize(v int) int {
	if v <= 0 {
		return 1500
	}
	if v < 100 {
		return 100
	}
	if v > 5000 {
		return 5000
	}
	return v
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
	fmt.Println("==> [鍏ュ簱] 鍐欏叆缁撴灉鍒版暟鎹簱")

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
	fmt.Println("==> [鍏ュ簱] 鍐欏叆瀹屾垚")
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
	fmt.Println("鉁?鎵弿瀹屾垚")
	fmt.Printf("鈴憋笍  鎬昏€楁椂: %v\n", time.Since(startTime).Round(time.Second))
	fmt.Printf("馃摋 瀛愬煙鍚? %d\n", counts["subdomains"])
	fmt.Printf("馃寪 Web 鏈嶅姟: %d\n", counts["web_services"])
	fmt.Printf("馃摬 寮€鏀剧鍙? %d\n", counts["ports"])
	fmt.Printf("馃洝锔? 婕忔礊鍊欓€? %d\n", counts["vulnerabilities"])
	fmt.Printf("馃摲 鎴浘: %d\n", counts["screenshots"])

	if !dryRun && database != nil {
		afterAsset, _ := database.GetAssetCount()
		afterPort, _ := database.GetPortCount()
		afterVuln, _ := database.GetVulnerabilityCount()
		fmt.Println("馃捑 鏁版嵁搴撳彉鍖?")
		fmt.Printf("- assets: %d -> %d\n", beforeAsset, afterAsset)
		fmt.Printf("- ports: %d -> %d\n", beforePort, afterPort)
		fmt.Printf("- vulnerabilities: %d -> %d\n", beforeVuln, afterVuln)
	}

	if witnessEnabled {
		screenshotDomains, _ := plugins.ListScreenshotDomains(screenshotDir)
		if len(screenshotDomains) > 0 {
			fmt.Println("馃攷 鏌ョ湅鎴浘: go run main.go -report <domain>")
		}
	}
	if len(pluginStatuses) > 0 {
		fmt.Println()
		fmt.Println("馃З 鎻掍欢杩愯鐘舵€?")
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
