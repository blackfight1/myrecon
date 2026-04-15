package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"hunter/internal/api"
	commonpkg "hunter/internal/common"
	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

func main() {
	runMode := flag.String("mode", "scan", "Run mode: scan, monitor, web, or worker")
	webAddr := flag.String("web-addr", "0.0.0.0:8080", "API server listen address (web mode)")
	projectID := flag.String("project", "default", "Project ID for CLI scan/monitor operations")
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

	// ── Web API Server Mode ──
	if mode == "web" {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("database connection failed: %v", err)
		}
		srv := api.NewServer(database, *screenshotDir)
		log.Fatal(srv.Start(*webAddr))
		return
	}

	// ── Worker Mode ──
	if mode == "worker" {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabaseNoMigrate(dsn)
		if err != nil {
			log.Fatalf("database connection failed: %v", err)
		}
		srv := api.NewServer(database, *screenshotDir)
		log.Fatal(srv.RunWorkers())
		return
	}

	if err := validateModeAndConflicts(mode, *domain, *domainList, *inputFile, *modules, *reportDomain, *listScreenshots, *monitorList, *monitorStop, *monitorDelete, *scanListDomains, *scanDeleteDomain); err != nil {
		log.Fatalf("argument conflict: %v", err)
	}

	if mode == "monitor" && (*monitorList || strings.TrimSpace(*monitorStop) != "" || strings.TrimSpace(*monitorDelete) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("database connection failed: %v", err)
		}
		pid := strings.TrimSpace(*projectID)
		if pid == "" {
			pid = "default"
		}

		if *monitorList {
			targets, err := database.ListMonitorTargets(pid)
			if err != nil {
				log.Fatalf("failed to list monitor targets: %v", err)
			}
			if len(targets) == 0 {
				fmt.Println("No monitor targets.")
			} else {
				fmt.Println("Monitor targets:")
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
			if err := database.StopMonitorTarget(pid, target); err != nil {
				log.Fatalf("failed to stop monitor target: %v", err)
			}
			fmt.Printf("Stopped monitor target: %s\n", target)
		}

		if strings.TrimSpace(*monitorDelete) != "" {
			target := strings.TrimSpace(*monitorDelete)
			if err := database.DeleteMonitorDataByRootDomain(pid, target); err != nil {
				log.Fatalf("failed to delete monitor data: %v", err)
			}
			fmt.Printf("Deleted monitor data: %s\n", target)
		}
		return
	}

	if mode == "scan" && (*scanListDomains || strings.TrimSpace(*scanDeleteDomain) != "") {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("database connection failed: %v", err)
		}
		pid := strings.TrimSpace(*projectID)
		if pid == "" {
			pid = "default"
		}

		if *scanListDomains {
			domains, err := database.ListAssetDomains(pid)
			if err != nil {
				log.Fatalf("failed to list asset domains: %v", err)
			}
			if len(domains) == 0 {
				fmt.Println("No domain data.")
			} else {
				fmt.Println("Domains:")
				for _, d := range domains {
					fmt.Printf("- %s\n", d)
				}
			}
		}

		if strings.TrimSpace(*scanDeleteDomain) != "" {
			target := strings.TrimSpace(*scanDeleteDomain)
			if err := database.DeleteAllDataByRootDomain(pid, target); err != nil {
				log.Fatalf("failed to delete domain data: %v", err)
			}
			fmt.Printf("Deleted all data for domain: %s\n", target)
		}
		return
	}

	if *listScreenshots {
		domains, err := plugins.ListScreenshotDomains(*screenshotDir)
		if err != nil {
			log.Fatalf("failed to list screenshot domains: %v", err)
		}
		if len(domains) == 0 {
			fmt.Println("No screenshot data.")
		} else {
			fmt.Println("Domains with screenshots:")
			for _, d := range domains {
				fmt.Printf("  - %s\n", d)
			}
			fmt.Println("\nUse go run main.go -report <domain> to start report server")
		}
		return
	}

	if mode == "monitor" {
		interval, err := time.ParseDuration(*monitorInterval)
		if err != nil || interval <= 0 {
			log.Fatalf("invalid monitor-interval: %s", *monitorInterval)
		}
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		monDB, err := db.NewDatabase(dsn)
		if err != nil {
			log.Fatalf("database connection failed: %v", err)
		}
		notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
		runMonitorLoop(
			monDB,
			strings.TrimSpace(*projectID),
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
			log.Fatalf("failed to start report server: %v", err)
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
		log.Fatalf("failed to read input: %v", err)
	}
	if len(input) == 0 {
		log.Fatalf("empty input")
	}

	printRunInfo(enableSubs, enablePorts, enableWitness, *enableNuclei, *enableActiveSubs, *dryRun, len(input))
	modulesList := buildModules(enableSubs, enablePorts, enableWitness, *enableNuclei, *enableActiveSubs)
	notifier := plugins.NewDingTalkNotifierFromEnv(*enableNotify)
	scanStartTime := time.Now()
	if notifier.Enabled() {
		if err := notifier.SendReconStart(len(input), modulesList, *dryRun); err != nil {
			fmt.Printf("[WARN] failed to send DingTalk start notification: %v\n", err)
		}
	}

	failExit := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		if notifier.Enabled() {
			if err := notifier.SendReconEnd(false, time.Since(scanStartTime), map[string]int{}, msg); err != nil {
				fmt.Printf("[WARN] failed to send DingTalk end notification: %v\n", err)
			}
		}
		log.Fatalf("scan failed: %s", msg)
	}

	var database *db.Database
	var beforeAssetCount, beforePortCount, beforeVulnCount int64
	if !*dryRun {
		dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
		database, err = db.NewDatabase(dsn)
		if err != nil {
			failExit("database connection failed: %v", err)
		}
		beforeAssetCount, _ = database.GetAssetCount()
		beforePortCount, _ = database.GetPortCount()
		beforeVulnCount, _ = database.GetVulnerabilityCount()
	} else {
		fmt.Println("[DRY-RUN] results will not be written to database")
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
		failExit("execution failed: %v", err)
	}

	if !*dryRun && database != nil {
		if err := saveResultsWithContext(database, results, strings.TrimSpace(*projectID), "", ""); err != nil {
			failExit("database write failed: %v", err)
		}
	}

	if notifier.Enabled() {
		stats := collectResultCounts(results)
		if err := notifier.SendReconEnd(true, time.Since(scanStartTime), stats, ""); err != nil {
			fmt.Printf("[WARN] failed to send DingTalk end notification: %v\n", err)
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
	fmt.Println("  API server:         go run . -mode web -web-addr 0.0.0.0:8080")
	fmt.Println("  Worker:             go run . -mode worker")
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
	fmt.Println("  -project           Project ID for data isolation (default: default)")
	fmt.Println("  -active-subs       Enable active subdomain bruteforce (passive-token + dnsx)")
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
	fmt.Println("Starting scan mode")
	fmt.Printf("Input count: %d\n", inputCount)
	fmt.Printf("Pipeline: %s\n", strings.Join(mods, " -> "))
	fmt.Printf("Run mode: %s\n", modeText)
	if dryRun {
		fmt.Println("[DRY-RUN] results will not be written to database")
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
	fmt.Println("==> [Stage] Port Scan")
	pipeline := engine.NewPipeline()

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.ExecuteFromSubdomains(context.Background(), subdomains)
}

func runWitnessOnly(urls []string, screenshotDir string) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Web Screenshot")
	gowitnessPlugin := plugins.NewGowitnessPlugin(screenshotDir)

	var input []string
	for _, u := range urls {
		domain := extractDomainFromURL(u)
		rootDomain := plugins.ExtractRootDomain(domain)
		input = append(input, u+"|"+rootDomain)
	}

	return gowitnessPlugin.Execute(context.Background(), input)
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

	networkResults, err := pipeline.ExecuteFromSubdomains(context.Background(), subdomains)
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

	networkResults, err := pipeline.ExecuteFromSubdomains(context.Background(), subdomains)
	return append(subResults, networkResults...), err
}

func runPortsAndWitness(subdomains []string, screenshotDir string, nucleiEnabled bool) ([]engine.Result, error) {
	fmt.Println("==> [Stage] Port Scan + Web Screenshot")
	pipeline := engine.NewPipeline()

	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	pipeline.AddPortScanner(plugins.NewNaabuPlugin())
	pipeline.AddPortScanner(plugins.NewNmapPlugin())
	pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	if nucleiEnabled {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}

	return pipeline.ExecuteFromSubdomains(context.Background(), subdomains)
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

	networkResults, err := pipeline.ExecuteFromSubdomains(context.Background(), subdomains)
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
	pipeline.AddDomainScanner(plugins.NewChaosPlugin(isBatchMode))
	pipeline.AddDomainScanner(plugins.NewFindomainPlugin())
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())

	results, err := pipeline.Execute(context.Background(), domains)
	subdomains := extractDomainResults(results)
	rawDomainItems := 0
	for _, r := range results {
		if r.Type == "domain" {
			rawDomainItems++
		}
	}
	fmt.Printf("[Subs] Passive merged unique subdomains: %d (raw=%d)\n", len(subdomains), rawDomainItems)
	return results, subdomains, err
}

func runActiveSubdomainExpansion(rootDomains, passiveSubdomains []string, dictSize int, dnsResolvers string) ([]engine.Result, []string, error) {
	var allResults []engine.Result

	words := commonpkg.BuildBruteforceWordlist(passiveSubdomains, rootDomains, clampDictSize(dictSize))
	if len(words) == 0 {
		return allResults, []string{}, nil
	}
	fmt.Printf("[ActiveSubs] Built %d words from passive subdomains\n", len(words))

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
	results, err := scanner.Execute(context.Background(), input)
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

func saveResults(database *db.Database, results []engine.Result) error {
	return saveResultsWithContext(database, results, "", "", "")
}

func saveResultsWithContext(database *db.Database, results []engine.Result, projectID, defaultRootDomain, sourceJobID string) error {
	fmt.Println("==> [DB] Writing results to database")

	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	defaultRootDomain = strings.TrimSpace(defaultRootDomain)
	sourceJobID = strings.TrimSpace(sourceJobID)

	failureCount := 0
	failureSamples := make([]string, 0, 10)
	recordFailure := func(kind string, err error) {
		if err == nil {
			return
		}
		failureCount++
		if len(failureSamples) < 10 {
			failureSamples = append(failureSamples, fmt.Sprintf("%s: %v", kind, err))
		}
	}

	normalizeRoot := func(data map[string]interface{}) {
		if data == nil {
			return
		}
		if v, ok := data["root_domain"].(string); ok && strings.TrimSpace(v) != "" {
			return
		}
		if defaultRootDomain != "" {
			data["root_domain"] = defaultRootDomain
			return
		}

		candidates := []string{
			getStringFromMap(data, "domain"),
			getStringFromMap(data, "host"),
			getStringFromMap(data, "url"),
			getStringFromMap(data, "matched_at"),
		}
		for _, c := range candidates {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			root := plugins.ExtractRootDomain(extractDomainFromURL(c))
			if root != "" {
				data["root_domain"] = root
				return
			}
		}
	}

	for _, result := range results {
		sourceModule := result.Type
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				record := map[string]interface{}{
					"project_id":    projectID,
					"source_job_id": sourceJobID,
					"source_module": sourceModule,
					"domain":        subdomain,
					"verify_status": "pending",
				}
				normalizeRoot(record)
				recordFailure("asset_candidate(domain)", database.SaveOrUpdateAssetCandidate(record))
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				data["source_job_id"] = sourceJobID
				data["source_module"] = sourceModule
				normalizeRoot(data)
				recordFailure("asset(web_service)", database.SaveOrUpdateAsset(data))
				if strings.TrimSpace(getStringFromMap(data, "domain")) != "" {
					recordFailure("asset_candidate(web_service)", database.SaveOrUpdateAssetCandidate(map[string]interface{}{
						"project_id":          projectID,
						"root_domain":         getStringFromMap(data, "root_domain"),
						"source_job_id":       sourceJobID,
						"source_module":       sourceModule,
						"domain":              getStringFromMap(data, "domain"),
						"last_ip":             getStringFromMap(data, "ip"),
						"last_url":            getStringFromMap(data, "url"),
						"last_status_code":    getIntFromMap(data, "status_code"),
						"last_title":          getStringFromMap(data, "title"),
						"verify_status":       "verified",
						"verification_method": "httpx",
					}))
				}
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				data["source_job_id"] = sourceJobID
				data["source_module"] = sourceModule
				normalizeRoot(data)
				recordFailure("port", database.SaveOrUpdatePort(data))
				if strings.TrimSpace(getStringFromMap(data, "domain")) != "" {
					recordFailure("asset_candidate(open_port)", database.SaveOrUpdateAssetCandidate(map[string]interface{}{
						"project_id":          projectID,
						"root_domain":         getStringFromMap(data, "root_domain"),
						"source_job_id":       sourceJobID,
						"source_module":       sourceModule,
						"domain":              getStringFromMap(data, "domain"),
						"last_ip":             getStringFromMap(data, "ip"),
						"verify_status":       "verified",
						"verification_method": "open_port",
					}))
				}
			}
		case "vulnerability":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				data["source_job_id"] = sourceJobID
				normalizeRoot(data)
				recordFailure("vulnerability", database.SaveOrUpdateVulnerability(data))
			}
		}
	}

	if failureCount > 0 {
		for _, sample := range failureSamples {
			fmt.Printf("[DB][ERROR] %s\n", sample)
		}
		return fmt.Errorf("write completed with %d errors", failureCount)
	}

	fmt.Println("==> [DB] Write completed with 0 errors")
	return nil
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
	fmt.Println("Scan completed")
	fmt.Printf("Total duration: %v\n", time.Since(startTime).Round(time.Second))
	fmt.Printf("Subdomains: %d\n", counts["subdomains"])
	fmt.Printf("Web services: %d\n", counts["web_services"])
	fmt.Printf("Open ports: %d\n", counts["ports"])
	fmt.Printf("Vulnerabilities: %d\n", counts["vulnerabilities"])
	fmt.Printf("Screenshots: %d\n", counts["screenshots"])

	if !dryRun && database != nil {
		afterAsset, _ := database.GetAssetCount()
		afterPort, _ := database.GetPortCount()
		afterVuln, _ := database.GetVulnerabilityCount()
		fmt.Println("Database changes:")
		fmt.Printf("- assets: %d -> %d\n", beforeAsset, afterAsset)
		fmt.Printf("- ports: %d -> %d\n", beforePort, afterPort)
		fmt.Printf("- vulnerabilities: %d -> %d\n", beforeVuln, afterVuln)
	}

	if witnessEnabled {
		screenshotDomains, _ := plugins.ListScreenshotDomains(screenshotDir)
		if len(screenshotDomains) > 0 {
			fmt.Println("View screenshots: go run main.go -report <domain>")
		}
	}
	if len(pluginStatuses) > 0 {
		fmt.Println()
		fmt.Println("Plugin execution status:")
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
				counts["screenshots"] += getIntFromMap(data, "screenshot_count")
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
