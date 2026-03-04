package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

type liveAssetSnapshot struct {
	Domain       string
	URL          string
	StatusCode   int
	Title        string
	Technologies []string
}

type portSnapshot struct {
	Domain   string
	IP       string
	Port     int
	Protocol string
	Service  string
	Version  string
}

type monitorChangeSummary struct {
	NewLiveSubdomains int
	WebChanged        int
	PortOpened        int
	PortClosed        int
	ServiceChanged    int
	Highlights        []string
}

func runMonitorLoop(rootDomain string, interval time.Duration, dryRun bool, notifier *plugins.DingTalkNotifier) {
	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
	database, err := db.NewDatabase(dsn)
	if err != nil {
		fmt.Printf("鈿狅笍  鐩戞帶鏁版嵁搴撹繛鎺ュけ璐? %v\n", err)
		return
	}

	intervalSec := int(interval.Seconds())
	if intervalSec <= 0 {
		intervalSec = 3600
	}

	if err := database.EnableMonitorTarget(rootDomain, intervalSec, 3); err != nil {
		fmt.Printf("鈿狅笍  鍚敤鐩戞帶鐩爣澶辫触: %v\n", err)
		return
	}

	fmt.Printf("馃攣 鐩戞帶璋冨害宸插惎鍔? %s, 浠诲姟闂撮殧: %s\n", rootDomain, interval.String())

	// Try immediately once.
	runDueMonitorTasks(database, dryRun, notifier)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runDueMonitorTasks(database, dryRun, notifier)
	}
}

func runDueMonitorTasks(database *db.Database, dryRun bool, notifier *plugins.DingTalkNotifier) {
	for {
		if !runOneDueMonitorTask(database, dryRun, notifier) {
			return
		}
	}
}

func runOneDueMonitorTask(database *db.Database, dryRun bool, notifier *plugins.DingTalkNotifier) bool {
	task, err := database.ClaimDueMonitorTask()
	if err != nil {
		fmt.Printf("鈿狅笍  鎶㈠崰鐩戞帶浠诲姟澶辫触: %v\n", err)
		return false
	}
	if task == nil {
		return false
	}

	executeMonitorTask(database, task, dryRun, notifier)
	return true
}

func executeMonitorTask(database *db.Database, task *db.MonitorTask, dryRun bool, notifier *plugins.DingTalkNotifier) {
	start := time.Now()
	rootDomain := task.RootDomain
	fmt.Printf("馃洶锔?寮€濮嬫墽琛岀洃鎺т换鍔? %s (attempt=%d/%d)\n", rootDomain, task.Attempt+1, task.MaxAttempts)

	if notifier.Enabled() {
		_ = notifier.SendReconStart(1, []string{"subs", "ports", "monitor"}, dryRun)
	}

	target, err := database.GetOrCreateMonitorTarget(rootDomain)
	if err != nil {
		errMsg := fmt.Sprintf("鑾峰彇鐩戞帶鐩爣鐘舵€佸け璐? %v", err)
		fmt.Printf("鈿狅笍  %s\n", errMsg)
		_ = database.HandleMonitorTaskFailure(task, errMsg)
		if notifier.Enabled() {
			_ = notifier.SendReconEnd(false, time.Since(start), map[string]int{}, errMsg)
		}
		return
	}
	baselineMode := !target.BaselineDone
	if baselineMode {
		fmt.Println("馃П 棣栨鐩戞帶浠诲姟锛氬缓绔嬪熀绾匡紝涓嶅彂閫佸彉鍖栭€氱煡")
	}

	run, err := database.CreateMonitorRun(rootDomain)
	if err != nil {
		fmt.Printf("鈿狅笍  鍒涘缓鐩戞帶杩愯璁板綍澶辫触: %v\n", err)
	}

	results, scanErr := runSubsAndPorts([]string{rootDomain}, false)
	if scanErr != nil {
		errMsg := fmt.Sprintf("鐩戞帶鎵弿澶辫触: %v", scanErr)
		fmt.Printf("鈿狅笍  %s\n", errMsg)
		if run != nil {
			_ = database.CompleteMonitorRun(run.ID, "failed", errMsg, 0, 0, 0, 0, 0)
		}
		_ = database.HandleMonitorTaskFailure(task, errMsg)
		if notifier.Enabled() {
			_ = notifier.SendReconEnd(false, time.Since(start), map[string]int{}, errMsg)
		}
		return
	}

	changeSummary := monitorChangeSummary{}
	if !baselineMode {
		currentLive, currentPorts := extractCurrentSnapshots(results)
		prevLiveAssets, _ := database.GetLiveAssetsByRootDomain(rootDomain)
		prevPorts, _ := database.GetPortsByRootDomain(rootDomain)
		changeSummary = detectAndPersistChanges(database, run, rootDomain, currentLive, currentPorts, prevLiveAssets, prevPorts)
	}

	if !dryRun {
		saveResults(database, results)
	}

	if run != nil {
		_ = database.CompleteMonitorRun(
			run.ID,
			"success",
			"",
			changeSummary.NewLiveSubdomains,
			changeSummary.WebChanged,
			changeSummary.PortOpened,
			changeSummary.PortClosed,
			changeSummary.ServiceChanged,
		)
	}
	if !dryRun {
		_ = database.UpdateMonitorTarget(rootDomain, true, time.Now())
	}

	if err := database.CompleteMonitorTaskSuccess(task.ID); err != nil {
		fmt.Printf("鈿狅笍  瀹屾垚鐩戞帶浠诲姟澶辫触: %v\n", err)
	}

	stats := collectResultCounts(results)
	fmt.Printf("鉁?鐩戞帶浠诲姟瀹屾垚: %s | 鏂板瓨娲?%d Web鍙樺寲=%d 绔彛鏂板=%d 绔彛鍏抽棴=%d 鏈嶅姟鍙樺寲=%d\n",
		rootDomain,
		changeSummary.NewLiveSubdomains,
		changeSummary.WebChanged,
		changeSummary.PortOpened,
		changeSummary.PortClosed,
		changeSummary.ServiceChanged,
	)

	if notifier.Enabled() {
		_ = notifier.SendReconEnd(true, time.Since(start), stats, "")
		if !baselineMode && hasMonitorChanges(changeSummary) {
			_ = notifier.SendMonitorChanges(rootDomain, map[string]int{
				"new_live_subdomains": changeSummary.NewLiveSubdomains,
				"web_changed":         changeSummary.WebChanged,
				"port_opened":         changeSummary.PortOpened,
				"port_closed":         changeSummary.PortClosed,
				"service_changed":     changeSummary.ServiceChanged,
			}, changeSummary.Highlights)
		}
	}
}

func extractCurrentSnapshots(results []engine.Result) (map[string]liveAssetSnapshot, map[string]portSnapshot) {
	liveMap := make(map[string]liveAssetSnapshot)
	portMap := make(map[string]portSnapshot)

	for _, r := range results {
		switch r.Type {
		case "web_service":
			data, ok := r.Data.(map[string]interface{})
			if !ok {
				continue
			}
			domain, _ := data["domain"].(string)
			if domain == "" {
				continue
			}
			techs := extractStringSlice(data["technologies"])
			liveMap[domain] = liveAssetSnapshot{
				Domain:       domain,
				URL:          getStringFromMap(data, "url"),
				StatusCode:   getIntFromMap(data, "status_code"),
				Title:        getStringFromMap(data, "title"),
				Technologies: techs,
			}
		case "port_service", "open_port":
			data, ok := r.Data.(map[string]interface{})
			if !ok {
				continue
			}
			ip, _ := data["ip"].(string)
			port := getIntFromMap(data, "port")
			if ip == "" || port <= 0 {
				continue
			}
			key := fmt.Sprintf("%s:%d", ip, port)
			portMap[key] = portSnapshot{
				Domain:   getStringFromMap(data, "domain"),
				IP:       ip,
				Port:     port,
				Protocol: getStringFromMap(data, "protocol"),
				Service:  getStringFromMap(data, "service"),
				Version:  getStringFromMap(data, "version"),
			}
		}
	}

	return liveMap, portMap
}

func detectAndPersistChanges(
	database *db.Database,
	run *db.MonitorRun,
	rootDomain string,
	currentLive map[string]liveAssetSnapshot,
	currentPorts map[string]portSnapshot,
	prevLiveAssets []db.Asset,
	prevPorts []db.Port,
) monitorChangeSummary {
	summary := monitorChangeSummary{}
	runID := uint(0)
	if run != nil {
		runID = run.ID
	}

	prevLive := make(map[string]liveAssetSnapshot)
	for _, a := range prevLiveAssets {
		prevLive[a.Domain] = liveAssetSnapshot{
			Domain:       a.Domain,
			URL:          a.URL,
			StatusCode:   a.StatusCode,
			Title:        a.Title,
			Technologies: decodeTech(a.Technologies),
		}
	}

	for domain, cur := range currentLive {
		prev, exists := prevLive[domain]
		if !exists {
			summary.NewLiveSubdomains++
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("鏂板瓨娲诲瓙鍩? %s (%d)", domain, cur.StatusCode))
			techJSON, _ := json.Marshal(cur.Technologies)
			if runID > 0 {
				_ = database.SaveAssetChange(&db.AssetChange{
					RunID:        runID,
					RootDomain:   rootDomain,
					ChangeType:   "new_live_subdomain",
					Domain:       cur.Domain,
					URL:          cur.URL,
					StatusCode:   cur.StatusCode,
					Title:        cur.Title,
					Technologies: techJSON,
				})
			}
			continue
		}

		if cur.StatusCode != prev.StatusCode || cur.Title != prev.Title || !equalStringSet(cur.Technologies, prev.Technologies) {
			summary.WebChanged++
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Web鍙樺寲: %s (%d -> %d)", domain, prev.StatusCode, cur.StatusCode))
			techJSON, _ := json.Marshal(cur.Technologies)
			if runID > 0 {
				_ = database.SaveAssetChange(&db.AssetChange{
					RunID:        runID,
					RootDomain:   rootDomain,
					ChangeType:   "web_changed",
					Domain:       cur.Domain,
					URL:          cur.URL,
					StatusCode:   cur.StatusCode,
					Title:        cur.Title,
					Technologies: techJSON,
				})
			}
		}
	}

	prevPortMap := make(map[string]portSnapshot)
	for _, p := range prevPorts {
		key := fmt.Sprintf("%s:%d", p.IP, p.Port)
		prevPortMap[key] = portSnapshot{
			Domain:   p.Domain,
			IP:       p.IP,
			Port:     p.Port,
			Protocol: p.Protocol,
			Service:  p.Service,
			Version:  p.Version,
		}
	}

	for key, cur := range currentPorts {
		prev, exists := prevPortMap[key]
		if !exists {
			summary.PortOpened++
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("绔彛鏂板: %s:%d", cur.IP, cur.Port))
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					RootDomain: rootDomain,
					ChangeType: "opened",
					Domain:     cur.Domain,
					IP:         cur.IP,
					Port:       cur.Port,
					Protocol:   cur.Protocol,
					Service:    cur.Service,
					Version:    cur.Version,
				})
			}
			continue
		}

		if cur.Service != prev.Service || cur.Version != prev.Version {
			summary.ServiceChanged++
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("鏈嶅姟鍙樺寲: %s:%d %s/%s -> %s/%s",
				cur.IP, cur.Port, prev.Service, prev.Version, cur.Service, cur.Version))
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					RootDomain: rootDomain,
					ChangeType: "service_changed",
					Domain:     cur.Domain,
					IP:         cur.IP,
					Port:       cur.Port,
					Protocol:   cur.Protocol,
					Service:    cur.Service,
					Version:    cur.Version,
				})
			}
		}
	}

	for key, prev := range prevPortMap {
		if _, exists := currentPorts[key]; exists {
			continue
		}
		summary.PortClosed++
		summary.Highlights = append(summary.Highlights, fmt.Sprintf("绔彛鍏抽棴: %s:%d", prev.IP, prev.Port))
		if runID > 0 {
			_ = database.SavePortChange(&db.PortChange{
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "closed",
				Domain:     prev.Domain,
				IP:         prev.IP,
				Port:       prev.Port,
				Protocol:   prev.Protocol,
				Service:    prev.Service,
				Version:    prev.Version,
			})
		}
	}

	if len(summary.Highlights) > 10 {
		summary.Highlights = summary.Highlights[:10]
	}
	return summary
}

func hasMonitorChanges(s monitorChangeSummary) bool {
	return s.NewLiveSubdomains > 0 || s.WebChanged > 0 || s.PortOpened > 0 || s.PortClosed > 0 || s.ServiceChanged > 0
}

func decodeTech(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	_ = json.Unmarshal(raw, &out)
	return out
}

func extractStringSlice(v interface{}) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []interface{}:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		ac := append([]string{}, a...)
		bc := append([]string{}, b...)
		sort.Strings(ac)
		sort.Strings(bc)
		return strings.Join(ac, ",") == strings.Join(bc, ",")
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return strings.Join(ac, ",") == strings.Join(bc, ",")
}

