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
	fmt.Printf("🔁 监控模式已启动: %s, 间隔: %s\n", rootDomain, interval.String())
	for {
		runMonitorCycle(rootDomain, dryRun, notifier)
		time.Sleep(interval)
	}
}

func runMonitorCycle(rootDomain string, dryRun bool, notifier *plugins.DingTalkNotifier) {
	start := time.Now()
	fmt.Printf("🛰️ 开始监控扫描: %s\n", rootDomain)

	if notifier.Enabled() {
		_ = notifier.SendReconStart(1, []string{"subs", "ports", "monitor"}, dryRun)
	}

	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
	database, err := db.NewDatabase(dsn)
	if err != nil {
		fmt.Printf("⚠️  监控数据库连接失败: %v\n", err)
		if notifier.Enabled() {
			_ = notifier.SendReconEnd(false, time.Since(start), map[string]int{}, err.Error())
		}
		return
	}

	run, err := database.CreateMonitorRun(rootDomain)
	if err != nil {
		fmt.Printf("⚠️  创建监控运行记录失败: %v\n", err)
	}

	target, err := database.GetOrCreateMonitorTarget(rootDomain)
	if err != nil {
		fmt.Printf("⚠️  获取监控目标状态失败: %v\n", err)
	}
	baselineMode := target != nil && !target.BaselineDone
	if baselineMode {
		fmt.Println("🧱 首次监控运行：将写入基线，不发送变化通知")
	}

	results, scanErr := runSubsAndPorts([]string{rootDomain}, false)
	if scanErr != nil {
		fmt.Printf("⚠️  监控扫描失败: %v\n", scanErr)
		if run != nil {
			_ = database.CompleteMonitorRun(run.ID, "failed", scanErr.Error(), 0, 0, 0, 0, 0)
		}
		if notifier.Enabled() {
			_ = notifier.SendReconEnd(false, time.Since(start), map[string]int{}, scanErr.Error())
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

	stats := collectResultCounts(results)
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
	if target != nil && !dryRun {
		_ = database.UpdateMonitorTarget(rootDomain, true, time.Now())
	}

	fmt.Printf("✅ 监控完成: 新存活=%d, Web变化=%d, 端口新增=%d, 端口关闭=%d, 服务变化=%d\n",
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("新存活子域: %s (%d)", domain, cur.StatusCode))
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Web变化: %s (%d -> %d)", domain, prev.StatusCode, cur.StatusCode))
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("端口新增: %s:%d", cur.IP, cur.Port))
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("服务变化: %s:%d %s/%s -> %s/%s",
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
		summary.Highlights = append(summary.Highlights, fmt.Sprintf("端口关闭: %s:%d", prev.IP, prev.Port))
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
