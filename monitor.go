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

const (
	monitorTaskStaleAfter       = 90 * time.Minute
	monitorChangeNotifyCooldown = 10 * time.Minute
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

func runMonitorLoop(database *db.Database, projectID, rootDomain string, interval time.Duration, dryRun bool, activeSubs bool, dictSize int, dnsResolvers string, notifier plugins.Notifier) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}

	intervalSec := int(interval.Seconds())
	if intervalSec <= 0 {
		intervalSec = 3600
	}

	if _, err := database.EnableMonitorTarget(projectID, rootDomain, intervalSec, 3, nil); err != nil {
		fmt.Printf("[Monitor] enable target failed: %v\n", err)
		return
	}

	fmt.Printf("[Monitor] scheduler started: %s | interval=%s\n", rootDomain, interval.String())

	// Try immediately once.
	runDueMonitorTasks(database, dryRun, activeSubs, dictSize, dnsResolvers, notifier)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		runDueMonitorTasks(database, dryRun, activeSubs, dictSize, dnsResolvers, notifier)
	}
}
func runDueMonitorTasks(database *db.Database, dryRun bool, activeSubs bool, dictSize int, dnsResolvers string, notifier plugins.Notifier) {
	if recovered, err := database.RecoverStaleRunningTasks(monitorTaskStaleAfter); err != nil {
		fmt.Printf("[Monitor] recover stale tasks failed: %v\n", err)
	} else if recovered > 0 {
		fmt.Printf("[Monitor] recovered stale tasks: %d\n", recovered)
	}

	for {
		if !runOneDueMonitorTask(database, dryRun, activeSubs, dictSize, dnsResolvers, notifier) {
			return
		}
	}
}

func runOneDueMonitorTask(database *db.Database, dryRun bool, activeSubs bool, dictSize int, dnsResolvers string, notifier plugins.Notifier) bool {
	task, err := database.ClaimDueMonitorTask()
	if err != nil {
		fmt.Printf("[Monitor] claim due task failed: %v\n", err)
		return false
	}
	if task == nil {
		return false
	}

	executeMonitorTask(database, task, dryRun, activeSubs, dictSize, dnsResolvers, notifier)
	return true
}

func executeMonitorTask(database *db.Database, task *db.MonitorTask, dryRun bool, activeSubs bool, dictSize int, dnsResolvers string, notifier plugins.Notifier) {
	start := time.Now()
	rootDomain := task.RootDomain
	projectID := strings.TrimSpace(task.ProjectID)
	if projectID == "" {
		projectID = "default"
	}
	fmt.Printf("[Monitor] run task: %s (attempt=%d/%d)\n", rootDomain, task.Attempt+1, task.MaxAttempts)

	if notifier.Enabled() {
		modules := []string{"subs", "ports", "monitor"}
		if activeSubs {
			modules = append(modules, "subs-active")
		}
		if err := notifier.SendReconStart(1, modules, dryRun); err != nil {
			fmt.Printf("[WARN] failed to send monitor start notification: %v\n", err)
		}
	}

	target, err := database.GetOrCreateMonitorTarget(projectID, rootDomain)
	if err != nil {
		errMsg := fmt.Sprintf("monitor target load failed: %v", err)
		fmt.Printf("[Monitor] %s\n", errMsg)
		_ = database.HandleMonitorTaskFailure(task, errMsg)
		if notifier.Enabled() {
			if err := notifier.SendReconEnd(false, time.Since(start), map[string]int{}, errMsg); err != nil {
				fmt.Printf("[WARN] failed to send monitor end notification: %v\n", err)
			}
		}
		return
	}
	baselineMode := !target.BaselineDone
	if baselineMode {
		fmt.Println("[Monitor] first baseline run; skip change notifications")
	}

	run, err := database.CreateMonitorRun(projectID, rootDomain)
	if err != nil {
		fmt.Printf("[Monitor] create run record failed: %v\n", err)
	}

	results, scanErr := runSubsAndPorts([]string{rootDomain}, false, activeSubs, dictSize, dnsResolvers)
	if scanErr != nil {
		errMsg := fmt.Sprintf("monitor scan failed: %v", scanErr)
		fmt.Printf("[Monitor] %s\n", errMsg)
		if run != nil {
			_ = database.CompleteMonitorRun(run.ID, "failed", errMsg, 0, 0, 0, 0, 0)
		}
		_ = database.HandleMonitorTaskFailure(task, errMsg)
		if notifier.Enabled() {
			if err := notifier.SendReconEnd(false, time.Since(start), map[string]int{}, errMsg); err != nil {
				fmt.Printf("[WARN] failed to send monitor end notification: %v\n", err)
			}
		}
		return
	}

	changeSummary := monitorChangeSummary{}
	if !baselineMode {
		currentLive, currentPorts := extractCurrentSnapshots(results)
		prevLiveAssets, _ := database.GetLiveAssetsByRootDomain(projectID, rootDomain)
		prevPorts, _ := database.GetPortsByRootDomain(projectID, rootDomain)
		changeSummary = detectAndPersistChanges(database, projectID, run, rootDomain, currentLive, currentPorts, prevLiveAssets, prevPorts)
	}

	if !dryRun {
		jobID := fmt.Sprintf("monitor-task-%d", task.ID)
		if run != nil {
			jobID = fmt.Sprintf("mon-run-%d", run.ID)
		}
		if err := saveResultsWithContext(database, results, projectID, rootDomain, jobID); err != nil {
			errMsg := fmt.Sprintf("monitor database write failed: %v", err)
			fmt.Printf("[ERROR] %s\n", errMsg)
			if run != nil {
				_ = database.CompleteMonitorRun(run.ID, "failed", errMsg, 0, 0, 0, 0, 0)
			}
			_ = database.HandleMonitorTaskFailure(task, errMsg)
			if notifier.Enabled() {
				if err := notifier.SendReconEnd(false, time.Since(start), map[string]int{}, errMsg); err != nil {
					fmt.Printf("[WARN] failed to send monitor end notification: %v\n", err)
				}
			}
			return
		}
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
		_ = database.UpdateMonitorTargetAfterRun(projectID, rootDomain, time.Now(), baselineMode)
	}

	if err := database.CompleteMonitorTaskSuccess(task.ID); err != nil {
		fmt.Printf("[Monitor] complete task failed: %v\n", err)
	}

	stats := collectResultCounts(results)
	fmt.Printf("[Monitor] task done: %s | new_live=%d web_changed=%d port_opened=%d port_closed=%d service_changed=%d\n",
		rootDomain,
		changeSummary.NewLiveSubdomains,
		changeSummary.WebChanged,
		changeSummary.PortOpened,
		changeSummary.PortClosed,
		changeSummary.ServiceChanged,
	)

	if notifier.Enabled() {
		if err := notifier.SendReconEnd(true, time.Since(start), stats, ""); err != nil {
			fmt.Printf("[WARN] failed to send monitor end notification: %v\n", err)
		}
		if !baselineMode && hasMonitorChanges(changeSummary) {
			shouldSend := true
			if run != nil {
				recent, err := database.HasRecentChangeRun(projectID, rootDomain, run.ID, time.Now().Add(-monitorChangeNotifyCooldown))
				if err != nil {
					fmt.Printf("[Monitor] cooldown check failed: %v\n", err)
				} else if recent {
					shouldSend = false
					fmt.Printf("[Monitor] change alert suppressed by cooldown: %s within %s\n", rootDomain, monitorChangeNotifyCooldown)
				}
			}
			if shouldSend {
				if err := notifier.SendMonitorChanges(rootDomain, map[string]int{
					"new_live_subdomains": changeSummary.NewLiveSubdomains,
					"web_changed":         changeSummary.WebChanged,
					"port_opened":         changeSummary.PortOpened,
					"port_closed":         changeSummary.PortClosed,
					"service_changed":     changeSummary.ServiceChanged,
				}, changeSummary.Highlights); err != nil {
					fmt.Printf("[WARN] failed to send monitor change notification: %v\n", err)
				}
			}
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
	projectID string,
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("New live subdomain: %s (%d)", domain, cur.StatusCode))
			techJSON, _ := json.Marshal(cur.Technologies)
			if runID > 0 {
				_ = database.SaveAssetChange(&db.AssetChange{
					RunID:        runID,
					ProjectID:    projectID,
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Web changed: %s (%d -> %d)", domain, prev.StatusCode, cur.StatusCode))
			techJSON, _ := json.Marshal(cur.Technologies)
			if runID > 0 {
				_ = database.SaveAssetChange(&db.AssetChange{
					RunID:        runID,
					ProjectID:    projectID,
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Port opened: %s:%d", cur.IP, cur.Port))
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					ProjectID:  projectID,
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
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Service changed: %s:%d %s/%s -> %s/%s", cur.IP, cur.Port, prev.Service, prev.Version, cur.Service, cur.Version))
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					ProjectID:  projectID,
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

		prevCloseState, err := database.GetPreviousPortCloseState(projectID, rootDomain, runID, prev.IP, prev.Port)
		if err != nil {
			fmt.Printf("[Monitor] load previous close state failed (%s:%d): %v\n", prev.IP, prev.Port, err)
			prevCloseState = ""
		}

		switch prevCloseState {
		case "closed":
			// Already confirmed closed in previous run; suppress repeated alerts.
			continue
		case "closed_pending":
			// Second consecutive absence confirms closure.
			summary.PortClosed++
			summary.Highlights = append(summary.Highlights, fmt.Sprintf("Port closed: %s:%d", prev.IP, prev.Port))
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					ProjectID:  projectID,
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
		default:
			// First time absent: record pending only, no alert yet.
			if runID > 0 {
				_ = database.SavePortChange(&db.PortChange{
					RunID:      runID,
					ProjectID:  projectID,
					RootDomain: rootDomain,
					ChangeType: "closed_pending",
					Domain:     prev.Domain,
					IP:         prev.IP,
					Port:       prev.Port,
					Protocol:   prev.Protocol,
					Service:    prev.Service,
					Version:    prev.Version,
				})
			}
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
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	return strings.Join(ac, ",") == strings.Join(bc, ",")
}
