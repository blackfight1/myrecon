package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"hunter/internal/db"
	"hunter/internal/plugins"
)

// Server is the HTTP API server.
type Server struct {
	db            *db.Database
	mux           *http.ServeMux
	screenshotDir string
}

// NewServer creates a new API server.
func NewServer(database *db.Database, screenshotDir string) *Server {
	s := &Server{
		db:            database,
		mux:           http.NewServeMux(),
		screenshotDir: screenshotDir,
	}
	s.registerRoutes()
	return s
}

// Start starts the HTTP server.
func (s *Server) Start(addr string) error {
	log.Printf("[API] Server starting on %s", addr)
	return http.ListenAndServe(addr, s.corsMiddleware(s.mux))
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/dashboard/summary", s.handleDashboard)
	s.mux.HandleFunc("/api/assets", s.handleAssets)
	s.mux.HandleFunc("/api/ports", s.handlePorts)
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/monitor/targets", s.handleMonitorTargets)
	s.mux.HandleFunc("/api/monitor/runs", s.handleMonitorRuns)
	s.mux.HandleFunc("/api/monitor/changes", s.handleMonitorChanges)
	s.mux.HandleFunc("/api/screenshots/domains", s.handleScreenshotDomains)
	s.mux.HandleFunc("/api/screenshots/", s.handleScreenshots)
	s.mux.HandleFunc("/api/settings", s.handleSettings)
	s.mux.HandleFunc("/api/settings/tools", s.handleToolStatus)
	s.mux.HandleFunc("/api/settings/test-notify", s.handleTestNotify)
	s.mux.HandleFunc("/api/projects", s.handleProjects)
}

// ── JSON helpers ──

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[API] JSON encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── Dashboard ──

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	assetCount, _ := s.db.GetAssetCount()
	portCount, _ := s.db.GetPortCount()
	vulnCount, _ := s.db.GetVulnerabilityCount()

	// Count live web services (assets with non-empty URL)
	var webServiceCount int64
	s.db.DB.Model(&db.Asset{}).Where("url <> ''").Count(&webServiceCount)

	// Count monitor targets
	var monitorCount int64
	s.db.DB.Model(&db.MonitorTarget{}).Where("enabled = ?", true).Count(&monitorCount)

	// Severity breakdown
	severities := map[string]int64{}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		var c int64
		s.db.DB.Model(&db.Vulnerability{}).Where("severity = ?", sev).Count(&c)
		severities[sev] = c
	}

	// Recent 7-day trend
	trend := make([]map[string]interface{}, 0)
	for i := 6; i >= 0; i-- {
		day := time.Now().AddDate(0, 0, -i)
		dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
		dayEnd := dayStart.Add(24 * time.Hour)

		var assets, ports, vulns int64
		s.db.DB.Model(&db.Asset{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&assets)
		s.db.DB.Model(&db.Port{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&ports)
		s.db.DB.Model(&db.Vulnerability{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&vulns)

		trend = append(trend, map[string]interface{}{
			"date":       dayStart.Format("2006-01-02"),
			"new_assets": assets,
			"new_ports":  ports,
			"new_vulns":  vulns,
		})
	}

	writeJSON(w, 200, map[string]interface{}{
		"summary": map[string]interface{}{
			"total_assets":       assetCount,
			"total_ports":        portCount,
			"total_vulns":        vulnCount,
			"web_services":       webServiceCount,
			"monitored_targets":  monitorCount,
			"severity_breakdown": severities,
		},
		"trend": trend,
	})
}

// ── Assets ──

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	var assets []db.Asset
	query := s.db.DB.Order("created_at desc").Limit(5000)

	// Optional filter by root domain
	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		pattern := "%." + rd
		query = query.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}

	if err := query.Find(&assets).Error; err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, assets)
}

// ── Ports ──

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	var ports []db.Port
	query := s.db.DB.Order("created_at desc").Limit(5000)

	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		pattern := "%." + rd
		query = query.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}

	if err := query.Find(&ports).Error; err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, ports)
}

// ── Vulnerabilities ──

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	var vulns []db.Vulnerability
	query := s.db.DB.Order("created_at desc").Limit(5000)

	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		query = query.Where("root_domain = ?", rd)
	}
	if sev := r.URL.Query().Get("severity"); sev != "" {
		query = query.Where("severity = ?", sev)
	}

	if err := query.Find(&vulns).Error; err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, vulns)
}

// ── Jobs (scan tasks) ──

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return monitor tasks as jobs
		var tasks []db.MonitorTask
		if err := s.db.DB.Order("created_at desc").Limit(100).Find(&tasks).Error; err != nil {
			writeError(w, 500, err.Error())
			return
		}

		jobs := make([]map[string]interface{}, 0, len(tasks))
		for _, t := range tasks {
			jobs = append(jobs, map[string]interface{}{
				"id":          t.ID,
				"domain":      t.RootDomain,
				"status":      t.Status,
				"run_at":      t.RunAt,
				"started_at":  t.StartedAt,
				"finished_at": t.FinishedAt,
				"attempt":     t.Attempt,
				"last_error":  t.LastError,
				"created_at":  t.CreatedAt,
			})
		}
		writeJSON(w, 200, jobs)

	case "POST":
		// Create a new scan job - placeholder for now
		writeJSON(w, 200, map[string]interface{}{
			"id":      0,
			"status":  "pending",
			"message": "Job creation via API is not yet implemented. Use CLI: go run . -d <domain>",
		})

	default:
		writeError(w, 405, "method not allowed")
	}
}

// ── Monitor ──

func (s *Server) handleMonitorTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	targets, err := s.db.ListMonitorTargets()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, targets)
}

func (s *Server) handleMonitorRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	var runs []db.MonitorRun
	query := s.db.DB.Order("started_at desc").Limit(100)

	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		query = query.Where("root_domain = ?", rd)
	}

	if err := query.Find(&runs).Error; err != nil {
		writeError(w, 500, err.Error())
		return
	}

	writeJSON(w, 200, runs)
}

func (s *Server) handleMonitorChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	type ChangeItem struct {
		Type       string      `json:"type"`
		ChangeType string      `json:"change_type"`
		Domain     string      `json:"domain"`
		Detail     interface{} `json:"detail"`
		CreatedAt  time.Time   `json:"created_at"`
	}

	var results []ChangeItem

	// Asset changes
	var assetChanges []db.AssetChange
	aq := s.db.DB.Order("created_at desc").Limit(200)
	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		aq = aq.Where("root_domain = ?", rd)
	}
	if err := aq.Find(&assetChanges).Error; err == nil {
		for _, ac := range assetChanges {
			results = append(results, ChangeItem{
				Type:       "asset",
				ChangeType: ac.ChangeType,
				Domain:     ac.Domain,
				Detail: map[string]interface{}{
					"url":         ac.URL,
					"status_code": ac.StatusCode,
					"title":       ac.Title,
				},
				CreatedAt: ac.CreatedAt,
			})
		}
	}

	// Port changes
	var portChanges []db.PortChange
	pq := s.db.DB.Order("created_at desc").Limit(200)
	if rd := r.URL.Query().Get("root_domain"); rd != "" {
		pq = pq.Where("root_domain = ?", rd)
	}
	if err := pq.Find(&portChanges).Error; err == nil {
		for _, pc := range portChanges {
			results = append(results, ChangeItem{
				Type:       "port",
				ChangeType: pc.ChangeType,
				Domain:     pc.Domain,
				Detail: map[string]interface{}{
					"ip":       pc.IP,
					"port":     pc.Port,
					"protocol": pc.Protocol,
					"service":  pc.Service,
				},
				CreatedAt: pc.CreatedAt,
			})
		}
	}

	writeJSON(w, 200, results)
}

// ── Screenshots ──

func (s *Server) handleScreenshotDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	domains, err := plugins.ListScreenshotDomains(s.screenshotDir)
	if err != nil {
		writeJSON(w, 200, []interface{}{})
		return
	}

	result := make([]map[string]interface{}, 0, len(domains))
	for _, d := range domains {
		result = append(result, map[string]interface{}{
			"root_domain": d,
			"count":       0,
		})
	}

	writeJSON(w, 200, result)
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	// Extract root domain from path: /api/screenshots/{rootDomain}
	path := strings.TrimPrefix(r.URL.Path, "/api/screenshots/")
	if path == "" {
		writeError(w, 400, "root_domain required")
		return
	}

	// For now return empty - screenshots are file-based, not in DB
	writeJSON(w, 200, []interface{}{})
}

// ── Settings ──

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, 200, map[string]interface{}{
			"database": map[string]interface{}{
				"host":      "localhost",
				"port":      5432,
				"name":      "hunter",
				"connected": true,
			},
			"notification": map[string]interface{}{
				"dingtalk_webhook": "",
				"dingtalk_secret":  "",
			},
			"scanner": map[string]interface{}{
				"screenshot_dir": s.screenshotDir,
				"dns_resolvers":  "",
				"dict_size":      1500,
				"active_subs":    false,
				"enable_nuclei":  false,
			},
		})

	case "POST":
		writeJSON(w, 200, map[string]interface{}{
			"message": "Settings updated",
		})

	default:
		writeError(w, 405, "method not allowed")
	}
}

func (s *Server) handleToolStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	tools := []map[string]interface{}{
		checkTool("subfinder"),
		checkTool("findomain"),
		checkTool("bbot"),
		checkTool("shosubgo"),
		checkTool("httpx"),
		checkTool("naabu"),
		checkTool("nmap"),
		checkTool("nuclei"),
		checkTool("gowitness"),
		checkTool("dnsx"),
		checkTool("alterx"),
	}

	writeJSON(w, 200, tools)
}

func checkTool(name string) map[string]interface{} {
	path, err := exec.LookPath(name)
	if err != nil {
		return map[string]interface{}{
			"name":      name,
			"installed": false,
			"version":   "",
			"path":      "",
		}
	}

	version := ""
	var cmd *exec.Cmd
	switch name {
	case "nmap":
		cmd = exec.Command(name, "--version")
	case "bbot":
		cmd = exec.Command(name, "--version")
	default:
		cmd = exec.Command(name, "-version")
	}

	if out, err := cmd.Output(); err == nil {
		v := strings.TrimSpace(string(out))
		// Take first line only
		if idx := strings.Index(v, "\n"); idx != -1 {
			v = v[:idx]
		}
		if len(v) > 80 {
			v = v[:80]
		}
		version = v
	}

	return map[string]interface{}{
		"name":      name,
		"installed": true,
		"version":   version,
		"path":      path,
	}
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeError(w, 405, "method not allowed")
		return
	}

	notifier := plugins.NewDingTalkNotifierFromEnv(true)
	if !notifier.Enabled() {
		writeJSON(w, 200, map[string]interface{}{
			"success": false,
			"message": "DingTalk webhook not configured. Set DINGTALK_WEBHOOK env var.",
		})
		return
	}

	err := notifier.SendReconStart(0, []string{"test"}, true)
	if err != nil {
		writeJSON(w, 200, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Failed: %v", err),
		})
		return
	}

	writeJSON(w, 200, map[string]interface{}{
		"success": true,
		"message": "Test notification sent successfully",
	})
}

// ── Projects (derived from root domains in data) ──

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeError(w, 405, "method not allowed")
		return
	}

	// Derive projects from unique root domains in assets
	type rootInfo struct {
		RootDomain string
		Count      int64
	}

	var assets []db.Asset
	if err := s.db.DB.Select("domain").Find(&assets).Error; err != nil {
		writeError(w, 500, err.Error())
		return
	}

	rootMap := make(map[string]int64)
	for _, a := range assets {
		rd := extractRootDomain(a.Domain)
		if rd != "" {
			rootMap[rd]++
		}
	}

	projects := make([]map[string]interface{}, 0)
	id := 1
	for rd, count := range rootMap {
		projects = append(projects, map[string]interface{}{
			"id":           fmt.Sprintf("proj-%d", id),
			"name":         rd,
			"root_domains": []string{rd},
			"asset_count":  count,
			"created_at":   time.Now().Format(time.RFC3339),
		})
		id++
	}

	// If no projects, add a default one
	if len(projects) == 0 {
		projects = append(projects, map[string]interface{}{
			"id":           "proj-default",
			"name":         "Default",
			"root_domains": []string{},
			"asset_count":  0,
			"created_at":   time.Now().Format(time.RFC3339),
		})
	}

	writeJSON(w, 200, projects)
}

// ── System Info ──

func GetSystemInfo() map[string]interface{} {
	return map[string]interface{}{
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

func extractRootDomain(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(domain)), ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
