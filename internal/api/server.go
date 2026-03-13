package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

const (
	defaultMonitorIntervalSec = 6 * 3600
	maxListRows               = 5000
	schedulerPollInterval     = 15 * time.Second
)

// Server is the HTTP API server.
type Server struct {
	db            *db.Database
	mux           *http.ServeMux
	screenshotDir string

	settingsMu sync.RWMutex
	settings   runtimeSettings

	// cancel functions for running scans, keyed by jobID
	scanCancelMu sync.Mutex
	scanCancels  map[string]context.CancelFunc
}

type runtimeSettings struct {
	Database      runtimeDatabaseSettings
	Notifications runtimeNotificationSettings
	Scanner       runtimeScannerSettings
}

type runtimeDatabaseSettings struct {
	Host    string
	Port    int
	User    string
	DBName  string
	SSLMode string
}

type runtimeNotificationSettings struct {
	DingTalkWebhook string
	DingTalkSecret  string
	Enabled         bool
}

type runtimeScannerSettings struct {
	ScreenshotDir     string
	DNSResolvers      string
	DefaultDictSize   int
	DefaultActiveSubs bool
	DefaultNuclei     bool
}

type dashboardResponse struct {
	Summary dashboardSummaryResponse `json:"summary"`
	Trend   []trendPointResponse     `json:"trend"`
}

type dashboardSummaryResponse struct {
	JobsRunning           int `json:"jobsRunning"`
	JobsSuccess24h        int `json:"jobsSuccess24h"`
	JobsFailed24h         int `json:"jobsFailed24h"`
	NewSubdomains24h      int `json:"newSubdomains24h"`
	NewPorts24h           int `json:"newPorts24h"`
	NewVulns24h           int `json:"newVulns24h"`
	ScanDurationAvgSec24h int `json:"scanDurationAvgSec24h"`
}

type trendPointResponse struct {
	Date            string `json:"date"`
	Subdomains      int    `json:"subdomains"`
	Ports           int    `json:"ports"`
	Vulnerabilities int    `json:"vulnerabilities"`
}

type jobOverviewResponse struct {
	ID           string   `json:"id"`
	RootDomain   string   `json:"rootDomain"`
	Mode         string   `json:"mode"`
	Modules      []string `json:"modules"`
	Status       string   `json:"status"`
	StartedAt    string   `json:"startedAt"`
	FinishedAt   string   `json:"finishedAt,omitempty"`
	DurationSec  int      `json:"durationSec,omitempty"`
	ErrorMessage string   `json:"errorMessage,omitempty"`
	SubdomainCnt int      `json:"subdomainCnt,omitempty"`
	PortCnt      int      `json:"portCnt,omitempty"`
	VulnCnt      int      `json:"vulnCnt,omitempty"`
}

type createJobRequest struct {
	Domain       string   `json:"domain"`
	Mode         string   `json:"mode"`
	Modules      []string `json:"modules"`
	EnableNuclei bool     `json:"enableNuclei"`
	ActiveSubs   bool     `json:"activeSubs"`
	DictSize     int      `json:"dictSize"`
	DNSResolvers string   `json:"dnsResolvers"`
	DryRun       bool     `json:"dryRun"`
}

type assetResponse struct {
	ID           int      `json:"id"`
	Domain       string   `json:"domain"`
	URL          string   `json:"url,omitempty"`
	IP           string   `json:"ip,omitempty"`
	StatusCode   int      `json:"statusCode,omitempty"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	CreatedAt    string   `json:"createdAt,omitempty"`
	UpdatedAt    string   `json:"updatedAt,omitempty"`
	LastSeen     string   `json:"lastSeen,omitempty"`
}

type portResponse struct {
	ID        int    `json:"id"`
	AssetID   int    `json:"assetId,omitempty"`
	Domain    string `json:"domain,omitempty"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol,omitempty"`
	Service   string `json:"service,omitempty"`
	Version   string `json:"version,omitempty"`
	Banner    string `json:"banner,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type vulnerabilityResponse struct {
	ID           int    `json:"id"`
	RootDomain   string `json:"rootDomain,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Host         string `json:"host,omitempty"`
	URL          string `json:"url,omitempty"`
	IP           string `json:"ip,omitempty"`
	TemplateID   string `json:"templateId"`
	TemplateName string `json:"templateName,omitempty"`
	Severity     string `json:"severity,omitempty"`
	CVE          string `json:"cve,omitempty"`
	MatcherName  string `json:"matcherName,omitempty"`
	Description  string `json:"description,omitempty"`
	Reference    string `json:"reference,omitempty"`
	MatchedAt    string `json:"matchedAt"`
	Fingerprint  string `json:"fingerprint"`
	LastSeen     string `json:"lastSeen,omitempty"`
}

type monitorTargetResponse struct {
	ID           int    `json:"id"`
	RootDomain   string `json:"rootDomain"`
	Enabled      bool   `json:"enabled"`
	BaselineDone bool   `json:"baselineDone"`
	LastRunAt    string `json:"lastRunAt,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	UpdatedAt    string `json:"updatedAt,omitempty"`
}

type monitorRunResponse struct {
	ID            int    `json:"id"`
	RootDomain    string `json:"rootDomain"`
	Status        string `json:"status"`
	StartedAt     string `json:"startedAt"`
	FinishedAt    string `json:"finishedAt,omitempty"`
	DurationSec   int    `json:"durationSec"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
	NewLiveCount  int    `json:"newLiveCount"`
	WebChanged    int    `json:"webChanged"`
	PortOpened    int    `json:"portOpened"`
	PortClosed    int    `json:"portClosed"`
	ServiceChange int    `json:"serviceChange"`
}

type monitorChangeResponse struct {
	RunID      int    `json:"runId"`
	RootDomain string `json:"rootDomain"`
	ChangeType string `json:"changeType"`
	Domain     string `json:"domain,omitempty"`
	IP         string `json:"ip,omitempty"`
	Port       int    `json:"port,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	Title      string `json:"title,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
}

type screenshotDomainResponse struct {
	RootDomain      string `json:"rootDomain"`
	ScreenshotCount int    `json:"screenshotCount"`
	ScreenshotDir   string `json:"screenshotDir"`
	DatabasePath    string `json:"databasePath"`
}

type screenshotItemResponse struct {
	ID           int    `json:"id"`
	URL          string `json:"url"`
	Filename     string `json:"filename"`
	Title        string `json:"title,omitempty"`
	StatusCode   int    `json:"statusCode,omitempty"`
	RootDomain   string `json:"rootDomain"`
	ThumbnailURL string `json:"thumbnailUrl"`
	FullURL      string `json:"fullUrl"`
	CreatedAt    string `json:"createdAt,omitempty"`
}

type systemSettingsResponse struct {
	Database      databaseSettingsResponse     `json:"database"`
	Notifications notificationSettingsResponse `json:"notifications"`
	Scanner       scannerSettingsResponse      `json:"scanner"`
	Tools         []toolStatusResponse         `json:"tools"`
}

type databaseSettingsResponse struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	User      string `json:"user"`
	DBName    string `json:"dbname"`
	SSLMode   string `json:"sslmode"`
	Connected bool   `json:"connected"`
}

type notificationSettingsResponse struct {
	DingTalkWebhook string `json:"dingtalkWebhook"`
	DingTalkSecret  string `json:"dingtalkSecret"`
	Enabled         bool   `json:"enabled"`
}

type scannerSettingsResponse struct {
	ScreenshotDir     string `json:"screenshotDir"`
	DNSResolvers      string `json:"dnsResolvers"`
	DefaultDictSize   int    `json:"defaultDictSize"`
	DefaultActiveSubs bool   `json:"defaultActiveSubs"`
	DefaultNuclei     bool   `json:"defaultNuclei"`
}

type toolStatusResponse struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
}

type settingsPatchRequest struct {
	Database      *databaseSettingsPatch     `json:"database"`
	Notifications *notificationSettingsPatch `json:"notifications"`
	Scanner       *scannerSettingsPatch      `json:"scanner"`
}

type databaseSettingsPatch struct {
	Host    *string `json:"host"`
	Port    *int    `json:"port"`
	User    *string `json:"user"`
	DBName  *string `json:"dbname"`
	SSLMode *string `json:"sslmode"`
}

type notificationSettingsPatch struct {
	DingTalkWebhook *string `json:"dingtalkWebhook"`
	DingTalkSecret  *string `json:"dingtalkSecret"`
	Enabled         *bool   `json:"enabled"`
}

type scannerSettingsPatch struct {
	ScreenshotDir     *string `json:"screenshotDir"`
	DNSResolvers      *string `json:"dnsResolvers"`
	DefaultDictSize   *int    `json:"defaultDictSize"`
	DefaultActiveSubs *bool   `json:"defaultActiveSubs"`
	DefaultNuclei     *bool   `json:"defaultNuclei"`
}

type monitorChangeSortItem struct {
	createdAt time.Time
	item      monitorChangeResponse
}

type createMonitorRequest struct {
	Domain      string `json:"domain"`
	IntervalSec int    `json:"intervalSec"`
}

// NewServer creates a new API server.
func NewServer(database *db.Database, screenshotDir string) *Server {
	if strings.TrimSpace(screenshotDir) == "" {
		screenshotDir = "screenshots"
	}

	s := &Server{
		db:            database,
		mux:           http.NewServeMux(),
		screenshotDir: screenshotDir,
		settings:      loadRuntimeSettings(screenshotDir),
		scanCancels:   make(map[string]context.CancelFunc),
	}
	s.registerRoutes()
	return s
}

// Start starts the HTTP server and the monitor scheduler.
func (s *Server) Start(addr string) error {
	// Recover stale monitor tasks from previous crash
	if recovered, err := s.db.RecoverStaleRunningTasks(2 * time.Hour); err != nil {
		log.Printf("[Scheduler] failed to recover stale tasks: %v", err)
	} else if recovered > 0 {
		log.Printf("[Scheduler] recovered %d stale running tasks", recovered)
	}

	// Start monitor scheduler in background
	go s.runMonitorScheduler()

	log.Printf("[API] server starting on %s (monitor scheduler enabled)", addr)
	return http.ListenAndServe(addr, s.corsMiddleware(s.mux))
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/dashboard/summary", s.handleDashboard)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/jobs/cancel", s.handleCancelJob)
	s.mux.HandleFunc("/api/assets", s.handleAssets)
	s.mux.HandleFunc("/api/ports", s.handlePorts)
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	s.mux.HandleFunc("/api/monitor/targets", s.handleMonitorTargets)
	s.mux.HandleFunc("/api/monitor/runs", s.handleMonitorRuns)
	s.mux.HandleFunc("/api/monitor/changes", s.handleMonitorChanges)
	s.mux.HandleFunc("/api/screenshots/domains", s.handleScreenshotDomains)
	s.mux.HandleFunc("/api/screenshots/file/", s.handleScreenshotFile)
	s.mux.HandleFunc("/api/screenshots/", s.handleScreenshots)
	s.mux.HandleFunc("/api/settings", s.handleSettings)
	s.mux.HandleFunc("/api/settings/tools", s.handleToolStatus)
	s.mux.HandleFunc("/api/settings/test-notify", s.handleTestNotify)
}

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

// ──────────────────────────────────────────
// Monitor Scheduler — runs inside web server
// ──────────────────────────────────────────

func (s *Server) runMonitorScheduler() {
	log.Printf("[Scheduler] monitor scheduler started (poll=%v)", schedulerPollInterval)
	ticker := time.NewTicker(schedulerPollInterval)
	defer ticker.Stop()

	for range ticker.C {
		task, err := s.db.ClaimDueMonitorTask()
		if err != nil {
			log.Printf("[Scheduler] claim error: %v", err)
			continue
		}
		if task == nil {
			continue
		}
		go s.executeMonitorTask(task)
	}
}

func (s *Server) executeMonitorTask(task *db.MonitorTask) {
	rootDomain := task.RootDomain
	log.Printf("[Scheduler] executing monitor task %d for %s", task.ID, rootDomain)

	// Create a monitor run record
	run, err := s.db.CreateMonitorRun(rootDomain)
	if err != nil {
		log.Printf("[Scheduler] failed to create monitor run: %v", err)
		_ = s.db.HandleMonitorTaskFailure(task, fmt.Sprintf("create run failed: %v", err))
		return
	}

	target, err := s.db.GetOrCreateMonitorTarget(rootDomain)
	if err != nil {
		log.Printf("[Scheduler] failed to get monitor target: %v", err)
		_ = s.db.CompleteMonitorRun(run.ID, "failed", err.Error(), 0, 0, 0, 0, 0)
		_ = s.db.HandleMonitorTaskFailure(task, err.Error())
		return
	}

	// Collect subdomains
	subResults, subdomains, err := s.collectSubdomains([]string{rootDomain})
	if err != nil {
		errMsg := fmt.Sprintf("subdomain collection failed: %v", err)
		log.Printf("[Scheduler] %s", errMsg)
		_ = s.db.CompleteMonitorRun(run.ID, "failed", errMsg, 0, 0, 0, 0, 0)
		_ = s.db.HandleMonitorTaskFailure(task, errMsg)
		return
	}

	// Run network pipeline (httpx + ports)
	networkResults, err := s.runNetworkPipeline(subdomains, true, false, false, s.screenshotDir)
	if err != nil {
		log.Printf("[Scheduler] network pipeline warning for %s: %v", rootDomain, err)
	}

	allResults := append(subResults, networkResults...)

	// Save results to DB
	if dbErr := s.saveResultsToDB(allResults); dbErr != nil {
		log.Printf("[Scheduler] DB save warning: %v", dbErr)
	}

	// Detect changes
	newLive, webChanged, portOpened, portClosed, svcChanged := s.detectChanges(rootDomain, run.ID, target)

	// Complete run
	status := "success"
	_ = s.db.CompleteMonitorRun(run.ID, status, "", newLive, webChanged, portOpened, portClosed, svcChanged)

	// Update target baseline
	now := time.Now()
	_ = s.db.UpdateMonitorTarget(rootDomain, true, now)

	// Complete task and schedule next
	_ = s.db.CompleteMonitorTaskSuccess(task.ID)

	totalChanges := newLive + webChanged + portOpened + portClosed + svcChanged
	log.Printf("[Scheduler] monitor task %d completed for %s: %d total changes", task.ID, rootDomain, totalChanges)

	// Send notification if changes detected
	if totalChanges > 0 {
		s.settingsMu.RLock()
		notifyEnabled := s.settings.Notifications.Enabled
		s.settingsMu.RUnlock()
		if notifyEnabled {
			notifier := plugins.NewDingTalkNotifierFromEnv(true)
			if notifier.Enabled() {
				stats := map[string]int{
					"new_live": newLive, "web_changed": webChanged,
					"port_opened": portOpened, "port_closed": portClosed,
					"service_changed": svcChanged,
				}
				_ = notifier.SendReconEnd(true, time.Since(run.StartedAt), stats, "")
			}
		}
	}
}

// detectChanges compares current state with previous baseline.
func (s *Server) detectChanges(rootDomain string, runID uint, target *db.MonitorTarget) (newLive, webChanged, portOpened, portClosed, svcChanged int) {
	if !target.BaselineDone {
		// First run = baseline, no changes to detect
		return 0, 0, 0, 0, 0
	}

	// Detect new live subdomains (created in last interval)
	recentAssets, _ := s.db.GetRecentAssets(target.LastRunAt.Add(-1 * time.Minute))
	for _, a := range recentAssets {
		if a.URL != "" && matchesRootDomain(a.Domain, rootDomain) {
			newLive++
			_ = s.db.SaveAssetChange(&db.AssetChange{
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "new_live",
				Domain:     a.Domain,
				URL:        a.URL,
				StatusCode: a.StatusCode,
				Title:      a.Title,
			})
		}
	}

	// Detect new ports
	var since time.Time
	if target.LastRunAt != nil {
		since = target.LastRunAt.Add(-1 * time.Minute)
	}
	recentPorts, _ := s.db.GetRecentPorts(since)
	for _, p := range recentPorts {
		if matchesRootDomain(p.Domain, rootDomain) {
			portOpened++
			_ = s.db.SavePortChange(&db.PortChange{
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "opened",
				Domain:     p.Domain,
				IP:         p.IP,
				Port:       p.Port,
				Protocol:   p.Protocol,
				Service:    p.Service,
			})
		}
	}

	return newLive, webChanged, portOpened, portClosed, svcChanged
}

// ──────────────────────────────────────────
// Dashboard
// ──────────────────────────────────────────

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	now := time.Now()
	since24h := now.Add(-24 * time.Hour)

	var (
		jobsRunningScans int64
		jobsRunningTasks int64
		jobsSuccess24h   int64
		jobsFailed24h    int64
		newSub24h        int64
		newPorts24h      int64
		newVulns24h      int64
		avgDuration      float64
	)

	// Count running scan jobs
	s.db.DB.Model(&db.ScanJob{}).
		Where("status IN ?", []string{"running", "pending"}).
		Count(&jobsRunningScans)
	s.db.DB.Model(&db.MonitorTask{}).
		Where("status IN ?", []string{"running", "pending"}).
		Count(&jobsRunningTasks)

	// Count success/failed in 24h (scan_jobs + monitor_runs)
	var scanSuccess, scanFailed int64
	s.db.DB.Model(&db.ScanJob{}).
		Where("status = ? AND finished_at >= ?", "success", since24h).
		Count(&scanSuccess)
	s.db.DB.Model(&db.ScanJob{}).
		Where("status = ? AND finished_at >= ?", "failed", since24h).
		Count(&scanFailed)
	var monSuccess, monFailed int64
	s.db.DB.Model(&db.MonitorRun{}).
		Where("status = ? AND COALESCE(finished_at, updated_at) >= ?", "success", since24h).
		Count(&monSuccess)
	s.db.DB.Model(&db.MonitorRun{}).
		Where("status = ? AND COALESCE(finished_at, updated_at) >= ?", "failed", since24h).
		Count(&monFailed)
	jobsSuccess24h = scanSuccess + monSuccess
	jobsFailed24h = scanFailed + monFailed

	s.db.DB.Model(&db.Asset{}).Where("created_at >= ?", since24h).Count(&newSub24h)
	s.db.DB.Model(&db.Port{}).Where("created_at >= ?", since24h).Count(&newPorts24h)
	s.db.DB.Model(&db.Vulnerability{}).Where("created_at >= ?", since24h).Count(&newVulns24h)
	s.db.DB.Model(&db.ScanJob{}).
		Select("COALESCE(AVG(duration_sec), 0)").
		Where("status = ? AND finished_at >= ?", "success", since24h).
		Scan(&avgDuration)

	trend := make([]trendPointResponse, 0, 7)
	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
		dayEnd := dayStart.Add(24 * time.Hour)

		var subCount, portCount, vulnCount int64
		s.db.DB.Model(&db.Asset{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&subCount)
		s.db.DB.Model(&db.Port{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&portCount)
		s.db.DB.Model(&db.Vulnerability{}).Where("created_at >= ? AND created_at < ?", dayStart, dayEnd).Count(&vulnCount)

		trend = append(trend, trendPointResponse{
			Date:            dayStart.Format("2006-01-02"),
			Subdomains:      int(subCount),
			Ports:           int(portCount),
			Vulnerabilities: int(vulnCount),
		})
	}

	resp := dashboardResponse{
		Summary: dashboardSummaryResponse{
			JobsRunning:           int(jobsRunningScans + jobsRunningTasks),
			JobsSuccess24h:        int(jobsSuccess24h),
			JobsFailed24h:         int(jobsFailed24h),
			NewSubdomains24h:      int(newSub24h),
			NewPorts24h:           int(newPorts24h),
			NewVulns24h:           int(newVulns24h),
			ScanDurationAvgSec24h: int(avgDuration),
		},
		Trend: trend,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ──────────────────────────────────────────
// Assets / Ports / Vulns (unchanged logic)
// ──────────────────────────────────────────

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var assets []db.Asset
	query := s.db.DB.Order("created_at desc").Limit(maxListRows)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		query = query.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}

	if err := query.Find(&assets).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]assetResponse, 0, len(assets))
	for _, a := range assets {
		resp = append(resp, assetResponse{
			ID:           int(a.ID),
			Domain:       a.Domain,
			URL:          a.URL,
			IP:           a.IP,
			StatusCode:   a.StatusCode,
			Title:        a.Title,
			Technologies: decodeJSONBStrings(a.Technologies),
			CreatedAt:    timeToISO(a.CreatedAt),
			UpdatedAt:    timeToISO(a.UpdatedAt),
			LastSeen:     timeToISO(a.LastSeen),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var ports []db.Port
	query := s.db.DB.Order("created_at desc").Limit(maxListRows)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		query = query.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}

	if err := query.Find(&ports).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]portResponse, 0, len(ports))
	for _, p := range ports {
		resp = append(resp, portResponse{
			ID:        int(p.ID),
			AssetID:   int(p.AssetID),
			Domain:    p.Domain,
			IP:        p.IP,
			Port:      p.Port,
			Protocol:  p.Protocol,
			Service:   p.Service,
			Version:   p.Version,
			Banner:    p.Banner,
			LastSeen:  timeToISO(p.LastSeen),
			UpdatedAt: timeToISO(p.UpdatedAt),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var vulns []db.Vulnerability
	query := s.db.DB.Order("created_at desc").Limit(maxListRows)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		query = query.Where(
			"root_domain = ? OR domain = ? OR domain LIKE ? OR host = ? OR host LIKE ?",
			rd, rd, pattern, rd, pattern,
		)
	}
	if sev := strings.TrimSpace(r.URL.Query().Get("severity")); sev != "" {
		query = query.Where("severity = ?", strings.ToLower(sev))
	}

	if err := query.Find(&vulns).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]vulnerabilityResponse, 0, len(vulns))
	for _, v := range vulns {
		matchedAt := strings.TrimSpace(v.MatchedAt)
		if matchedAt == "" {
			matchedAt = timeToISO(v.CreatedAt)
		}
		resp = append(resp, vulnerabilityResponse{
			ID: int(v.ID), RootDomain: v.RootDomain, Domain: v.Domain, Host: v.Host,
			URL: v.URL, IP: v.IP, TemplateID: v.TemplateID, TemplateName: v.TemplateName,
			Severity: v.Severity, CVE: v.CVE, MatcherName: v.MatcherName,
			Description: v.Description, Reference: v.Reference, MatchedAt: matchedAt,
			Fingerprint: v.Fingerprint, LastSeen: timeToISO(v.LastSeen),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// ──────────────────────────────────────────
// Jobs — persistent scan_jobs table
// ──────────────────────────────────────────

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListJobs(w, r)
	case http.MethodPost:
		s.handleCreateJob(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	rootDomainFilter := normalizeRootDomain(r.URL.Query().Get("root_domain"))

	// Fetch scan jobs from DB
	scanJobs, err := s.db.ListScanJobs(rootDomainFilter, 300)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jobs := make([]jobOverviewResponse, 0, len(scanJobs)+200)
	for _, sj := range scanJobs {
		modules := []string{}
		if sj.Modules != "" {
			modules = strings.Split(sj.Modules, ",")
		}
		started := timeToISO(sj.CreatedAt)
		if sj.StartedAt != nil {
			started = timeToISO(*sj.StartedAt)
		}
		jobs = append(jobs, jobOverviewResponse{
			ID:           sj.JobID,
			RootDomain:   sj.RootDomain,
			Mode:         sj.Mode,
			Modules:      modules,
			Status:       normalizeHealthStatus(sj.Status),
			StartedAt:    started,
			FinishedAt:   timePtrToISO(sj.FinishedAt),
			DurationSec:  sj.DurationSec,
			ErrorMessage: sj.ErrorMessage,
			SubdomainCnt: sj.SubdomainCnt,
			PortCnt:      sj.PortCnt,
			VulnCnt:      sj.VulnCnt,
		})
	}

	// Also include monitor tasks/runs
	var tasks []db.MonitorTask
	taskQuery := s.db.DB.Order("created_at desc").Limit(200)
	if rootDomainFilter != "" {
		taskQuery = taskQuery.Where("root_domain = ?", rootDomainFilter)
	}
	if err := taskQuery.Find(&tasks).Error; err == nil {
		for _, t := range tasks {
			started := timeToISO(t.CreatedAt)
			if t.StartedAt != nil {
				started = timeToISO(*t.StartedAt)
			}
			finished := timePtrToISO(t.FinishedAt)
			duration := 0
			if t.StartedAt != nil && t.FinishedAt != nil {
				if d := t.FinishedAt.Sub(*t.StartedAt); d > 0 {
					duration = int(d.Seconds())
				}
			}
			jobs = append(jobs, jobOverviewResponse{
				ID: fmt.Sprintf("task-%d", t.ID), RootDomain: t.RootDomain, Mode: "monitor",
				Modules: []string{"subs", "ports", "monitor"}, Status: normalizeHealthStatus(t.Status),
				StartedAt: started, FinishedAt: finished, DurationSec: duration,
				ErrorMessage: strings.TrimSpace(t.LastError),
			})
		}
	}

	sort.SliceStable(jobs, func(i, j int) bool {
		return parseTimeBestEffort(jobs[i].StartedAt).After(parseTimeBestEffort(jobs[j].StartedAt))
	})
	if len(jobs) > 500 {
		jobs = jobs[:500]
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req createJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	rootDomain := normalizeRootDomain(req.Domain)
	if rootDomain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}

	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "scan"
	}
	if mode != "scan" && mode != "monitor" {
		writeError(w, http.StatusBadRequest, "mode must be scan or monitor")
		return
	}

	modules := sanitizeModules(req.Modules)
	if len(modules) == 0 {
		if mode == "monitor" {
			modules = []string{"subs", "ports", "monitor"}
		} else {
			modules = []string{"subs", "ports", "httpx"}
			if req.EnableNuclei {
				modules = append(modules, "nuclei")
			}
			if req.ActiveSubs {
				modules = append(modules, "dnsx_bruteforce")
			}
		}
	}

	now := time.Now().UTC()
	jobID := fmt.Sprintf("scan-%d", now.UnixNano())
	if mode == "monitor" {
		jobID = fmt.Sprintf("mon-%d", now.UnixNano())
	}

	if mode == "monitor" {
		if err := s.db.EnableMonitorTarget(rootDomain, defaultMonitorIntervalSec, 3); err != nil {
			writeJSON(w, http.StatusOK, jobOverviewResponse{
				ID: jobID, RootDomain: rootDomain, Mode: mode, Modules: modules,
				Status: "error", StartedAt: now.Format(time.RFC3339), ErrorMessage: err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, jobOverviewResponse{
			ID: jobID, RootDomain: rootDomain, Mode: mode, Modules: modules,
			Status: "pending", StartedAt: now.Format(time.RFC3339),
		})
		return
	}

	// Persist scan job to DB
	scanJob := db.ScanJob{
		JobID:      jobID,
		RootDomain: rootDomain,
		Mode:       mode,
		Modules:    strings.Join(modules, ","),
		Status:     "pending",
	}
	if err := s.db.CreateScanJob(&scanJob); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scan job: "+err.Error())
		return
	}

	if !req.DryRun {
		go s.runScanAsync(jobID, rootDomain, modules, req.EnableNuclei, req.ActiveSubs, req.DictSize, req.DNSResolvers)
	}

	writeJSON(w, http.StatusOK, jobOverviewResponse{
		ID: jobID, RootDomain: rootDomain, Mode: mode, Modules: modules,
		Status: "pending", StartedAt: now.Format(time.RFC3339),
	})
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		JobID string `json:"jobId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.JobID == "" {
		writeError(w, http.StatusBadRequest, "jobId is required")
		return
	}

	// Cancel context if scan is running
	s.scanCancelMu.Lock()
	if cancel, ok := s.scanCancels[body.JobID]; ok {
		cancel()
		delete(s.scanCancels, body.JobID)
	}
	s.scanCancelMu.Unlock()

	// Update DB
	_ = s.db.CancelScanJob(body.JobID)

	writeJSON(w, http.StatusOK, map[string]string{"status": "canceled", "jobId": body.JobID})
}

// runScanAsync executes the scan pipeline in a background goroutine.
func (s *Server) runScanAsync(jobID, rootDomain string, modules []string, enableNuclei, activeSubs bool, dictSize int, dnsResolvers string) {
	startTime := time.Now()
	ctx, cancel := context.WithCancel(context.Background())

	s.scanCancelMu.Lock()
	s.scanCancels[jobID] = cancel
	s.scanCancelMu.Unlock()

	defer func() {
		cancel()
		s.scanCancelMu.Lock()
		delete(s.scanCancels, jobID)
		s.scanCancelMu.Unlock()
	}()

	nowStart := startTime
	_ = s.db.UpdateScanJob(jobID, map[string]interface{}{"status": "running", "started_at": nowStart})

	log.Printf("[Scan] Job %s started for %s, modules=%v", jobID, rootDomain, modules)

	hasSubs := containsModule(modules, "subs")
	hasPorts := containsModule(modules, "ports")
	hasHttpx := containsModule(modules, "httpx")
	hasNuclei := enableNuclei || containsModule(modules, "nuclei")
	hasActiveSubs := activeSubs || containsModule(modules, "dnsx_bruteforce")
	hasWitness := containsModule(modules, "witness")

	s.settingsMu.RLock()
	screenshotDir := s.screenshotDir
	if dnsResolvers == "" {
		dnsResolvers = s.settings.Scanner.DNSResolvers
	}
	if dictSize <= 0 {
		dictSize = s.settings.Scanner.DefaultDictSize
	}
	s.settingsMu.RUnlock()

	dictSize = clampDictSize(dictSize)

	var allResults []engine.Result
	var scanErr error

	domains := []string{rootDomain}

	// Check for cancellation
	select {
	case <-ctx.Done():
		s.finishScan(jobID, startTime, nil, fmt.Errorf("canceled"))
		return
	default:
	}

	if hasSubs {
		subResults, subdomains, err := s.collectSubdomains(domains)
		allResults = append(allResults, subResults...)
		if err != nil {
			scanErr = fmt.Errorf("subdomain collection failed: %v", err)
			s.finishScan(jobID, startTime, allResults, scanErr)
			return
		}

		if hasActiveSubs {
			activeResults, activeSubdomains, err := s.expandActiveSubdomains(domains, subdomains, dictSize, dnsResolvers)
			allResults = append(allResults, activeResults...)
			if err != nil {
				log.Printf("[Scan] Job %s active subs warning: %v", jobID, err)
			} else {
				subdomains = mergeUnique(subdomains, activeSubdomains)
			}
		}

		if hasPorts || hasHttpx || len(subdomains) > 0 {
			networkResults, err := s.runNetworkPipeline(subdomains, hasPorts, hasNuclei, hasWitness, screenshotDir)
			allResults = append(allResults, networkResults...)
			if err != nil {
				scanErr = fmt.Errorf("network stage failed: %v", err)
			}
		}
	} else if hasPorts || hasHttpx {
		networkResults, err := s.runNetworkPipeline(domains, hasPorts, hasNuclei, hasWitness, screenshotDir)
		allResults = append(allResults, networkResults...)
		if err != nil {
			scanErr = fmt.Errorf("network stage failed: %v", err)
		}
	}

	s.finishScan(jobID, startTime, allResults, scanErr)
}

func (s *Server) finishScan(jobID string, startTime time.Time, results []engine.Result, scanErr error) {
	duration := int(time.Since(startTime).Seconds())
	dbErr := s.saveResultsToDB(results)

	finalStatus := "success"
	errMsg := ""
	if scanErr != nil {
		finalStatus = "failed"
		errMsg = scanErr.Error()
	} else if dbErr != nil {
		finalStatus = "failed"
		errMsg = "database write error: " + dbErr.Error()
	}

	counts := countResults(results)
	now := time.Now()
	_ = s.db.UpdateScanJob(jobID, map[string]interface{}{
		"status":        finalStatus,
		"error_message": errMsg,
		"duration_sec":  duration,
		"finished_at":   now,
		"subdomain_cnt": counts["subdomains"],
		"port_cnt":      counts["ports"],
		"vuln_cnt":      counts["vulnerabilities"],
	})

	log.Printf("[Scan] Job %s finished: status=%s duration=%ds subs=%d ports=%d vulns=%d",
		jobID, finalStatus, duration, counts["subdomains"], counts["ports"], counts["vulnerabilities"])
}

// ──────────────────────────────────────────
// Scan pipeline helpers
// ──────────────────────────────────────────

func (s *Server) collectSubdomains(rootDomains []string) ([]engine.Result, []string, error) {
	pipeline := engine.NewPipeline()
	isBatch := len(rootDomains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatch))
	pipeline.AddDomainScanner(plugins.NewFindomainPlugin())
	pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())
	results, err := pipeline.Execute(rootDomains)
	subdomains := extractDomains(results)
	log.Printf("[Scan] Passive collection: %d unique subdomains", len(subdomains))
	return results, subdomains, err
}

func (s *Server) expandActiveSubdomains(rootDomains, passiveSubdomains []string, dictSize int, dnsResolvers string) ([]engine.Result, []string, error) {
	var allResults []engine.Result
	dictPlugin := plugins.NewDictgenPlugin(dictSize)
	dictInput := append(append([]string{}, passiveSubdomains...), rootDomains...)
	dictResults, err := dictPlugin.Execute(dictInput)
	allResults = append(allResults, dictResults...)
	if err != nil {
		return allResults, nil, err
	}
	var words []string
	for _, r := range dictResults {
		if r.Type == "dict_word" {
			if w, ok := r.Data.(string); ok && strings.TrimSpace(w) != "" {
				words = append(words, w)
			}
		}
	}
	if len(words) == 0 {
		return allResults, []string{}, nil
	}
	brutePlugin := plugins.NewDNSXBruteforcePlugin(rootDomains, dnsResolvers)
	bruteResults, err := brutePlugin.Execute(words)
	allResults = append(allResults, bruteResults...)
	if err != nil {
		return allResults, nil, err
	}
	return allResults, extractDomains(bruteResults), nil
}

func (s *Server) runNetworkPipeline(subdomains []string, enablePorts, enableNuclei, enableWitness bool, screenshotDir string) ([]engine.Result, error) {
	pipeline := engine.NewPipeline()
	pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	if enablePorts {
		pipeline.AddPortScanner(plugins.NewNaabuPlugin())
		pipeline.AddPortScanner(plugins.NewNmapPlugin())
	}
	if enableNuclei {
		pipeline.SetVulnScanner(plugins.NewNucleiPlugin())
	}
	if enableWitness {
		pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	}
	return pipeline.ExecuteFromSubdomains(subdomains)
}

func (s *Server) saveResultsToDB(results []engine.Result) error {
	failureCount := 0
	for _, result := range results {
		var err error
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				err = s.db.SaveOrUpdateAsset(map[string]interface{}{"domain": subdomain})
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				err = s.db.SaveOrUpdateAsset(data)
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				err = s.db.SaveOrUpdatePort(data)
			}
		case "vulnerability":
			if data, ok := result.Data.(map[string]interface{}); ok {
				err = s.db.SaveOrUpdateVulnerability(data)
			}
		}
		if err != nil {
			failureCount++
			log.Printf("[Scan][DB] save error (%s): %v", result.Type, err)
		}
	}
	if failureCount > 0 {
		return fmt.Errorf("%d records failed to save", failureCount)
	}
	return nil
}

func extractDomains(results []engine.Result) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, 256)
	for _, r := range results {
		if r.Type != "domain" {
			continue
		}
		d, ok := r.Data.(string)
		if !ok {
			continue
		}
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range b {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func containsModule(modules []string, name string) bool {
	for _, m := range modules {
		if m == name {
			return true
		}
	}
	return false
}

func countResults(results []engine.Result) map[string]int {
	counts := map[string]int{"subdomains": 0, "web_services": 0, "ports": 0, "vulnerabilities": 0}
	for _, r := range results {
		switch r.Type {
		case "domain":
			counts["subdomains"]++
		case "web_service":
			counts["web_services"]++
		case "port_service", "open_port":
			counts["ports"]++
		case "vulnerability":
			counts["vulnerabilities"]++
		}
	}
	return counts
}

// ──────────────────────────────────────────
// Monitor targets/runs/changes API
// ──────────────────────────────────────────

func (s *Server) handleMonitorTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListMonitorTargets(w, r)
	case http.MethodPost:
		s.handleCreateMonitorTarget(w, r)
	case http.MethodDelete:
		s.handleDeleteMonitorTarget(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleListMonitorTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.db.ListMonitorTargets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]monitorTargetResponse, 0, len(targets))
	for _, t := range targets {
		resp = append(resp, monitorTargetResponse{
			ID: int(t.ID), RootDomain: t.RootDomain, Enabled: t.Enabled,
			BaselineDone: t.BaselineDone, LastRunAt: timePtrToISO(t.LastRunAt),
			CreatedAt: timeToISO(t.CreatedAt), UpdatedAt: timeToISO(t.UpdatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCreateMonitorTarget(w http.ResponseWriter, r *http.Request) {
	var req createMonitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	domain := normalizeRootDomain(req.Domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	intervalSec := req.IntervalSec
	if intervalSec <= 0 {
		intervalSec = defaultMonitorIntervalSec
	}
	if err := s.db.EnableMonitorTarget(domain, intervalSec, 3); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "domain": domain, "intervalSec": intervalSec})
}

func (s *Server) handleDeleteMonitorTarget(w http.ResponseWriter, r *http.Request) {
	domain := normalizeRootDomain(r.URL.Query().Get("domain"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	switch action {
	case "stop":
		if err := s.db.StopMonitorTarget(domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "domain": domain})
	case "delete":
		if err := s.db.DeleteMonitorDataByRootDomain(domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "domain": domain})
	default:
		// Default: toggle stop
		if err := s.db.StopMonitorTarget(domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "domain": domain})
	}
}

func (s *Server) handleMonitorRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var runs []db.MonitorRun
	query := s.db.DB.Order("started_at desc").Limit(500)
	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		query = query.Where("root_domain = ?", rd)
	}
	if err := query.Find(&runs).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]monitorRunResponse, 0, len(runs))
	for _, run := range runs {
		resp = append(resp, monitorRunResponse{
			ID: int(run.ID), RootDomain: run.RootDomain, Status: normalizeHealthStatus(run.Status),
			StartedAt: timeToISO(run.StartedAt), FinishedAt: timePtrToISO(run.FinishedAt),
			DurationSec: run.DurationSec, ErrorMessage: strings.TrimSpace(run.ErrorMessage),
			NewLiveCount: run.NewLiveCount, WebChanged: run.WebChanged,
			PortOpened: run.PortOpened, PortClosed: run.PortClosed, ServiceChange: run.ServiceChange,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMonitorChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rd := normalizeRootDomain(r.URL.Query().Get("root_domain"))
	sorted := make([]monitorChangeSortItem, 0, 400)

	var assetChanges []db.AssetChange
	aq := s.db.DB.Order("created_at desc").Limit(200)
	if rd != "" {
		aq = aq.Where("root_domain = ?", rd)
	}
	if err := aq.Find(&assetChanges).Error; err == nil {
		for _, ac := range assetChanges {
			sorted = append(sorted, monitorChangeSortItem{
				createdAt: ac.CreatedAt,
				item: monitorChangeResponse{
					RunID: int(ac.RunID), RootDomain: ac.RootDomain, ChangeType: ac.ChangeType,
					Domain: ac.Domain, StatusCode: ac.StatusCode, Title: ac.Title,
					CreatedAt: timeToISO(ac.CreatedAt),
				},
			})
		}
	}

	var portChanges []db.PortChange
	pq := s.db.DB.Order("created_at desc").Limit(200)
	if rd != "" {
		pq = pq.Where("root_domain = ?", rd)
	}
	if err := pq.Find(&portChanges).Error; err == nil {
		for _, pc := range portChanges {
			sorted = append(sorted, monitorChangeSortItem{
				createdAt: pc.CreatedAt,
				item: monitorChangeResponse{
					RunID: int(pc.RunID), RootDomain: pc.RootDomain, ChangeType: pc.ChangeType,
					Domain: pc.Domain, IP: pc.IP, Port: pc.Port, CreatedAt: timeToISO(pc.CreatedAt),
				},
			})
		}
	}

	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].createdAt.After(sorted[j].createdAt) })
	resp := make([]monitorChangeResponse, 0, len(sorted))
	for _, item := range sorted {
		resp = append(resp, item.item)
	}
	if len(resp) > 500 {
		resp = resp[:500]
	}
	writeJSON(w, http.StatusOK, resp)
}

// ──────────────────────────────────────────
// Screenshots
// ──────────────────────────────────────────

func (s *Server) handleScreenshotDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domains, err := plugins.ListScreenshotDomains(s.screenshotDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []screenshotDomainResponse{})
		return
	}
	resp := make([]screenshotDomainResponse, 0, len(domains))
	for _, rootDomain := range domains {
		domainDir := filepath.Join(s.screenshotDir, rootDomain)
		ssDir := filepath.Join(domainDir, "screenshots")
		count := 0
		if entries, err := os.ReadDir(ssDir); err == nil {
			for _, e := range entries {
				if !e.IsDir() && (strings.HasSuffix(e.Name(), ".png") || strings.HasSuffix(e.Name(), ".jpg")) {
					count++
				}
			}
		}
		dbPath := filepath.Join(domainDir, "gowitness.sqlite3")
		resp = append(resp, screenshotDomainResponse{
			RootDomain:      rootDomain,
			ScreenshotCount: count,
			ScreenshotDir:   ssDir,
			DatabasePath:    dbPath,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pathParts := strings.TrimPrefix(r.URL.Path, "/api/screenshots/")
	rootDomain := normalizeRootDomain(pathParts)
	if rootDomain == "" {
		rootDomain = normalizeRootDomain(r.URL.Query().Get("root_domain"))
	}
	if rootDomain == "" {
		writeJSON(w, http.StatusOK, []screenshotItemResponse{})
		return
	}

	items, err := plugins.ListScreenshots(s.screenshotDir, rootDomain)
	if err != nil {
		writeJSON(w, http.StatusOK, []screenshotItemResponse{})
		return
	}
	resp := make([]screenshotItemResponse, 0, len(items))
	for i, item := range items {
		resp = append(resp, screenshotItemResponse{
			ID:           i + 1,
			URL:          item.URL,
			Filename:     item.Filename,
			Title:        item.Title,
			StatusCode:   item.StatusCode,
			RootDomain:   rootDomain,
			ThumbnailURL: fmt.Sprintf("/api/screenshots/file/%s/%s", rootDomain, url.PathEscape(item.Filename)),
			FullURL:      fmt.Sprintf("/api/screenshots/file/%s/%s", rootDomain, url.PathEscape(item.Filename)),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScreenshotFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pathParts := strings.TrimPrefix(r.URL.Path, "/api/screenshots/file/")
	parts := strings.SplitN(pathParts, "/", 2)
	if len(parts) < 2 {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	rootDomain := normalizeRootDomain(parts[0])
	filename, _ := url.PathUnescape(parts[1])
	if rootDomain == "" || filename == "" {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}
	filePath := filepath.Join(s.screenshotDir, rootDomain, "screenshots", filepath.Base(filename))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	http.ServeFile(w, r, filePath)
}

// ──────────────────────────────────────────
// Settings
// ──────────────────────────────────────────

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleGetSettings(w, r)
	case http.MethodPut, http.MethodPost:
		s.handleUpdateSettings(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s.settingsMu.RLock()
	settings := s.settings
	s.settingsMu.RUnlock()

	resp := systemSettingsResponse{
		Database: databaseSettingsResponse{
			Host: settings.Database.Host, Port: settings.Database.Port,
			User: settings.Database.User, DBName: settings.Database.DBName,
			SSLMode: settings.Database.SSLMode, Connected: s.db.DB != nil,
		},
		Notifications: notificationSettingsResponse{
			DingTalkWebhook: settings.Notifications.DingTalkWebhook,
			DingTalkSecret:  maskSecret(settings.Notifications.DingTalkSecret),
			Enabled:         settings.Notifications.Enabled,
		},
		Scanner: scannerSettingsResponse{
			ScreenshotDir:     settings.Scanner.ScreenshotDir,
			DNSResolvers:      settings.Scanner.DNSResolvers,
			DefaultDictSize:   settings.Scanner.DefaultDictSize,
			DefaultActiveSubs: settings.Scanner.DefaultActiveSubs,
			DefaultNuclei:     settings.Scanner.DefaultNuclei,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var patch settingsPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	s.settingsMu.Lock()
	if p := patch.Notifications; p != nil {
		if p.DingTalkWebhook != nil {
			s.settings.Notifications.DingTalkWebhook = *p.DingTalkWebhook
			os.Setenv("DINGTALK_WEBHOOK", *p.DingTalkWebhook)
		}
		if p.DingTalkSecret != nil {
			s.settings.Notifications.DingTalkSecret = *p.DingTalkSecret
			os.Setenv("DINGTALK_SECRET", *p.DingTalkSecret)
		}
		if p.Enabled != nil {
			s.settings.Notifications.Enabled = *p.Enabled
		}
	}
	if p := patch.Scanner; p != nil {
		if p.ScreenshotDir != nil {
			s.settings.Scanner.ScreenshotDir = *p.ScreenshotDir
			s.screenshotDir = *p.ScreenshotDir
		}
		if p.DNSResolvers != nil {
			s.settings.Scanner.DNSResolvers = *p.DNSResolvers
		}
		if p.DefaultDictSize != nil {
			s.settings.Scanner.DefaultDictSize = *p.DefaultDictSize
		}
		if p.DefaultActiveSubs != nil {
			s.settings.Scanner.DefaultActiveSubs = *p.DefaultActiveSubs
		}
		if p.DefaultNuclei != nil {
			s.settings.Scanner.DefaultNuclei = *p.DefaultNuclei
		}
	}
	s.settingsMu.Unlock()

	s.handleGetSettings(w, r)
}

func (s *Server) handleToolStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tools := []string{"subfinder", "findomain", "bbot", "naabu", "nmap", "httpx", "nuclei", "gowitness", "dnsx", "shosubgo"}
	resp := make([]toolStatusResponse, 0, len(tools))
	for _, name := range tools {
		ts := toolStatusResponse{Name: name}
		if path, err := exec.LookPath(name); err == nil {
			ts.Installed = true
			ts.Path = path
			if out, err := exec.Command(name, "--version").CombinedOutput(); err == nil {
				ver := strings.TrimSpace(string(out))
				if len(ver) > 100 {
					ver = ver[:100]
				}
				ts.Version = ver
			}
		}
		resp = append(resp, ts)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	notifier := plugins.NewDingTalkNotifierFromEnv(true)
	if !notifier.Enabled() {
		writeError(w, http.StatusBadRequest, "DingTalk notification not configured")
		return
	}
	stats := map[string]int{"test": 1}
	if err := notifier.SendReconEnd(true, 0, stats, "This is a test notification from myrecon."); err != nil {
		writeError(w, http.StatusInternalServerError, "send failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "message": "test notification sent"})
}

// ──────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────

func loadRuntimeSettings(screenshotDir string) runtimeSettings {
	port := 5432
	if p := os.Getenv("DB_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	dictSize := 5000
	if d := os.Getenv("DEFAULT_DICT_SIZE"); d != "" {
		if v, err := strconv.Atoi(d); err == nil {
			dictSize = v
		}
	}

	return runtimeSettings{
		Database: runtimeDatabaseSettings{
			Host:    envOrDefault("DB_HOST", "127.0.0.1"),
			Port:    port,
			User:    envOrDefault("DB_USER", "postgres"),
			DBName:  envOrDefault("DB_NAME", "recon"),
			SSLMode: envOrDefault("DB_SSLMODE", "disable"),
		},
		Notifications: runtimeNotificationSettings{
			DingTalkWebhook: os.Getenv("DINGTALK_WEBHOOK"),
			DingTalkSecret:  os.Getenv("DINGTALK_SECRET"),
			Enabled:         os.Getenv("DINGTALK_WEBHOOK") != "",
		},
		Scanner: runtimeScannerSettings{
			ScreenshotDir:     screenshotDir,
			DNSResolvers:      envOrDefault("DNS_RESOLVERS", ""),
			DefaultDictSize:   dictSize,
			DefaultActiveSubs: os.Getenv("DEFAULT_ACTIVE_SUBS") == "true",
			DefaultNuclei:     os.Getenv("DEFAULT_NUCLEI") == "true",
		},
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func normalizeRootDomain(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}
	return s
}

func normalizeHealthStatus(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "ok" || s == "done" || s == "success":
		return "success"
	case s == "fail" || s == "error" || s == "failed":
		return "failed"
	case s == "running":
		return "running"
	case s == "pending":
		return "pending"
	case s == "canceled" || s == "cancelled":
		return "canceled"
	default:
		return s
	}
}

func sanitizeModules(raw []string) []string {
	allowed := map[string]bool{
		"subfinder": true, "findomain": true, "bbot": true, "shosubgo": true,
		"dictgen": true, "dnsx_bruteforce": true,
		"naabu": true, "nmap": true,
		"httpx": true, "gowitness": true, "nuclei": true,
		"subs": true, "ports": true, "monitor": true, "witness": true,
	}
	var out []string
	for _, m := range raw {
		m = strings.ToLower(strings.TrimSpace(m))
		if m != "" && allowed[m] {
			out = append(out, m)
		}
	}
	return out
}

func clampDictSize(n int) int {
	if n <= 0 {
		return 5000
	}
	if n > 100000 {
		return 100000
	}
	return n
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func timeToISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func timePtrToISO(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeToISO(*t)
}

func parseTimeBestEffort(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func matchesRootDomain(domain, rootDomain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	rootDomain = strings.ToLower(strings.TrimSpace(rootDomain))
	return domain == rootDomain || strings.HasSuffix(domain, "."+rootDomain)
}

func decodeJSONBStrings(data db.JSONB) []string {
	if len(data) == 0 {
		return nil
	}
	var items []string
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}
	return items
}
