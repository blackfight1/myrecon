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
	"hunter/internal/plugins"
)

const (
	defaultMonitorIntervalSec = 6 * 3600
	maxListRows               = 5000
)

// Server is the HTTP API server.
type Server struct {
	db            *db.Database
	mux           *http.ServeMux
	screenshotDir string

	settingsMu sync.RWMutex
	settings   runtimeSettings

	jobsMu        sync.RWMutex
	ephemeralJobs []jobOverviewResponse
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
	}
	s.registerRoutes()
	return s
}

// Start starts the HTTP server.
func (s *Server) Start(addr string) error {
	log.Printf("[API] server starting on %s", addr)
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	now := time.Now()
	since24h := now.Add(-24 * time.Hour)

	var (
		jobsRunningTasks int64
		jobsRunningRuns  int64
		jobsSuccess24h   int64
		jobsFailed24h    int64
		newSub24h        int64
		newPorts24h      int64
		newVulns24h      int64
		avgDuration      float64
	)

	s.db.DB.Model(&db.MonitorTask{}).
		Where("status IN ?", []string{"running", "pending"}).
		Count(&jobsRunningTasks)
	s.db.DB.Model(&db.MonitorRun{}).
		Where("status = ? AND finished_at IS NULL", "running").
		Count(&jobsRunningRuns)
	s.db.DB.Model(&db.MonitorRun{}).
		Where("status = ? AND COALESCE(finished_at, updated_at) >= ?", "success", since24h).
		Count(&jobsSuccess24h)
	s.db.DB.Model(&db.MonitorRun{}).
		Where("status = ? AND COALESCE(finished_at, updated_at) >= ?", "failed", since24h).
		Count(&jobsFailed24h)

	s.db.DB.Model(&db.Asset{}).Where("created_at >= ?", since24h).Count(&newSub24h)
	s.db.DB.Model(&db.Port{}).Where("created_at >= ?", since24h).Count(&newPorts24h)
	s.db.DB.Model(&db.Vulnerability{}).Where("created_at >= ?", since24h).Count(&newVulns24h)
	s.db.DB.Model(&db.MonitorRun{}).
		Select("COALESCE(AVG(duration_sec), 0)").
		Where("status = ? AND COALESCE(finished_at, updated_at) >= ?", "success", since24h).
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
			JobsRunning:           int(jobsRunningTasks + jobsRunningRuns),
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
			ID:           int(v.ID),
			RootDomain:   v.RootDomain,
			Domain:       v.Domain,
			Host:         v.Host,
			URL:          v.URL,
			IP:           v.IP,
			TemplateID:   v.TemplateID,
			TemplateName: v.TemplateName,
			Severity:     v.Severity,
			CVE:          v.CVE,
			MatcherName:  v.MatcherName,
			Description:  v.Description,
			Reference:    v.Reference,
			MatchedAt:    matchedAt,
			Fingerprint:  v.Fingerprint,
			LastSeen:     timeToISO(v.LastSeen),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

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

	jobs := make([]jobOverviewResponse, 0, 512)

	s.jobsMu.RLock()
	for _, j := range s.ephemeralJobs {
		if rootDomainFilter != "" && !matchesRootDomain(j.RootDomain, rootDomainFilter) {
			continue
		}
		jobs = append(jobs, j)
	}
	s.jobsMu.RUnlock()

	var tasks []db.MonitorTask
	taskQuery := s.db.DB.Order("created_at desc").Limit(300)
	if rootDomainFilter != "" {
		taskQuery = taskQuery.Where("root_domain = ?", rootDomainFilter)
	}
	if err := taskQuery.Find(&tasks).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
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
			ID:           fmt.Sprintf("task-%d", t.ID),
			RootDomain:   t.RootDomain,
			Mode:         "monitor",
			Modules:      []string{"subs", "ports", "monitor"},
			Status:       normalizeHealthStatus(t.Status),
			StartedAt:    started,
			FinishedAt:   finished,
			DurationSec:  duration,
			ErrorMessage: strings.TrimSpace(t.LastError),
		})
	}

	var runs []db.MonitorRun
	runQuery := s.db.DB.Order("started_at desc").Limit(300)
	if rootDomainFilter != "" {
		runQuery = runQuery.Where("root_domain = ?", rootDomainFilter)
	}
	if err := runQuery.Find(&runs).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, run := range runs {
		jobs = append(jobs, jobOverviewResponse{
			ID:           fmt.Sprintf("run-%d", run.ID),
			RootDomain:   run.RootDomain,
			Mode:         "monitor",
			Modules:      []string{"subs", "ports", "monitor"},
			Status:       normalizeHealthStatus(run.Status),
			StartedAt:    timeToISO(run.StartedAt),
			FinishedAt:   timePtrToISO(run.FinishedAt),
			DurationSec:  run.DurationSec,
			ErrorMessage: strings.TrimSpace(run.ErrorMessage),
		})
	}

	sort.SliceStable(jobs, func(i, j int) bool {
		ti := parseTimeBestEffort(jobs[i].StartedAt)
		tj := parseTimeBestEffort(jobs[j].StartedAt)
		return ti.After(tj)
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
	job := jobOverviewResponse{
		ID:         fmt.Sprintf("api-%d", now.UnixNano()),
		RootDomain: rootDomain,
		Mode:       mode,
		Modules:    modules,
		Status:     "pending",
		StartedAt:  now.Format(time.RFC3339),
	}

	if mode == "monitor" {
		if err := s.db.EnableMonitorTarget(rootDomain, defaultMonitorIntervalSec, 3); err != nil {
			job.Status = "error"
			job.ErrorMessage = err.Error()
			writeJSON(w, http.StatusOK, job)
			return
		}
	}

	s.jobsMu.Lock()
	s.ephemeralJobs = append([]jobOverviewResponse{job}, s.ephemeralJobs...)
	if len(s.ephemeralJobs) > 300 {
		s.ephemeralJobs = s.ephemeralJobs[:300]
	}
	s.jobsMu.Unlock()

	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleMonitorTargets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	targets, err := s.db.ListMonitorTargets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]monitorTargetResponse, 0, len(targets))
	for _, t := range targets {
		resp = append(resp, monitorTargetResponse{
			ID:           int(t.ID),
			RootDomain:   t.RootDomain,
			Enabled:      t.Enabled,
			BaselineDone: t.BaselineDone,
			LastRunAt:    timePtrToISO(t.LastRunAt),
			CreatedAt:    timeToISO(t.CreatedAt),
			UpdatedAt:    timeToISO(t.UpdatedAt),
		})
	}

	writeJSON(w, http.StatusOK, resp)
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
			ID:            int(run.ID),
			RootDomain:    run.RootDomain,
			Status:        normalizeHealthStatus(run.Status),
			StartedAt:     timeToISO(run.StartedAt),
			FinishedAt:    timePtrToISO(run.FinishedAt),
			DurationSec:   run.DurationSec,
			ErrorMessage:  strings.TrimSpace(run.ErrorMessage),
			NewLiveCount:  run.NewLiveCount,
			WebChanged:    run.WebChanged,
			PortOpened:    run.PortOpened,
			PortClosed:    run.PortClosed,
			ServiceChange: run.ServiceChange,
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
					RunID:      int(ac.RunID),
					RootDomain: ac.RootDomain,
					ChangeType: ac.ChangeType,
					Domain:     ac.Domain,
					StatusCode: ac.StatusCode,
					Title:      ac.Title,
					CreatedAt:  timeToISO(ac.CreatedAt),
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
					RunID:      int(pc.RunID),
					RootDomain: pc.RootDomain,
					ChangeType: pc.ChangeType,
					Domain:     pc.Domain,
					IP:         pc.IP,
					Port:       pc.Port,
					CreatedAt:  timeToISO(pc.CreatedAt),
				},
			})
		}
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].createdAt.After(sorted[j].createdAt)
	})

	resp := make([]monitorChangeResponse, 0, len(sorted))
	for _, item := range sorted {
		resp = append(resp, item.item)
	}
	if len(resp) > 500 {
		resp = resp[:500]
	}

	writeJSON(w, http.StatusOK, resp)
}

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
		screenshotDir := filepath.Join(domainDir, "screenshots")
		dbPath := filepath.Join(domainDir, "gowitness.sqlite3")
		resp = append(resp, screenshotDomainResponse{
			RootDomain:      rootDomain,
			ScreenshotCount: countImageFiles(screenshotDir),
			ScreenshotDir:   screenshotDir,
			DatabasePath:    dbPath,
		})
	}

	sort.SliceStable(resp, func(i, j int) bool {
		return resp[i].RootDomain < resp[j].RootDomain
	})

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/screenshots/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "root domain is required")
		return
	}
	if strings.Contains(path, "/") {
		writeError(w, http.StatusBadRequest, "invalid root domain")
		return
	}

	rootDomain, err := url.PathUnescape(path)
	if err != nil || strings.TrimSpace(rootDomain) == "" {
		writeError(w, http.StatusBadRequest, "invalid root domain")
		return
	}

	screenshotPath := filepath.Join(s.screenshotDir, rootDomain, "screenshots")
	entries, err := os.ReadDir(screenshotPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusOK, []screenshotItemResponse{})
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type imageEntry struct {
		name    string
		modTime time.Time
	}
	images := make([]imageEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isImageFile(entry.Name()) {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		images = append(images, imageEntry{name: entry.Name(), modTime: info.ModTime()})
	}

	sort.SliceStable(images, func(i, j int) bool {
		return images[i].modTime.After(images[j].modTime)
	})

	resp := make([]screenshotItemResponse, 0, len(images))
	for idx, item := range images {
		fileEscaped := url.PathEscape(item.name)
		rootEscaped := url.PathEscape(rootDomain)
		fileURL := fmt.Sprintf("/api/screenshots/file/%s/%s", rootEscaped, fileEscaped)
		resp = append(resp, screenshotItemResponse{
			ID:           idx + 1,
			URL:          inferScreenshotURL(item.name, rootDomain),
			Filename:     item.name,
			RootDomain:   rootDomain,
			ThumbnailURL: fileURL,
			FullURL:      fileURL,
			CreatedAt:    item.modTime.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleScreenshotFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/screenshots/file/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusBadRequest, "invalid file path")
		return
	}

	rootDomain, err := url.PathUnescape(parts[0])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid root domain")
		return
	}
	filename, err := url.PathUnescape(parts[1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	if strings.TrimSpace(rootDomain) == "" || strings.TrimSpace(filename) == "" {
		writeError(w, http.StatusBadRequest, "invalid file path")
		return
	}
	if strings.Contains(rootDomain, "..") || strings.ContainsAny(rootDomain, `/\`) {
		writeError(w, http.StatusBadRequest, "invalid root domain")
		return
	}
	if strings.Contains(filename, "..") || strings.ContainsAny(filename, `/\`) {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	baseDir := filepath.Clean(filepath.Join(s.screenshotDir, rootDomain, "screenshots"))
	filePath := filepath.Clean(filepath.Join(baseDir, filename))
	rel, err := filepath.Rel(baseDir, filePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		writeError(w, http.StatusBadRequest, "invalid file path")
		return
	}

	if _, err := os.Stat(filePath); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "file not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	http.ServeFile(w, r, filePath)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.buildSettingsResponse())
	case http.MethodPost:
		s.handleUpdateSettings(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var patch settingsPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	s.settingsMu.Lock()
	if patch.Database != nil {
		if patch.Database.Host != nil {
			s.settings.Database.Host = strings.TrimSpace(*patch.Database.Host)
		}
		if patch.Database.Port != nil && *patch.Database.Port > 0 {
			s.settings.Database.Port = *patch.Database.Port
		}
		if patch.Database.User != nil {
			s.settings.Database.User = strings.TrimSpace(*patch.Database.User)
		}
		if patch.Database.DBName != nil {
			s.settings.Database.DBName = strings.TrimSpace(*patch.Database.DBName)
		}
		if patch.Database.SSLMode != nil {
			s.settings.Database.SSLMode = strings.TrimSpace(*patch.Database.SSLMode)
		}
	}

	if patch.Notifications != nil {
		if patch.Notifications.DingTalkWebhook != nil {
			s.settings.Notifications.DingTalkWebhook = strings.TrimSpace(*patch.Notifications.DingTalkWebhook)
		}
		if patch.Notifications.DingTalkSecret != nil {
			s.settings.Notifications.DingTalkSecret = strings.TrimSpace(*patch.Notifications.DingTalkSecret)
		}
		if patch.Notifications.Enabled != nil {
			s.settings.Notifications.Enabled = *patch.Notifications.Enabled
		} else if s.settings.Notifications.DingTalkWebhook == "" {
			s.settings.Notifications.Enabled = false
		}
	}

	if patch.Scanner != nil {
		if patch.Scanner.ScreenshotDir != nil {
			newDir := strings.TrimSpace(*patch.Scanner.ScreenshotDir)
			if newDir != "" {
				s.settings.Scanner.ScreenshotDir = newDir
				s.screenshotDir = newDir
			}
		}
		if patch.Scanner.DNSResolvers != nil {
			s.settings.Scanner.DNSResolvers = strings.TrimSpace(*patch.Scanner.DNSResolvers)
		}
		if patch.Scanner.DefaultDictSize != nil {
			s.settings.Scanner.DefaultDictSize = clampDictSize(*patch.Scanner.DefaultDictSize)
		}
		if patch.Scanner.DefaultActiveSubs != nil {
			s.settings.Scanner.DefaultActiveSubs = *patch.Scanner.DefaultActiveSubs
		}
		if patch.Scanner.DefaultNuclei != nil {
			s.settings.Scanner.DefaultNuclei = *patch.Scanner.DefaultNuclei
		}
	}

	// Keep runtime env in sync for the notifier helper.
	_ = os.Setenv("DINGTALK_WEBHOOK", s.settings.Notifications.DingTalkWebhook)
	_ = os.Setenv("DINGTALK_SECRET", s.settings.Notifications.DingTalkSecret)
	s.settingsMu.Unlock()

	writeJSON(w, http.StatusOK, s.buildSettingsResponse())
}

func (s *Server) handleToolStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, collectToolStatus())
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.settingsMu.RLock()
	enabled := s.settings.Notifications.Enabled
	webhook := s.settings.Notifications.DingTalkWebhook
	secret := s.settings.Notifications.DingTalkSecret
	s.settingsMu.RUnlock()

	if strings.TrimSpace(webhook) == "" || !enabled {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": "DingTalk notification is disabled or webhook is empty",
		})
		return
	}

	_ = os.Setenv("DINGTALK_WEBHOOK", webhook)
	_ = os.Setenv("DINGTALK_SECRET", secret)

	notifier := plugins.NewDingTalkNotifierFromEnv(true)
	if !notifier.Enabled() {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": "DingTalk webhook is not configured",
		})
		return
	}

	err := notifier.SendReconStart(1, []string{"api-test"}, true)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("failed to send test notification: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "test notification sent successfully",
	})
}

func (s *Server) buildSettingsResponse() systemSettingsResponse {
	s.settingsMu.RLock()
	current := s.settings
	s.settingsMu.RUnlock()

	return systemSettingsResponse{
		Database: databaseSettingsResponse{
			Host:      current.Database.Host,
			Port:      current.Database.Port,
			User:      current.Database.User,
			DBName:    current.Database.DBName,
			SSLMode:   current.Database.SSLMode,
			Connected: s.isDatabaseConnected(),
		},
		Notifications: notificationSettingsResponse{
			DingTalkWebhook: current.Notifications.DingTalkWebhook,
			DingTalkSecret:  current.Notifications.DingTalkSecret,
			Enabled:         current.Notifications.Enabled,
		},
		Scanner: scannerSettingsResponse{
			ScreenshotDir:     current.Scanner.ScreenshotDir,
			DNSResolvers:      current.Scanner.DNSResolvers,
			DefaultDictSize:   current.Scanner.DefaultDictSize,
			DefaultActiveSubs: current.Scanner.DefaultActiveSubs,
			DefaultNuclei:     current.Scanner.DefaultNuclei,
		},
		Tools: collectToolStatus(),
	}
}

func (s *Server) isDatabaseConnected() bool {
	if s.db == nil || s.db.DB == nil {
		return false
	}
	sqlDB, err := s.db.DB.DB()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return sqlDB.PingContext(ctx) == nil
}

func collectToolStatus() []toolStatusResponse {
	tools := []string{
		"subfinder",
		"findomain",
		"bbot",
		"shosubgo",
		"dictgen",
		"dnsx",
		"httpx",
		"naabu",
		"nmap",
		"gowitness",
		"nuclei",
	}

	out := make([]toolStatusResponse, 0, len(tools))
	for _, name := range tools {
		if name == "dictgen" {
			out = append(out, toolStatusResponse{
				Name:      name,
				Installed: true,
				Version:   "builtin",
				Path:      "internal plugin",
			})
			continue
		}
		out = append(out, checkTool(name))
	}
	return out
}

func checkTool(name string) toolStatusResponse {
	path, err := exec.LookPath(name)
	if err != nil {
		return toolStatusResponse{
			Name:      name,
			Installed: false,
		}
	}

	version := detectToolVersion(name)
	return toolStatusResponse{
		Name:      name,
		Installed: true,
		Version:   version,
		Path:      path,
	}
}

func detectToolVersion(name string) string {
	candidates := [][]string{
		{"--version"},
		{"-version"},
		{"version"},
		{"-v"},
	}

	for _, args := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, name, args...)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			continue
		}

		line := strings.TrimSpace(string(output))
		if idx := strings.Index(line, "\n"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 120 {
			line = line[:120]
		}
		return line
	}

	return ""
}

func loadRuntimeSettings(screenshotDir string) runtimeSettings {
	if strings.TrimSpace(screenshotDir) == "" {
		screenshotDir = "screenshots"
	}

	webhook := strings.TrimSpace(os.Getenv("DINGTALK_WEBHOOK"))
	enabled := parseEnvBool("DINGTALK_ENABLED", webhook != "")

	return runtimeSettings{
		Database: runtimeDatabaseSettings{
			Host:    getenvDefault("DB_HOST", "localhost"),
			Port:    getenvIntDefault("DB_PORT", 5432),
			User:    getenvDefault("DB_USER", "hunter"),
			DBName:  getenvDefault("DB_NAME", "hunter"),
			SSLMode: getenvDefault("DB_SSLMODE", "disable"),
		},
		Notifications: runtimeNotificationSettings{
			DingTalkWebhook: webhook,
			DingTalkSecret:  strings.TrimSpace(os.Getenv("DINGTALK_SECRET")),
			Enabled:         enabled,
		},
		Scanner: runtimeScannerSettings{
			ScreenshotDir:     screenshotDir,
			DNSResolvers:      strings.TrimSpace(os.Getenv("DNS_RESOLVERS")),
			DefaultDictSize:   clampDictSize(getenvIntDefault("DEFAULT_DICT_SIZE", 1500)),
			DefaultActiveSubs: parseEnvBool("DEFAULT_ACTIVE_SUBS", false),
			DefaultNuclei:     parseEnvBool("DEFAULT_NUCLEI", false),
		},
	}
}

func normalizeRootDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "*.")
	v = strings.TrimSuffix(v, ".")
	return v
}

func sanitizeModules(in []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(in))
	for _, item := range in {
		v := strings.TrimSpace(strings.ToLower(item))
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeHealthStatus(status string) string {
	s := strings.TrimSpace(strings.ToLower(status))
	switch s {
	case "ok", "success", "done", "completed":
		return "ok"
	case "error", "failed", "fail", "canceled", "cancelled":
		return "error"
	case "running":
		return "running"
	case "pending", "queued", "queue":
		return "pending"
	default:
		if strings.Contains(s, "run") {
			return "running"
		}
		if strings.Contains(s, "success") || strings.Contains(s, "ok") || strings.Contains(s, "done") {
			return "ok"
		}
		if strings.Contains(s, "fail") || strings.Contains(s, "error") || strings.Contains(s, "cancel") {
			return "error"
		}
		if strings.Contains(s, "pend") || strings.Contains(s, "queue") {
			return "pending"
		}
		return "unknown"
	}
}

func decodeJSONBStrings(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	var generic []interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return []string{}
	}
	out := make([]string, 0, len(generic))
	for _, item := range generic {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func timeToISO(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func timePtrToISO(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTimeBestEffort(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
		return t
	}
	return time.Time{}
}

func matchesRootDomain(candidate, root string) bool {
	candidate = normalizeRootDomain(candidate)
	root = normalizeRootDomain(root)
	if candidate == "" || root == "" {
		return false
	}
	return candidate == root || strings.HasSuffix(candidate, "."+root)
}

func isImageFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png", ".jpg", ".jpeg", ".webp":
		return true
	default:
		return false
	}
}

func countImageFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if isImageFile(entry.Name()) {
			total++
		}
	}
	return total
}

func inferScreenshotURL(filename, rootDomain string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	if decoded, err := url.QueryUnescape(name); err == nil {
		decoded = strings.TrimSpace(decoded)
		if strings.HasPrefix(decoded, "http://") || strings.HasPrefix(decoded, "https://") {
			return decoded
		}
	}

	if strings.HasPrefix(name, "http___") {
		guess := strings.Replace(name, "http___", "http://", 1)
		guess = strings.ReplaceAll(guess, "_", ".")
		return guess
	}
	if strings.HasPrefix(name, "https___") {
		guess := strings.Replace(name, "https___", "https://", 1)
		guess = strings.ReplaceAll(guess, "_", ".")
		return guess
	}
	if strings.HasPrefix(name, "http://") || strings.HasPrefix(name, "https://") {
		return name
	}

	if rootDomain == "" {
		return filename
	}
	return "https://" + rootDomain
}

func getenvDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getenvIntDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func parseEnvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
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
