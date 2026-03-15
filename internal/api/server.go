package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"

	"gorm.io/gorm"
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

	corsAllowAll bool
	corsOrigins  map[string]bool

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
	ProjectID    string   `json:"projectId,omitempty"`
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
	ProjectID    string   `json:"projectId"`
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

type pagedAssetsResponse struct {
	Items    []assetResponse `json:"items"`
	Page     int             `json:"page"`
	PageSize int             `json:"pageSize"`
	Total    int64           `json:"total"`
}

type pagedPortsResponse struct {
	Items    []portResponse `json:"items"`
	Page     int            `json:"page"`
	PageSize int            `json:"pageSize"`
	Total    int64          `json:"total"`
}

type pagedVulnsResponse struct {
	Items    []vulnerabilityResponse `json:"items"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"pageSize"`
	Total    int64                   `json:"total"`
}

type pagedJobsResponse struct {
	Items    []jobOverviewResponse `json:"items"`
	Page     int                   `json:"page"`
	PageSize int                   `json:"pageSize"`
	Total    int64                 `json:"total"`
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
	ID               int    `json:"id"`
	RootDomain       string `json:"rootDomain,omitempty"`
	Domain           string `json:"domain,omitempty"`
	Host             string `json:"host,omitempty"`
	URL              string `json:"url,omitempty"`
	IP               string `json:"ip,omitempty"`
	TemplateID       string `json:"templateId"`
	TemplateName     string `json:"templateName,omitempty"`
	Severity         string `json:"severity,omitempty"`
	CVE              string `json:"cve,omitempty"`
	MatcherName      string `json:"matcherName,omitempty"`
	Description      string `json:"description,omitempty"`
	Reference        string `json:"reference,omitempty"`
	MatchedAt        string `json:"matchedAt"`
	Fingerprint      string `json:"fingerprint"`
	Status           string `json:"status,omitempty"`
	Assignee         string `json:"assignee,omitempty"`
	TicketRef        string `json:"ticketRef,omitempty"`
	DueAt            string `json:"dueAt,omitempty"`
	FixedAt          string `json:"fixedAt,omitempty"`
	VerifiedAt       string `json:"verifiedAt,omitempty"`
	ReopenCount      int    `json:"reopenCount,omitempty"`
	LastTransitionAt string `json:"lastTransitionAt,omitempty"`
	LastSeen         string `json:"lastSeen,omitempty"`
}

type monitorTargetResponse struct {
	ID           int    `json:"id"`
	ProjectID    string `json:"projectId,omitempty"`
	RootDomain   string `json:"rootDomain"`
	Enabled      bool   `json:"enabled"`
	BaselineDone bool   `json:"baselineDone"`
	LastRunAt    string `json:"lastRunAt,omitempty"`
	CreatedAt    string `json:"createdAt,omitempty"`
	UpdatedAt    string `json:"updatedAt,omitempty"`
}

type monitorRunResponse struct {
	ID            int    `json:"id"`
	ProjectID     string `json:"projectId,omitempty"`
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
	ProjectID  string `json:"projectId,omitempty"`
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
	ProjectID       string `json:"projectId,omitempty"`
	RootDomain      string `json:"rootDomain"`
	ScreenshotCount int    `json:"screenshotCount"`
	ScreenshotDir   string `json:"screenshotDir"`
	DatabasePath    string `json:"databasePath"`
}

type screenshotItemResponse struct {
	ID           int    `json:"id"`
	ProjectID    string `json:"projectId,omitempty"`
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

type settingsPatchRequest struct {
	Database *databaseSettingsPatch `json:"database"`
	Scanner  *scannerSettingsPatch  `json:"scanner"`
}

type databaseSettingsPatch struct {
	Host    *string `json:"host"`
	Port    *int    `json:"port"`
	User    *string `json:"user"`
	DBName  *string `json:"dbname"`
	SSLMode *string `json:"sslmode"`
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
	ProjectID   string `json:"projectId"`
	Domain      string `json:"domain"`
	IntervalSec int    `json:"intervalSec"`
}

type projectResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Tags        []string `json:"tags"`
	Archived    bool     `json:"archived"`
	RootDomains []string `json:"rootDomains"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
	LastScanAt  string   `json:"lastScanAt,omitempty"`
}

type projectUpsertRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
	RootDomains []string `json:"rootDomains"`
	Archived    *bool    `json:"archived"`
}

type vulnStatusPatchRequest struct {
	VulnID    int    `json:"vulnId"`
	ProjectID string `json:"projectId"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Actor     string `json:"actor"`
	Assignee  string `json:"assignee"`
	TicketRef string `json:"ticketRef"`
}

type vulnEventResponse struct {
	ID         int    `json:"id"`
	ProjectID  string `json:"projectId"`
	VulnID     int    `json:"vulnId"`
	Action     string `json:"action"`
	FromStatus string `json:"fromStatus"`
	ToStatus   string `json:"toStatus"`
	Actor      string `json:"actor"`
	Reason     string `json:"reason"`
	CreatedAt  string `json:"createdAt"`
}

type edgeResponse struct {
	SrcType  string `json:"srcType"`
	SrcID    string `json:"srcId"`
	DstType  string `json:"dstType"`
	DstID    string `json:"dstId"`
	Relation string `json:"relation"`
}

// NewServer creates a new API server.
func NewServer(database *db.Database, screenshotDir string) *Server {
	if strings.TrimSpace(screenshotDir) == "" {
		screenshotDir = "screenshots"
	}
	ensureCommonToolPaths()
	corsAllowAll, corsOrigins := parseCORSOrigins()

	s := &Server{
		db:            database,
		mux:           http.NewServeMux(),
		screenshotDir: screenshotDir,
		corsAllowAll:  corsAllowAll,
		corsOrigins:   corsOrigins,
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
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowed := origin == ""
		if s.corsAllowAll {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			allowed = true
		} else if origin != "" && s.corsOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			allowed = true
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Authorization, X-Actor")
		if r.Method == http.MethodOptions {
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		if origin != "" && !allowed {
			writeError(w, http.StatusForbidden, "origin not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/projects", s.handleProjects)
	s.mux.HandleFunc("/api/dashboard/summary", s.handleDashboard)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/jobs/cancel", s.handleCancelJob)
	s.mux.HandleFunc("/api/assets/detail", s.handleAssetDetail)
	s.mux.HandleFunc("/api/assets", s.handleAssets)
	s.mux.HandleFunc("/api/ports", s.handlePorts)
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	s.mux.HandleFunc("/api/vulns/bulk-status", s.handleBulkVulnStatus)
	s.mux.HandleFunc("/api/vulns/status", s.handlePatchVulnStatus)
	s.mux.HandleFunc("/api/vulns/events", s.handleVulnEvents)
	s.mux.HandleFunc("/api/graph/relations", s.handleRelations)
	s.mux.HandleFunc("/api/monitor/targets", s.handleMonitorTargets)
	s.mux.HandleFunc("/api/monitor/runs", s.handleMonitorRuns)
	s.mux.HandleFunc("/api/monitor/changes", s.handleMonitorChanges)
	s.mux.HandleFunc("/api/screenshots/domains", s.handleScreenshotDomains)
	s.mux.HandleFunc("/api/screenshots/file/", s.handleScreenshotFile)
	s.mux.HandleFunc("/api/screenshots/", s.handleScreenshots)
	s.mux.HandleFunc("/api/search", s.handleGlobalSearch)
	s.mux.HandleFunc("/api/bulk/assets/delete", s.handleBulkDeleteAssets)
	s.mux.HandleFunc("/api/settings", s.handleSettings)
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

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		var projects []db.Project
		if err := s.db.DB.Preload("Scopes", "enabled = ?", true).Where("archived = ?", false).Order("created_at desc").Find(&projects).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp := make([]projectResponse, 0, len(projects))
		for _, p := range projects {
			rootDomains := make([]string, 0, len(p.Scopes))
			for _, sc := range p.Scopes {
				rootDomains = append(rootDomains, sc.RootDomain)
			}
			sort.Strings(rootDomains)
			resp = append(resp, projectResponse{
				ID:          p.ID,
				Name:        p.Name,
				Description: p.Description,
				Owner:       p.Owner,
				Tags:        decodeJSONBStrings(p.Tags),
				Archived:    p.Archived,
				RootDomains: rootDomains,
				CreatedAt:   timeToISO(p.CreatedAt),
				UpdatedAt:   timeToISO(p.UpdatedAt),
				LastScanAt:  timePtrToISO(p.LastScanAt),
			})
		}
		writeJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req projectUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "name is required")
			return
		}
		rootDomains := normalizeRootDomains(req.RootDomains)
		if len(rootDomains) == 0 {
			writeError(w, http.StatusBadRequest, "at least one root domain is required")
			return
		}
		id := strings.TrimSpace(req.ID)
		if id == "" {
			id = fmt.Sprintf("project_%d", time.Now().UnixNano())
		}
		tagsJSON, _ := json.Marshal(dedupTrimmed(req.Tags))
		project := db.Project{
			ID:          id,
			Name:        req.Name,
			Description: strings.TrimSpace(req.Description),
			Owner:       strings.TrimSpace(req.Owner),
			Tags:        tagsJSON,
			Archived:    false,
		}
		err := s.db.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.Create(&project).Error; err != nil {
				return err
			}
			for _, rd := range rootDomains {
				sc := db.ProjectScope{
					ProjectID:  id,
					RootDomain: rd,
					Enabled:    true,
				}
				if err := tx.Create(&sc).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeAudit(id, actorFromRequest(r), "project_create", "project", id, map[string]interface{}{
			"name": req.Name, "rootDomains": rootDomains,
		}, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "id": id})
	case http.MethodPut:
		var req projectUpsertRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		id := strings.TrimSpace(req.ID)
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		updates := map[string]interface{}{}
		if name := strings.TrimSpace(req.Name); name != "" {
			updates["name"] = name
		}
		if req.Description != "" {
			updates["description"] = strings.TrimSpace(req.Description)
		}
		if req.Owner != "" {
			updates["owner"] = strings.TrimSpace(req.Owner)
		}
		if req.Archived != nil {
			updates["archived"] = *req.Archived
		}
		if req.Tags != nil {
			tagsJSON, _ := json.Marshal(dedupTrimmed(req.Tags))
			updates["tags"] = tagsJSON
		}
		rootDomains := normalizeRootDomains(req.RootDomains)
		err := s.db.DB.Transaction(func(tx *gorm.DB) error {
			if len(updates) > 0 {
				if err := tx.Model(&db.Project{}).Where("id = ?", id).Updates(updates).Error; err != nil {
					return err
				}
			}
			if req.Archived != nil && *req.Archived {
				if err := tx.Model(&db.MonitorTarget{}).Where("project_id = ?", id).Update("enabled", false).Error; err != nil {
					return err
				}
				now := time.Now()
				if err := tx.Model(&db.MonitorTask{}).
					Where("project_id = ? AND status IN ?", id, []string{"pending", "running"}).
					Updates(map[string]interface{}{
						"status":      "canceled",
						"finished_at": now,
					}).Error; err != nil {
					return err
				}
			}
			if req.RootDomains != nil {
				if err := tx.Where("project_id = ?", id).Delete(&db.ProjectScope{}).Error; err != nil {
					return err
				}
				for _, rd := range rootDomains {
					sc := db.ProjectScope{ProjectID: id, RootDomain: rd, Enabled: true}
					if err := tx.Create(&sc).Error; err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeAudit(id, actorFromRequest(r), "project_update", "project", id, map[string]interface{}{
			"updatedFields": keysOfMap(updates),
		}, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "id": id})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "id is required")
			return
		}
		if err := s.db.ArchiveProject(id); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeAudit(id, actorFromRequest(r), "project_archive", "project", id, nil, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "id": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handlePatchVulnStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req vulnStatusPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status := strings.ToLower(strings.TrimSpace(req.Status))
	if req.VulnID <= 0 || strings.TrimSpace(req.ProjectID) == "" || status == "" {
		writeError(w, http.StatusBadRequest, "vulnId, projectId and status are required")
		return
	}
	valid := map[string]bool{
		"open": true, "triaged": true, "confirmed": true, "accepted_risk": true,
		"fixed": true, "false_positive": true, "duplicate": true,
	}
	if !valid[status] {
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	var vuln db.Vulnerability
	if err := s.db.DB.Where("id = ? AND project_id = ?", req.VulnID, req.ProjectID).First(&vuln).Error; err != nil {
		writeError(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	now := time.Now()
	updates := map[string]interface{}{
		"status":             status,
		"last_transition_at": &now,
	}
	if strings.TrimSpace(req.Assignee) != "" {
		updates["assignee"] = strings.TrimSpace(req.Assignee)
	}
	if strings.TrimSpace(req.TicketRef) != "" {
		updates["ticket_ref"] = strings.TrimSpace(req.TicketRef)
	}
	if status == "fixed" {
		updates["fixed_at"] = &now
	}
	if status == "open" && vuln.Status == "fixed" {
		updates["reopen_count"] = vuln.ReopenCount + 1
	}
	if err := s.db.DB.Model(&db.Vulnerability{}).Where("id = ? AND project_id = ?", req.VulnID, req.ProjectID).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	event := db.VulnEvent{
		ProjectID:  req.ProjectID,
		VulnID:     uint(req.VulnID),
		Action:     "status_change",
		FromStatus: vuln.Status,
		ToStatus:   status,
		Actor:      defaultActor(req.Actor),
		Reason:     strings.TrimSpace(req.Reason),
	}
	if err := s.db.DB.Create(&event).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeAudit(req.ProjectID, event.Actor, "vuln_status_change", "vulnerability", strconv.Itoa(req.VulnID), map[string]interface{}{
		"from": vuln.Status, "to": status, "reason": event.Reason,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "ok", "vulnId": req.VulnID, "from": vuln.Status, "to": status,
	})
}

func (s *Server) handleVulnEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	vulnID, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("vuln_id")))
	query := s.db.DB.Where("project_id = ?", projectID).Order("created_at desc").Limit(500)
	if vulnID > 0 {
		query = query.Where("vuln_id = ?", vulnID)
	}
	var events []db.VulnEvent
	if err := query.Find(&events).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]vulnEventResponse, 0, len(events))
	for _, e := range events {
		resp = append(resp, vulnEventResponse{
			ID: int(e.ID), ProjectID: e.ProjectID, VulnID: int(e.VulnID), Action: e.Action,
			FromStatus: e.FromStatus, ToStatus: e.ToStatus, Actor: e.Actor, Reason: e.Reason,
			CreatedAt: timeToISO(e.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRelations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	rd := normalizeRootDomain(r.URL.Query().Get("root_domain"))
	query := s.db.DB.Where("project_id = ?", projectID).Order("updated_at desc").Limit(1000)
	if rd != "" {
		query = query.Where("root_domain = ?", rd)
	}
	var edges []db.AssetEdge
	if err := query.Find(&edges).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]edgeResponse, 0, len(edges))
	for _, e := range edges {
		resp = append(resp, edgeResponse{
			SrcType: e.SrcType, SrcID: e.SrcID, DstType: e.DstType, DstID: e.DstID, Relation: e.Relation,
		})
	}
	writeJSON(w, http.StatusOK, resp)
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
	run, err := s.db.CreateMonitorRun(task.ProjectID, rootDomain)
	if err != nil {
		log.Printf("[Scheduler] failed to create monitor run: %v", err)
		_ = s.db.HandleMonitorTaskFailure(task, fmt.Sprintf("create run failed: %v", err))
		return
	}

	target, err := s.db.GetOrCreateMonitorTarget(task.ProjectID, rootDomain)
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
	networkResults, err := s.runNetworkPipeline(subdomains, true, true, false, false, s.screenshotDir)
	if err != nil {
		log.Printf("[Scheduler] network pipeline warning for %s: %v", rootDomain, err)
	}

	allResults := append(subResults, networkResults...)

	// Save results to DB
	if dbErr := s.saveResultsToDB(task.ProjectID, rootDomain, fmt.Sprintf("mon-run-%d", run.ID), allResults); dbErr != nil {
		log.Printf("[Scheduler] DB save warning: %v", dbErr)
	}

	// Detect changes
	newLive, webChanged, portOpened, portClosed, svcChanged := s.detectChanges(task.ProjectID, rootDomain, run.ID, target)

	// Complete run
	status := "success"
	_ = s.db.CompleteMonitorRun(run.ID, status, "", newLive, webChanged, portOpened, portClosed, svcChanged)

	// Update target baseline
	now := time.Now()
	_ = s.db.UpdateMonitorTarget(task.ProjectID, rootDomain, true, now)

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
func (s *Server) detectChanges(projectID, rootDomain string, runID uint, target *db.MonitorTarget) (newLive, webChanged, portOpened, portClosed, svcChanged int) {
	if !target.BaselineDone {
		// First run = baseline, no changes to detect
		return 0, 0, 0, 0, 0
	}

	// Detect new live subdomains (created in last interval)
	recentAssets, _ := s.db.GetRecentAssets(target.LastRunAt.Add(-1 * time.Minute))
	for _, a := range recentAssets {
		if a.ProjectID == projectID && a.URL != "" && matchesRootDomain(a.Domain, rootDomain) {
			newLive++
			_ = s.db.SaveAssetChange(&db.AssetChange{
				ProjectID:  projectID,
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
		if p.ProjectID == projectID && matchesRootDomain(p.Domain, rootDomain) {
			portOpened++
			_ = s.db.SavePortChange(&db.PortChange{
				ProjectID:  projectID,
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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}

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
	qScanRunning := s.db.DB.Model(&db.ScanJob{}).
		Where("project_id = ? AND status IN ?", projectID, []string{"running", "pending"})
	qTaskRunning := s.db.DB.Model(&db.MonitorTask{}).
		Where("project_id = ? AND status IN ?", projectID, []string{"running", "pending"})
	qScanRunning.Count(&jobsRunningScans)
	qTaskRunning.Count(&jobsRunningTasks)

	// Count success/failed in 24h (scan_jobs + monitor_runs)
	var scanSuccess, scanFailed int64
	qScanSuccess := s.db.DB.Model(&db.ScanJob{}).
		Where("project_id = ? AND status = ? AND finished_at >= ?", projectID, "success", since24h)
	qScanFailed := s.db.DB.Model(&db.ScanJob{}).
		Where("project_id = ? AND status = ? AND finished_at >= ?", projectID, "failed", since24h)
	qScanSuccess.Count(&scanSuccess)
	qScanFailed.Count(&scanFailed)
	var monSuccess, monFailed int64
	qMonSuccess := s.db.DB.Model(&db.MonitorRun{}).
		Where("project_id = ? AND status = ? AND COALESCE(finished_at, updated_at) >= ?", projectID, "success", since24h)
	qMonFailed := s.db.DB.Model(&db.MonitorRun{}).
		Where("project_id = ? AND status = ? AND COALESCE(finished_at, updated_at) >= ?", projectID, "failed", since24h)
	qMonSuccess.Count(&monSuccess)
	qMonFailed.Count(&monFailed)
	jobsSuccess24h = scanSuccess + monSuccess
	jobsFailed24h = scanFailed + monFailed

	qAsset24 := s.db.DB.Model(&db.Asset{}).Where("project_id = ? AND created_at >= ?", projectID, since24h)
	qPort24 := s.db.DB.Model(&db.Port{}).Where("project_id = ? AND created_at >= ?", projectID, since24h)
	qVuln24 := s.db.DB.Model(&db.Vulnerability{}).Where("project_id = ? AND created_at >= ?", projectID, since24h)
	qAvgDuration := s.db.DB.Model(&db.ScanJob{}).
		Select("COALESCE(AVG(duration_sec), 0)").
		Where("project_id = ? AND status = ? AND finished_at >= ?", projectID, "success", since24h)
	qAsset24.Count(&newSub24h)
	qPort24.Count(&newPorts24h)
	qVuln24.Count(&newVulns24h)
	qAvgDuration.Scan(&avgDuration)

	trend := make([]trendPointResponse, 0, 7)
	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
		dayEnd := dayStart.Add(24 * time.Hour)

		var subCount, portCount, vulnCount int64
		qSub := s.db.DB.Model(&db.Asset{}).Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, dayStart, dayEnd)
		qPort := s.db.DB.Model(&db.Port{}).Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, dayStart, dayEnd)
		qVuln := s.db.DB.Model(&db.Vulnerability{}).Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, dayStart, dayEnd)
		qSub.Count(&subCount)
		qPort.Count(&portCount)
		qVuln.Count(&vulnCount)

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
// Assets / Ports / Vulns
// ──────────────────────────────────────────

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	paged := isTruthy(r.URL.Query().Get("paged"))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	liveOnly := isTruthy(r.URL.Query().Get("live_only"))

	base := s.db.DB.Model(&db.Asset{}).Where("project_id = ?", projectID)
	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		base = base.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}
	if search != "" {
		pattern := "%" + search + "%"
		base = base.Where(
			"LOWER(domain) LIKE ? OR LOWER(url) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(title) LIKE ?",
			pattern, pattern, pattern, pattern,
		)
	}
	if liveOnly {
		base = base.Where("status_code > 0")
	}

	var assets []db.Asset
	query := base.Order(resolveAssetOrder(r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir")))
	if paged {
		page := parseBoundedInt(r.URL.Query().Get("page"), 1, 1, 100000)
		pageSize := parseBoundedInt(r.URL.Query().Get("page_size"), 50, 10, 200)
		var total int64
		if err := base.Count(&total).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		offset := (page - 1) * pageSize
		query = query.Offset(offset).Limit(pageSize)
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
		writeJSON(w, http.StatusOK, pagedAssetsResponse{
			Items:    resp,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})
		return
	}
	query = query.Limit(maxListRows)

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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	paged := isTruthy(r.URL.Query().Get("paged"))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	base := s.db.DB.Model(&db.Port{}).Where("project_id = ?", projectID)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		base = base.Where("domain = ? OR domain LIKE ?", rd, pattern)
	}
	if search != "" {
		pattern := "%" + search + "%"
		base = base.Where(
			"LOWER(domain) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(service) LIKE ? OR LOWER(version) LIKE ?",
			pattern, pattern, pattern, pattern,
		)
	}

	var ports []db.Port
	query := base.Order(resolvePortOrder(r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir")))
	if paged {
		page := parseBoundedInt(r.URL.Query().Get("page"), 1, 1, 100000)
		pageSize := parseBoundedInt(r.URL.Query().Get("page_size"), 50, 10, 200)
		var total int64
		if err := base.Count(&total).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		offset := (page - 1) * pageSize
		query = query.Offset(offset).Limit(pageSize)
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
		writeJSON(w, http.StatusOK, pagedPortsResponse{
			Items:    resp,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})
		return
	}
	query = query.Limit(maxListRows)

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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	paged := isTruthy(r.URL.Query().Get("paged"))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))

	base := s.db.DB.Model(&db.Vulnerability{}).Where("project_id = ?", projectID)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		base = base.Where(
			"root_domain = ? OR domain = ? OR domain LIKE ? OR host = ? OR host LIKE ?",
			rd, rd, pattern, rd, pattern,
		)
	}
	if sev := strings.TrimSpace(r.URL.Query().Get("severity")); sev != "" {
		base = base.Where("severity = ?", strings.ToLower(sev))
	}
	if status != "" {
		base = base.Where("status = ?", status)
	}
	if search != "" {
		pattern := "%" + search + "%"
		base = base.Where(
			"LOWER(root_domain) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(host) LIKE ? OR LOWER(template_id) LIKE ? OR LOWER(cve) LIKE ? OR LOWER(url) LIKE ? OR LOWER(fingerprint) LIKE ? OR LOWER(assignee) LIKE ?",
			pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern,
		)
	}

	var vulns []db.Vulnerability
	query := base.Order(resolveVulnOrder(r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir")))
	if paged {
		page := parseBoundedInt(r.URL.Query().Get("page"), 1, 1, 100000)
		pageSize := parseBoundedInt(r.URL.Query().Get("page_size"), 50, 10, 200)
		var total int64
		if err := base.Count(&total).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		offset := (page - 1) * pageSize
		query = query.Offset(offset).Limit(pageSize)
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
				Fingerprint: v.Fingerprint, Status: v.Status, Assignee: v.Assignee,
				TicketRef: v.TicketRef, DueAt: timePtrToISO(v.DueAt),
				FixedAt: timePtrToISO(v.FixedAt), VerifiedAt: timePtrToISO(v.VerifiedAt),
				ReopenCount: v.ReopenCount, LastTransitionAt: timePtrToISO(v.LastTransitionAt),
				LastSeen: timeToISO(v.LastSeen),
			})
		}
		writeJSON(w, http.StatusOK, pagedVulnsResponse{
			Items:    resp,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})
		return
	}
	query = query.Limit(maxListRows)

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
			Fingerprint: v.Fingerprint, Status: v.Status, Assignee: v.Assignee,
			TicketRef: v.TicketRef, DueAt: timePtrToISO(v.DueAt),
			FixedAt: timePtrToISO(v.FixedAt), VerifiedAt: timePtrToISO(v.VerifiedAt),
			ReopenCount: v.ReopenCount, LastTransitionAt: timePtrToISO(v.LastTransitionAt),
			LastSeen: timeToISO(v.LastSeen),
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
	projectFilter := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectFilter == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	rootDomainFilter := normalizeRootDomain(r.URL.Query().Get("root_domain"))
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	paged := isTruthy(r.URL.Query().Get("paged"))
	page := parseBoundedInt(r.URL.Query().Get("page"), 1, 1, 100000)
	pageSize := parseBoundedInt(r.URL.Query().Get("page_size"), 50, 10, 200)
	scanLimit := 300
	taskLimit := 200
	if paged {
		scanLimit = 5000
		taskLimit = 5000
	}

	// Fetch scan jobs from DB
	scanJobs, err := s.db.ListScanJobs(projectFilter, rootDomainFilter, scanLimit)
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
			ProjectID:    sj.ProjectID,
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
	taskQuery := s.db.DB.Where("project_id = ?", projectFilter).Order("created_at desc").Limit(taskLimit)
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
				ID: fmt.Sprintf("task-%d", t.ID), ProjectID: t.ProjectID, RootDomain: t.RootDomain, Mode: "monitor",
				Modules: []string{"subs", "ports", "monitor"}, Status: normalizeHealthStatus(t.Status),
				StartedAt: started, FinishedAt: finished, DurationSec: duration,
				ErrorMessage: strings.TrimSpace(t.LastError),
			})
		}
	}

	if statusFilter != "" && statusFilter != "all" {
		filtered := make([]jobOverviewResponse, 0, len(jobs))
		for _, job := range jobs {
			if matchJobStatusFilter(job, statusFilter) {
				filtered = append(filtered, job)
			}
		}
		jobs = filtered
	}
	if search != "" {
		filtered := make([]jobOverviewResponse, 0, len(jobs))
		for _, job := range jobs {
			if matchJobSearch(job, search) {
				filtered = append(filtered, job)
			}
		}
		jobs = filtered
	}
	sortJobs(jobs, r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir"))
	if paged {
		total := len(jobs)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		writeJSON(w, http.StatusOK, pagedJobsResponse{
			Items:    jobs[start:end],
			Page:     page,
			PageSize: pageSize,
			Total:    int64(total),
		})
		return
	}
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
	projectID := strings.TrimSpace(req.ProjectID)
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "projectId is required")
		return
	}

	rootDomain := normalizeRootDomain(req.Domain)
	if rootDomain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if ok, err := s.isDomainInProjectScope(projectID, rootDomain); err != nil {
		writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusBadRequest, "domain is not in project scope")
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
		if err := s.db.EnableMonitorTarget(projectID, rootDomain, defaultMonitorIntervalSec, 3); err != nil {
			writeJSON(w, http.StatusOK, jobOverviewResponse{
				ID: jobID, ProjectID: projectID, RootDomain: rootDomain, Mode: mode, Modules: modules,
				Status: "error", StartedAt: now.Format(time.RFC3339), ErrorMessage: err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusOK, jobOverviewResponse{
			ID: jobID, ProjectID: projectID, RootDomain: rootDomain, Mode: mode, Modules: modules,
			Status: "pending", StartedAt: now.Format(time.RFC3339),
		})
		s.writeAudit(projectID, actorFromRequest(r), "create_monitor", "job", jobID, map[string]interface{}{
			"domain": rootDomain, "modules": modules,
		}, r)
		return
	}

	// Persist scan job to DB
	scanJob := db.ScanJob{
		JobID:      jobID,
		ProjectID:  projectID,
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
		go s.runScanAsync(projectID, jobID, rootDomain, modules, req.EnableNuclei, req.ActiveSubs, req.DictSize, req.DNSResolvers)
	}

	writeJSON(w, http.StatusOK, jobOverviewResponse{
		ID: jobID, ProjectID: projectID, RootDomain: rootDomain, Mode: mode, Modules: modules,
		Status: "pending", StartedAt: now.Format(time.RFC3339),
	})
	s.writeAudit(projectID, actorFromRequest(r), "create_scan", "job", jobID, map[string]interface{}{
		"domain": rootDomain, "modules": modules, "dryRun": req.DryRun,
	}, r)
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
	if job, err := s.db.GetScanJob(body.JobID); err == nil {
		s.writeAudit(job.ProjectID, actorFromRequest(r), "cancel_scan", "job", body.JobID, map[string]interface{}{
			"rootDomain": job.RootDomain,
		}, r)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "canceled", "jobId": body.JobID})
}

// runScanAsync executes the scan pipeline in a background goroutine.
func (s *Server) runScanAsync(projectID, jobID, rootDomain string, modules []string, enableNuclei, activeSubs bool, dictSize int, dnsResolvers string) {
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
	_ = s.db.DB.Create(&db.ScanStage{
		ProjectID: projectID,
		JobID:     jobID,
		Stage:     "pipeline",
		Module:    strings.Join(modules, ","),
		Status:    "running",
		StartedAt: &nowStart,
	}).Error

	log.Printf("[Scan] Job %s started for %s, modules=%v", jobID, rootDomain, modules)

	// Frontend may send stage modules (subs/ports/httpx/...) or concrete tool
	// modules (subfinder/findomain/bbot/naabu/nmap/...); normalize behavior here.
	hasPassiveSubs := containsAnyModule(modules, "subs", "subfinder", "findomain", "bbot", "shosubgo")
	hasActiveSubs := activeSubs || containsAnyModule(modules, "dnsx_bruteforce", "dictgen")
	hasSubs := hasPassiveSubs || hasActiveSubs
	hasPorts := containsAnyModule(modules, "ports", "naabu", "nmap")
	hasWitness := containsAnyModule(modules, "witness", "gowitness")
	hasNuclei := enableNuclei || containsAnyModule(modules, "nuclei")
	// Nuclei/Witness both depend on live HTTP targets from httpx.
	hasHttpx := containsAnyModule(modules, "httpx") || hasNuclei || hasWitness

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
		s.finishScan(projectID, rootDomain, jobID, startTime, nil, fmt.Errorf("canceled"))
		return
	default:
	}

	if hasSubs {
		subResults, subdomains, err := s.collectSubdomains(domains)
		allResults = append(allResults, subResults...)
		if err != nil {
			scanErr = fmt.Errorf("subdomain collection failed: %v", err)
			s.finishScan(projectID, rootDomain, jobID, startTime, allResults, scanErr)
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

		if hasPorts || hasHttpx {
			networkResults, err := s.runNetworkPipeline(subdomains, hasHttpx, hasPorts, hasNuclei, hasWitness, screenshotDir)
			allResults = append(allResults, networkResults...)
			if err != nil {
				scanErr = fmt.Errorf("network stage failed: %v", err)
			}
		}
	} else if hasPorts || hasHttpx {
		networkResults, err := s.runNetworkPipeline(domains, hasHttpx, hasPorts, hasNuclei, hasWitness, screenshotDir)
		allResults = append(allResults, networkResults...)
		if err != nil {
			scanErr = fmt.Errorf("network stage failed: %v", err)
		}
	}

	s.finishScan(projectID, rootDomain, jobID, startTime, allResults, scanErr)
}

func (s *Server) finishScan(projectID, rootDomain, jobID string, startTime time.Time, results []engine.Result, scanErr error) {
	duration := int(time.Since(startTime).Seconds())
	dbErr := s.saveResultsToDB(projectID, rootDomain, jobID, results)

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
	_ = s.db.DB.Model(&db.ScanStage{}).
		Where("project_id = ? AND job_id = ? AND stage = ? AND status = ?", projectID, jobID, "pipeline", "running").
		Updates(map[string]interface{}{
			"status":       finalStatus,
			"output_count": len(results),
			"error":        errMsg,
			"finished_at":  &now,
		}).Error

	log.Printf("[Scan] Job %s finished: status=%s duration=%ds subs=%d ports=%d vulns=%d",
		jobID, finalStatus, duration, counts["subdomains"], counts["ports"], counts["vulnerabilities"])
	s.writeAudit(projectID, "system", "finish_scan", "job", jobID, map[string]interface{}{
		"status": finalStatus, "durationSec": duration, "subdomains": counts["subdomains"], "ports": counts["ports"], "vulns": counts["vulnerabilities"],
	}, nil)
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

func (s *Server) runNetworkPipeline(targets []string, enableHTTPX, enablePorts, enableNuclei, enableWitness bool, screenshotDir string) ([]engine.Result, error) {
	pipeline := engine.NewPipeline()
	if enableHTTPX {
		pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	}
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
	return pipeline.ExecuteFromSubdomains(targets)
}

func (s *Server) saveResultsToDB(projectID, rootDomain, jobID string, results []engine.Result) error {
	failureCount := 0
	for _, result := range results {
		var err error
		sourceModule := result.Type
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				err = s.db.SaveOrUpdateAsset(map[string]interface{}{
					"project_id":    projectID,
					"root_domain":   rootDomain,
					"source_job_id": jobID,
					"source_module": sourceModule,
					"domain":        subdomain,
				})
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				if mapString(data, "root_domain") == "" {
					data["root_domain"] = rootDomain
				}
				data["source_job_id"] = jobID
				data["source_module"] = sourceModule
				err = s.db.SaveOrUpdateAsset(data)
				if err == nil {
					s.saveSimpleEdge(projectID, rootDomain, "domain", mapString(data, "domain"), "ip", mapString(data, "ip"), "resolves_to", jobID)
				}
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				if mapString(data, "root_domain") == "" {
					data["root_domain"] = rootDomain
				}
				data["source_job_id"] = jobID
				data["source_module"] = sourceModule
				err = s.db.SaveOrUpdatePort(data)
				if err == nil {
					s.saveSimpleEdge(projectID, rootDomain, "ip", mapString(data, "ip"), "port", fmt.Sprintf("%d", mapInt(data, "port")), "hosts_port", jobID)
				}
			}
		case "vulnerability":
			if data, ok := result.Data.(map[string]interface{}); ok {
				data["project_id"] = projectID
				if mapString(data, "root_domain") == "" {
					data["root_domain"] = rootDomain
				}
				data["source_job_id"] = jobID
				err = s.db.SaveOrUpdateVulnerability(data)
				if err == nil {
					vulnID := mapString(data, "template_id")
					s.saveSimpleEdge(projectID, rootDomain, "domain", mapString(data, "domain"), "vuln", vulnID, "has_vuln", jobID)
				}
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

func containsAnyModule(modules []string, names ...string) bool {
	for _, name := range names {
		if containsModule(modules, name) {
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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	targets, err := s.db.ListMonitorTargets(projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]monitorTargetResponse, 0, len(targets))
	for _, t := range targets {
		resp = append(resp, monitorTargetResponse{
			ID: int(t.ID), ProjectID: t.ProjectID, RootDomain: t.RootDomain, Enabled: t.Enabled,
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
	projectID := strings.TrimSpace(req.ProjectID)
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "projectId is required")
		return
	}
	domain := normalizeRootDomain(req.Domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if ok, err := s.isDomainInProjectScope(projectID, domain); err != nil {
		writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
		return
	} else if !ok {
		writeError(w, http.StatusBadRequest, "domain is not in project scope")
		return
	}
	intervalSec := req.IntervalSec
	if intervalSec <= 0 {
		intervalSec = defaultMonitorIntervalSec
	}
	if err := s.db.EnableMonitorTarget(projectID, domain, intervalSec, 3); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "projectId": projectID, "domain": domain, "intervalSec": intervalSec})
}

func (s *Server) handleDeleteMonitorTarget(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	domain := normalizeRootDomain(r.URL.Query().Get("domain"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	switch action {
	case "stop":
		if err := s.db.StopMonitorTarget(projectID, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "projectId": projectID, "domain": domain})
	case "delete":
		if err := s.db.DeleteMonitorDataByRootDomain(projectID, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "projectId": projectID, "domain": domain})
	default:
		// Default: toggle stop
		if err := s.db.StopMonitorTarget(projectID, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "projectId": projectID, "domain": domain})
	}
}

func (s *Server) handleMonitorRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	var runs []db.MonitorRun
	query := s.db.DB.Where("project_id = ?", projectID).Order("started_at desc").Limit(500)
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
			ID: int(run.ID), ProjectID: run.ProjectID, RootDomain: run.RootDomain, Status: normalizeHealthStatus(run.Status),
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
	pid := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if pid == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	rd := normalizeRootDomain(r.URL.Query().Get("root_domain"))
	sorted := make([]monitorChangeSortItem, 0, 400)

	var assetChanges []db.AssetChange
	aq := s.db.DB.Where("project_id = ?", pid).Order("created_at desc").Limit(200)
	if rd != "" {
		aq = aq.Where("root_domain = ?", rd)
	}
	if err := aq.Find(&assetChanges).Error; err == nil {
		for _, ac := range assetChanges {
			sorted = append(sorted, monitorChangeSortItem{
				createdAt: ac.CreatedAt,
				item: monitorChangeResponse{
					RunID: int(ac.RunID), ProjectID: ac.ProjectID, RootDomain: ac.RootDomain, ChangeType: ac.ChangeType,
					Domain: ac.Domain, StatusCode: ac.StatusCode, Title: ac.Title,
					CreatedAt: timeToISO(ac.CreatedAt),
				},
			})
		}
	}

	var portChanges []db.PortChange
	pq := s.db.DB.Where("project_id = ?", pid).Order("created_at desc").Limit(200)
	if rd != "" {
		pq = pq.Where("root_domain = ?", rd)
	}
	if err := pq.Find(&portChanges).Error; err == nil {
		for _, pc := range portChanges {
			sorted = append(sorted, monitorChangeSortItem{
				createdAt: pc.CreatedAt,
				item: monitorChangeResponse{
					RunID: int(pc.RunID), ProjectID: pc.ProjectID, RootDomain: pc.RootDomain, ChangeType: pc.ChangeType,
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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	scopeSet := map[string]bool(nil)
	if projectID != "" {
		var scopes []db.ProjectScope
		if err := s.db.DB.Where("project_id = ? AND enabled = ?", projectID, true).Find(&scopes).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(scopes) == 0 {
			writeJSON(w, http.StatusOK, []screenshotDomainResponse{})
			return
		}
		scopeSet = make(map[string]bool, len(scopes))
		for _, sc := range scopes {
			rd := normalizeRootDomain(sc.RootDomain)
			if rd != "" {
				scopeSet[rd] = true
			}
		}
	}

	domains, err := plugins.ListScreenshotDomains(s.screenshotDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []screenshotDomainResponse{})
		return
	}
	resp := make([]screenshotDomainResponse, 0, len(domains))
	for _, rootDomain := range domains {
		if scopeSet != nil && !scopeSet[normalizeRootDomain(rootDomain)] {
			continue
		}
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
			ProjectID:       projectID,
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
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	pathParts := strings.TrimPrefix(r.URL.Path, "/api/screenshots/")
	rootDomain := normalizeRootDomain(pathParts)
	if rootDomain == "" {
		rootDomain = normalizeRootDomain(r.URL.Query().Get("root_domain"))
	}
	if rootDomain == "" {
		writeJSON(w, http.StatusOK, []screenshotItemResponse{})
		return
	}
	if projectID != "" {
		ok, err := s.isDomainInProjectScope(projectID, rootDomain)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
			return
		}
		if !ok {
			writeJSON(w, http.StatusOK, []screenshotItemResponse{})
			return
		}
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
			ProjectID:    projectID,
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
	// Notification credentials are managed by environment variables only.
	settings.Notifications.DingTalkWebhook = os.Getenv("DINGTALK_WEBHOOK")
	settings.Notifications.DingTalkSecret = os.Getenv("DINGTALK_SECRET")
	settings.Notifications.Enabled = strings.TrimSpace(settings.Notifications.DingTalkWebhook) != ""

	resp := systemSettingsResponse{
		Database: databaseSettingsResponse{
			Host: settings.Database.Host, Port: settings.Database.Port,
			User: settings.Database.User, DBName: settings.Database.DBName,
			SSLMode: settings.Database.SSLMode, Connected: s.db.DB != nil,
		},
		Notifications: notificationSettingsResponse{
			DingTalkWebhook: maskSecret(settings.Notifications.DingTalkWebhook),
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

func ensureCommonToolPaths() {
	extra := "/root/go/bin"
	st, err := os.Stat(extra)
	if err != nil || !st.IsDir() {
		return
	}

	cur := os.Getenv("PATH")
	for _, item := range filepath.SplitList(cur) {
		if filepath.Clean(item) == filepath.Clean(extra) {
			return
		}
	}
	if cur == "" {
		_ = os.Setenv("PATH", extra)
		return
	}
	_ = os.Setenv("PATH", cur+string(os.PathListSeparator)+extra)
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"success": true,
		"message": "test notification sent",
	})
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

func normalizeRootDomains(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		d := normalizeRootDomain(raw)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func dedupTrimmed(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		v := strings.TrimSpace(raw)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func mapString(data map[string]interface{}, key string) string {
	v, ok := data[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case fmt.Stringer:
		return strings.TrimSpace(t.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

func mapInt(data map[string]interface{}, key string) int {
	v, ok := data[key]
	if !ok || v == nil {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int32:
		return int(t)
	case int64:
		return int(t)
	case float64:
		return int(t)
	case float32:
		return int(t)
	case json.Number:
		i, _ := t.Int64()
		return int(i)
	default:
		return 0
	}
}

func parseBoundedInt(raw string, defaultValue, minValue, maxValue int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return defaultValue
	}
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func parseCORSOrigins() (bool, map[string]bool) {
	raw := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if raw == "" {
		return false, map[string]bool{
			"http://localhost:5173": true,
			"http://127.0.0.1:5173": true,
		}
	}
	if raw == "*" {
		return true, nil
	}
	origins := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		origin := strings.TrimSpace(item)
		if origin == "" {
			continue
		}
		origins[origin] = true
	}
	if len(origins) == 0 {
		return true, nil
	}
	return false, origins
}

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func resolveAssetOrder(sortByRaw, sortDirRaw string) string {
	sortBy := strings.ToLower(strings.TrimSpace(sortByRaw))
	sortDir := strings.ToLower(strings.TrimSpace(sortDirRaw))
	if sortDir != "asc" {
		sortDir = "desc"
	}
	allowed := map[string]string{
		"created_at":  "created_at",
		"updated_at":  "updated_at",
		"last_seen":   "last_seen",
		"domain":      "domain",
		"status_code": "status_code",
	}
	column, ok := allowed[sortBy]
	if !ok {
		column = "created_at"
	}
	return fmt.Sprintf("%s %s", column, sortDir)
}

func resolvePortOrder(sortByRaw, sortDirRaw string) string {
	sortBy := strings.ToLower(strings.TrimSpace(sortByRaw))
	sortDir := strings.ToLower(strings.TrimSpace(sortDirRaw))
	if sortDir != "asc" {
		sortDir = "desc"
	}
	allowed := map[string]string{
		"created_at": "created_at",
		"updated_at": "updated_at",
		"last_seen":  "last_seen",
		"domain":     "domain",
		"ip":         "ip",
		"port":       "port",
		"service":    "service",
	}
	column, ok := allowed[sortBy]
	if !ok {
		column = "created_at"
	}
	return fmt.Sprintf("%s %s", column, sortDir)
}

func resolveVulnOrder(sortByRaw, sortDirRaw string) string {
	sortBy := strings.ToLower(strings.TrimSpace(sortByRaw))
	sortDir := strings.ToLower(strings.TrimSpace(sortDirRaw))
	if sortDir != "asc" {
		sortDir = "desc"
	}
	allowed := map[string]string{
		"created_at":  "created_at",
		"updated_at":  "updated_at",
		"last_seen":   "last_seen",
		"severity":    "severity",
		"status":      "status",
		"domain":      "domain",
		"template_id": "template_id",
	}
	column, ok := allowed[sortBy]
	if !ok {
		column = "created_at"
	}
	return fmt.Sprintf("%s %s", column, sortDir)
}

func sortJobs(jobs []jobOverviewResponse, sortByRaw, sortDirRaw string) {
	sortBy := strings.ToLower(strings.TrimSpace(sortByRaw))
	sortDir := strings.ToLower(strings.TrimSpace(sortDirRaw))
	asc := sortDir == "asc"
	if sortBy == "" {
		sortBy = "started_at"
	}
	sort.SliceStable(jobs, func(i, j int) bool {
		a := jobs[i]
		b := jobs[j]
		var less bool
		switch sortBy {
		case "root_domain":
			less = strings.Compare(strings.ToLower(a.RootDomain), strings.ToLower(b.RootDomain)) < 0
		case "status":
			less = strings.Compare(strings.ToLower(a.Status), strings.ToLower(b.Status)) < 0
		case "duration_sec":
			less = a.DurationSec < b.DurationSec
		case "finished_at":
			at := parseTimeBestEffort(a.FinishedAt)
			bt := parseTimeBestEffort(b.FinishedAt)
			less = at.Before(bt)
			if at.Equal(bt) {
				less = strings.Compare(strings.ToLower(a.ID), strings.ToLower(b.ID)) < 0
			}
		default:
			at := parseTimeBestEffort(a.StartedAt)
			bt := parseTimeBestEffort(b.StartedAt)
			less = at.Before(bt)
			if at.Equal(bt) {
				less = strings.Compare(strings.ToLower(a.ID), strings.ToLower(b.ID)) < 0
			}
		}
		if !asc {
			return !less
		}
		return less
	})
}

func matchJobStatusFilter(job jobOverviewResponse, filter string) bool {
	s := strings.ToLower(strings.TrimSpace(job.Status))
	switch filter {
	case "running":
		return strings.Contains(s, "running") || strings.Contains(s, "pending")
	case "success":
		return strings.Contains(s, "success") || strings.Contains(s, "ok") || strings.Contains(s, "done")
	case "failed":
		return strings.Contains(s, "failed") || strings.Contains(s, "error") || strings.Contains(s, "fail")
	case "pending":
		return strings.Contains(s, "pending")
	case "canceled":
		return strings.Contains(s, "canceled")
	default:
		return true
	}
}

func matchJobSearch(job jobOverviewResponse, q string) bool {
	lq := strings.ToLower(strings.TrimSpace(q))
	if lq == "" {
		return true
	}
	if strings.Contains(strings.ToLower(job.ID), lq) ||
		strings.Contains(strings.ToLower(job.RootDomain), lq) ||
		strings.Contains(strings.ToLower(job.Status), lq) ||
		strings.Contains(strings.ToLower(job.ErrorMessage), lq) {
		return true
	}
	for _, mod := range job.Modules {
		if strings.Contains(strings.ToLower(mod), lq) {
			return true
		}
	}
	return false
}

func keysOfMap(m map[string]interface{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func defaultActor(actor string) string {
	a := strings.TrimSpace(actor)
	if a == "" {
		return "system"
	}
	return a
}

func actorFromRequest(r *http.Request) string {
	if r == nil {
		return "system"
	}
	if a := strings.TrimSpace(r.Header.Get("X-Actor")); a != "" {
		return a
	}
	return "system"
}

func (s *Server) writeAudit(projectID, actor, action, targetType, targetID string, meta map[string]interface{}, r *http.Request) {
	if s == nil || s.db == nil || s.db.DB == nil {
		return
	}
	var rawMeta []byte
	if meta != nil {
		rawMeta, _ = json.Marshal(meta)
	}
	detail := ""
	if meta != nil {
		if b, err := json.Marshal(meta); err == nil {
			detail = string(b)
		}
	}
	logRecord := db.AuditLog{
		ProjectID:  strings.TrimSpace(projectID),
		Actor:      defaultActor(actor),
		Action:     strings.TrimSpace(action),
		TargetType: strings.TrimSpace(targetType),
		TargetID:   strings.TrimSpace(targetID),
		Detail:     detail,
		Meta:       rawMeta,
	}
	if r != nil {
		logRecord.IP = strings.TrimSpace(r.RemoteAddr)
		logRecord.UserAgent = strings.TrimSpace(r.UserAgent())
	}
	_ = s.db.DB.Create(&logRecord).Error
}

func (s *Server) saveSimpleEdge(projectID, rootDomain, srcType, srcID, dstType, dstID, relation, jobID string) {
	srcID = strings.TrimSpace(srcID)
	dstID = strings.TrimSpace(dstID)
	if srcID == "" || dstID == "" {
		return
	}
	now := time.Now()
	var existing db.AssetEdge
	q := s.db.DB.Where("project_id = ? AND src_type = ? AND src_id = ? AND dst_type = ? AND dst_id = ? AND relation = ?",
		projectID, srcType, srcID, dstType, dstID, relation)
	if err := q.First(&existing).Error; err == nil {
		_ = s.db.DB.Model(&existing).Updates(map[string]interface{}{
			"last_seen": now,
			"job_id":    jobID,
		}).Error
		return
	}
	edge := db.AssetEdge{
		ProjectID:  projectID,
		RootDomain: rootDomain,
		SrcType:    srcType,
		SrcID:      srcID,
		DstType:    dstType,
		DstID:      dstID,
		Relation:   relation,
		Confidence: 100,
		JobID:      jobID,
		FirstSeen:  now,
		LastSeen:   now,
	}
	_ = s.db.DB.Create(&edge).Error
}

// ──────────────────────────────────────────
// Asset Detail
// ──────────────────────────────────────────

type assetDetailResponse struct {
	Asset  assetResponse           `json:"asset"`
	Ports  []portResponse          `json:"ports"`
	Vulns  []vulnerabilityResponse `json:"vulns"`
	Events []vulnEventResponse     `json:"events"`
}

func (s *Server) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	idStr := strings.TrimSpace(r.URL.Query().Get("id"))
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}

	var asset db.Asset
	if idStr != "" {
		id, _ := strconv.Atoi(idStr)
		if err := s.db.DB.Where("id = ? AND project_id = ?", id, projectID).First(&asset).Error; err != nil {
			writeError(w, http.StatusNotFound, "asset not found")
			return
		}
	} else if domain != "" {
		if err := s.db.DB.Where("domain = ? AND project_id = ?", strings.ToLower(domain), projectID).First(&asset).Error; err != nil {
			writeError(w, http.StatusNotFound, "asset not found")
			return
		}
	} else {
		writeError(w, http.StatusBadRequest, "id or domain is required")
		return
	}

	ar := assetResponse{
		ID: int(asset.ID), Domain: asset.Domain, URL: asset.URL, IP: asset.IP,
		StatusCode: asset.StatusCode, Title: asset.Title,
		Technologies: decodeJSONBStrings(asset.Technologies),
		CreatedAt:    timeToISO(asset.CreatedAt), UpdatedAt: timeToISO(asset.UpdatedAt),
		LastSeen: timeToISO(asset.LastSeen),
	}

	var ports []db.Port
	s.db.DB.Where("asset_id = ? AND project_id = ?", asset.ID, projectID).Order("port asc").Limit(500).Find(&ports)
	if len(ports) == 0 {
		s.db.DB.Where("project_id = ? AND (domain = ? OR ip = ?)", projectID, asset.Domain, asset.IP).Order("port asc").Limit(500).Find(&ports)
	}
	pr := make([]portResponse, 0, len(ports))
	for _, p := range ports {
		pr = append(pr, portResponse{
			ID: int(p.ID), AssetID: int(p.AssetID), Domain: p.Domain, IP: p.IP,
			Port: p.Port, Protocol: p.Protocol, Service: p.Service, Version: p.Version,
			Banner: p.Banner, LastSeen: timeToISO(p.LastSeen), UpdatedAt: timeToISO(p.UpdatedAt),
		})
	}

	var vulns []db.Vulnerability
	s.db.DB.Where("project_id = ? AND (domain = ? OR host = ? OR ip = ?)", projectID, asset.Domain, asset.Domain, asset.IP).Order("created_at desc").Limit(200).Find(&vulns)
	vr := make([]vulnerabilityResponse, 0, len(vulns))
	for _, v := range vulns {
		matchedAt := strings.TrimSpace(v.MatchedAt)
		if matchedAt == "" {
			matchedAt = timeToISO(v.CreatedAt)
		}
		vr = append(vr, vulnerabilityResponse{
			ID: int(v.ID), RootDomain: v.RootDomain, Domain: v.Domain, Host: v.Host,
			URL: v.URL, IP: v.IP, TemplateID: v.TemplateID, TemplateName: v.TemplateName,
			Severity: v.Severity, CVE: v.CVE, Description: v.Description,
			MatchedAt: matchedAt, Fingerprint: v.Fingerprint, Status: v.Status,
			LastSeen: timeToISO(v.LastSeen),
		})
	}

	writeJSON(w, http.StatusOK, assetDetailResponse{Asset: ar, Ports: pr, Vulns: vr})
}

// ──────────────────────────────────────────
// Bulk Operations
// ──────────────────────────────────────────

func (s *Server) handleBulkDeleteAssets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ProjectID string `json:"projectId"`
		IDs       []int  `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if body.ProjectID == "" || len(body.IDs) == 0 {
		writeError(w, http.StatusBadRequest, "projectId and ids are required")
		return
	}
	if len(body.IDs) > 500 {
		writeError(w, http.StatusBadRequest, "max 500 IDs per request")
		return
	}
	result := s.db.DB.Where("id IN ? AND project_id = ?", body.IDs, body.ProjectID).Delete(&db.Asset{})
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	s.writeAudit(body.ProjectID, actorFromRequest(r), "bulk_delete_assets", "asset", "", map[string]interface{}{
		"count": result.RowsAffected, "ids": body.IDs,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "deleted": result.RowsAffected})
}

func (s *Server) handleBulkVulnStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ProjectID string `json:"projectId"`
		IDs       []int  `json:"ids"`
		Status    string `json:"status"`
		Reason    string `json:"reason"`
		Actor     string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status := strings.ToLower(strings.TrimSpace(body.Status))
	valid := map[string]bool{
		"open": true, "triaged": true, "confirmed": true, "accepted_risk": true,
		"fixed": true, "false_positive": true, "duplicate": true,
	}
	if body.ProjectID == "" || len(body.IDs) == 0 || !valid[status] {
		writeError(w, http.StatusBadRequest, "projectId, ids and valid status are required")
		return
	}
	if len(body.IDs) > 500 {
		writeError(w, http.StatusBadRequest, "max 500 IDs per request")
		return
	}
	now := time.Now()
	updates := map[string]interface{}{
		"status":             status,
		"last_transition_at": &now,
	}
	if status == "fixed" {
		updates["fixed_at"] = &now
	}
	result := s.db.DB.Model(&db.Vulnerability{}).Where("id IN ? AND project_id = ?", body.IDs, body.ProjectID).Updates(updates)
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	actor := defaultActor(body.Actor)
	for _, vid := range body.IDs {
		event := db.VulnEvent{
			ProjectID: body.ProjectID, VulnID: uint(vid), Action: "bulk_status_change",
			ToStatus: status, Actor: actor, Reason: strings.TrimSpace(body.Reason),
		}
		_ = s.db.DB.Create(&event).Error
	}
	s.writeAudit(body.ProjectID, actor, "bulk_vuln_status", "vulnerability", "", map[string]interface{}{
		"count": result.RowsAffected, "toStatus": status,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "updated": result.RowsAffected})
}

// ──────────────────────────────────────────
// Global Search
// ──────────────────────────────────────────

type globalSearchResponse struct {
	Assets []assetResponse         `json:"assets"`
	Ports  []portResponse          `json:"ports"`
	Vulns  []vulnerabilityResponse `json:"vulns"`
}

func (s *Server) handleGlobalSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if projectID == "" || q == "" || len(q) < 2 {
		writeError(w, http.StatusBadRequest, "project_id and q (min 2 chars) are required")
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 20, 5, 50)
	pattern := "%" + q + "%"
	resp := globalSearchResponse{}

	var assets []db.Asset
	s.db.DB.Where("project_id = ? AND (LOWER(domain) LIKE ? OR LOWER(url) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(title) LIKE ?)",
		projectID, pattern, pattern, pattern, pattern).Order("last_seen desc").Limit(limit).Find(&assets)
	resp.Assets = make([]assetResponse, 0, len(assets))
	for _, a := range assets {
		resp.Assets = append(resp.Assets, assetResponse{
			ID: int(a.ID), Domain: a.Domain, URL: a.URL, IP: a.IP,
			StatusCode: a.StatusCode, Title: a.Title,
			Technologies: decodeJSONBStrings(a.Technologies),
			LastSeen:     timeToISO(a.LastSeen),
		})
	}

	var ports []db.Port
	s.db.DB.Where("project_id = ? AND (LOWER(domain) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(service) LIKE ? OR CAST(port AS TEXT) LIKE ?)",
		projectID, pattern, pattern, pattern, pattern).Order("last_seen desc").Limit(limit).Find(&ports)
	resp.Ports = make([]portResponse, 0, len(ports))
	for _, p := range ports {
		resp.Ports = append(resp.Ports, portResponse{
			ID: int(p.ID), Domain: p.Domain, IP: p.IP, Port: p.Port,
			Protocol: p.Protocol, Service: p.Service, Version: p.Version,
			LastSeen: timeToISO(p.LastSeen),
		})
	}

	var vulns []db.Vulnerability
	s.db.DB.Where("project_id = ? AND (LOWER(domain) LIKE ? OR LOWER(host) LIKE ? OR LOWER(template_id) LIKE ? OR LOWER(cve) LIKE ? OR LOWER(url) LIKE ?)",
		projectID, pattern, pattern, pattern, pattern, pattern).Order("last_seen desc").Limit(limit).Find(&vulns)
	resp.Vulns = make([]vulnerabilityResponse, 0, len(vulns))
	for _, v := range vulns {
		matchedAt := strings.TrimSpace(v.MatchedAt)
		if matchedAt == "" {
			matchedAt = timeToISO(v.CreatedAt)
		}
		resp.Vulns = append(resp.Vulns, vulnerabilityResponse{
			ID: int(v.ID), Domain: v.Domain, Host: v.Host, URL: v.URL,
			TemplateID: v.TemplateID, TemplateName: v.TemplateName,
			Severity: v.Severity, CVE: v.CVE, Status: v.Status,
			MatchedAt: matchedAt, LastSeen: timeToISO(v.LastSeen),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) isDomainInProjectScope(projectID, domain string) (bool, error) {
	domain = normalizeRootDomain(domain)
	if projectID == "" || domain == "" {
		return false, nil
	}
	var project db.Project
	if err := s.db.DB.Select("id", "archived").Where("id = ?", projectID).First(&project).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if project.Archived {
		return false, nil
	}
	var scopes []db.ProjectScope
	if err := s.db.DB.Where("project_id = ? AND enabled = ?", projectID, true).Find(&scopes).Error; err != nil {
		return false, err
	}
	if len(scopes) == 0 {
		return false, nil
	}
	for _, sc := range scopes {
		rd := normalizeRootDomain(sc.RootDomain)
		if rd == "" {
			continue
		}
		if domain == rd || strings.HasSuffix(domain, "."+rd) {
			return true, nil
		}
	}
	return false, nil
}
