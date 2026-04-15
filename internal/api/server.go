package api

import (
	"context"
	"encoding/json"
	"errors"
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
	defaultMonitorIntervalSec  = 6 * 3600
	defaultMonitorVulnMaxURLs  = 50
	defaultMonitorVulnCooldown = 30
	maxMonitorVulnMaxURLs      = 1000
	maxMonitorVulnCooldownMin  = 24 * 60
	maxListRows                = 5000
	schedulerPollInterval      = 15 * time.Second
	scanWorkerPollInterval     = 3 * time.Second
	scanJobStaleAfter          = 6 * time.Hour
	monitorEventNotifyWindow   = 30 * time.Minute
	monitorNotifyMaxAssets     = 10
	monitorNotifyMaxPorts      = 12
	monitorEventStatusOpen     = "open"
	monitorEventStatusResolved = "resolved"
	appSettingAIKey            = "settings.ai.v1"
)

var errScanCanceled = errors.New("scan canceled")

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

	aiLimiterMu          sync.Mutex
	aiLimiterWindowStart time.Time
	aiLimiterUsed        int
}

type runtimeSettings struct {
	Database      runtimeDatabaseSettings
	Notifications runtimeNotificationSettings
	Scanner       runtimeScannerSettings
	AI            runtimeAISettings
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

type runtimeAISettings struct {
	Enabled           bool
	BaseURL           string
	APIKey            string
	Model             string
	TimeoutSec        int
	MaxRetries        int
	RequestsPerMinute int
}

type dashboardResponse struct {
	Summary dashboardSummaryResponse `json:"summary"`
	Trend   []trendPointResponse     `json:"trend"`
}

type dashboardSummaryResponse struct {
	JobsRunning           int                          `json:"jobsRunning"`
	JobsSuccess24h        int                          `json:"jobsSuccess24h"`
	JobsFailed24h         int                          `json:"jobsFailed24h"`
	NewSubdomains24h      int                          `json:"newSubdomains24h"`
	NewPorts24h           int                          `json:"newPorts24h"`
	NewVulns24h           int                          `json:"newVulns24h"`
	ScanDurationAvgSec24h int                          `json:"scanDurationAvgSec24h"`
	ServiceDistribution   []dashboardCountItemResponse `json:"serviceDistribution"`
	SeverityDistribution  []dashboardCountItemResponse `json:"severityDistribution"`
}

type dashboardCountItemResponse struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
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
	EnableNuclei *bool    `json:"enableNuclei"`
	ActiveSubs   *bool    `json:"activeSubs"`
	DictSize     int      `json:"dictSize"`
	DNSResolvers string   `json:"dnsResolvers"`
	DryRun       bool     `json:"dryRun"`
	Notify       *bool    `json:"notify"`
}

type assetResponse struct {
	ID           int      `json:"id"`
	Domain       string   `json:"domain"`
	URL          string   `json:"url,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Pool         string   `json:"pool,omitempty"`
	VerifyStatus string   `json:"verifyStatus,omitempty"`
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

type jobLogItemResponse struct {
	ID        uint   `json:"id"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
}

type jobLogsResponse struct {
	Items         []jobLogItemResponse `json:"items"`
	SinceID       uint                 `json:"sinceId"`
	JobStatus     string               `json:"jobStatus"`
	HasMoreBefore bool                 `json:"hasMoreBefore"`
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
	ID                int    `json:"id"`
	ProjectID         string `json:"projectId,omitempty"`
	RootDomain        string `json:"rootDomain"`
	Enabled           bool   `json:"enabled"`
	IntervalSec       int    `json:"intervalSec"`
	MonitorPorts      bool   `json:"monitorPorts"`
	NotifyAISummary   bool   `json:"notifyAiSummary"`
	EnableVulnScan    bool   `json:"enableVulnScan"`
	EnableNuclei      bool   `json:"enableNuclei"`
	EnableCors        bool   `json:"enableCors"`
	EnableSubtakeover bool   `json:"enableSubtakeover"`
	VulnOnNewLive     bool   `json:"vulnOnNewLive"`
	VulnOnWebChanged  bool   `json:"vulnOnWebChanged"`
	VulnMaxURLs       int    `json:"vulnMaxUrls"`
	VulnCooldownMin   int    `json:"vulnCooldownMin"`
	LastVulnScanAt    string `json:"lastVulnScanAt,omitempty"`
	BaselineDone      bool   `json:"baselineDone"`
	BaselineVersion   int    `json:"baselineVersion"`
	BaselineAt        string `json:"baselineAt,omitempty"`
	LastRunAt         string `json:"lastRunAt,omitempty"`
	CreatedAt         string `json:"createdAt,omitempty"`
	UpdatedAt         string `json:"updatedAt,omitempty"`
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

type monitorEventResponse struct {
	ID              int    `json:"id"`
	ProjectID       string `json:"projectId,omitempty"`
	RootDomain      string `json:"rootDomain"`
	EventKey        string `json:"eventKey"`
	EventType       string `json:"eventType"`
	Status          string `json:"status"`
	Domain          string `json:"domain,omitempty"`
	URL             string `json:"url,omitempty"`
	IP              string `json:"ip,omitempty"`
	Port            int    `json:"port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Service         string `json:"service,omitempty"`
	Version         string `json:"version,omitempty"`
	Title           string `json:"title,omitempty"`
	StatusCode      int    `json:"statusCode,omitempty"`
	FirstSeenAt     string `json:"firstSeenAt,omitempty"`
	LastSeenAt      string `json:"lastSeenAt,omitempty"`
	LastChangedAt   string `json:"lastChangedAt,omitempty"`
	ResolvedAt      string `json:"resolvedAt,omitempty"`
	OccurrenceCount int    `json:"occurrenceCount"`
	LastRunID       int    `json:"lastRunId,omitempty"`
}

type monitorSnapshotResponse struct {
	ID             int                    `json:"id"`
	ProjectID      string                 `json:"projectId,omitempty"`
	RootDomain     string                 `json:"rootDomain"`
	RunID          int                    `json:"runId"`
	AssetCount     int                    `json:"assetCount"`
	PortCount      int                    `json:"portCount"`
	OpenEventCount int                    `json:"openEventCount"`
	Summary        map[string]interface{} `json:"summary,omitempty"`
	CreatedAt      string                 `json:"createdAt,omitempty"`
}

type monitorDiffResponse struct {
	ProjectID  string                   `json:"projectId,omitempty"`
	RootDomain string                   `json:"rootDomain"`
	RunID      int                      `json:"runId"`
	PrevRunID  int                      `json:"prevRunId,omitempty"`
	Snapshot   monitorSnapshotResponse  `json:"snapshot"`
	Previous   *monitorSnapshotResponse `json:"previous,omitempty"`
	Delta      struct {
		AssetCount     int `json:"assetCount"`
		PortCount      int `json:"portCount"`
		OpenEventCount int `json:"openEventCount"`
	} `json:"delta"`
	AssetChanges []monitorChangeResponse `json:"assetChanges"`
	PortChanges  []monitorChangeResponse `json:"portChanges"`
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
	AI            aiSettingsResponse           `json:"ai"`
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

type aiSettingsResponse struct {
	Enabled           bool   `json:"enabled"`
	BaseURL           string `json:"baseUrl"`
	APIKey            string `json:"apiKey"`
	Model             string `json:"model"`
	TimeoutSec        int    `json:"timeoutSec"`
	MaxRetries        int    `json:"maxRetries"`
	RequestsPerMinute int    `json:"requestsPerMinute"`
	Configured        bool   `json:"configured"`
}

type settingsPatchRequest struct {
	Database *databaseSettingsPatch `json:"database"`
	Scanner  *scannerSettingsPatch  `json:"scanner"`
	AI       *aiSettingsPatch       `json:"ai"`
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

type aiSettingsPatch struct {
	Enabled           *bool   `json:"enabled"`
	BaseURL           *string `json:"baseUrl"`
	APIKey            *string `json:"apiKey"`
	Model             *string `json:"model"`
	TimeoutSec        *int    `json:"timeoutSec"`
	MaxRetries        *int    `json:"maxRetries"`
	RequestsPerMinute *int    `json:"requestsPerMinute"`
}

type monitorChangeSortItem struct {
	createdAt time.Time
	item      monitorChangeResponse
}

type createMonitorRequest struct {
	ProjectID         string `json:"projectId"`
	Domain            string `json:"domain"`
	IntervalSec       int    `json:"intervalSec"`
	MonitorPorts      *bool  `json:"monitorPorts"`
	NotifyAISummary   *bool  `json:"notifyAiSummary"`
	EnableVulnScan    *bool  `json:"enableVulnScan"`
	EnableNuclei      *bool  `json:"enableNuclei"`
	EnableCors        *bool  `json:"enableCors"`
	EnableSubtakeover *bool  `json:"enableSubtakeover"`
	VulnOnNewLive     *bool  `json:"vulnOnNewLive"`
	VulnOnWebChanged  *bool  `json:"vulnOnWebChanged"`
	VulnMaxURLs       *int   `json:"vulnMaxUrls"`
	VulnCooldownMin   *int   `json:"vulnCooldownMin"`
}

type projectResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Tags        []string `json:"tags"`
	Archived    bool     `json:"archived"`
	AIEnabled   bool     `json:"aiEnabled"`
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
	AIEnabled   *bool    `json:"aiEnabled"`
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

	initialSettings := loadRuntimeSettings(screenshotDir)
	initialSettings.AI = normalizeRuntimeAISettings(initialSettings.AI)

	s := &Server{
		db:            database,
		mux:           http.NewServeMux(),
		screenshotDir: screenshotDir,
		corsAllowAll:  corsAllowAll,
		corsOrigins:   corsOrigins,
		settings:      initialSettings,
		scanCancels:   make(map[string]context.CancelFunc),
	}
	if err := s.loadPersistedSettings(); err != nil {
		log.Printf("[Settings] load persisted settings failed: %v", err)
	}
	s.registerRoutes()
	return s
}

// Start starts the HTTP API server.
func (s *Server) Start(addr string) error {
	log.Printf("[API] server starting on %s", addr)
	handler := s.corsMiddleware(s.authMiddleware(s.mux))
	return http.ListenAndServe(addr, handler)
}

// RunWorkers starts background workers for monitor tasks and scan jobs.
func (s *Server) RunWorkers() error {
	if recovered, err := s.db.RecoverStaleRunningTasks(2 * time.Hour); err != nil {
		log.Printf("[Worker] failed to recover stale monitor tasks: %v", err)
	} else if recovered > 0 {
		log.Printf("[Worker] recovered %d stale monitor tasks", recovered)
	}
	if recovered, err := s.db.RecoverStaleRunningScanJobsDetailed(scanJobStaleAfter); err != nil {
		log.Printf("[Worker] failed to recover stale scan jobs: %v", err)
	} else if len(recovered) > 0 {
		log.Printf("[Worker] recovered %d stale scan jobs", len(recovered))
		for _, item := range recovered {
			s.appendJobLog(item.ProjectID, item.JobID, "warn", item.ErrorMessage)
			if strings.TrimSpace(item.LastStage) == "" {
				s.appendJobLogf(item.ProjectID, item.JobID, "warn",
					"worker 鍥炴敹鍓嶆棤闃舵璁板綍: root=%s started_at=%s updated_at=%s cutoff=%s",
					item.RootDomain, timePtrToISO(item.StartedAt), timeToISO(item.JobUpdatedAt), timeToISO(item.CutoffAt),
				)
				continue
			}

			stageErr := strings.TrimSpace(item.LastStageError)
			if stageErr != "" {
				stageErr = trimForNotify(stageErr, 280)
			}
			if stageErr == "" {
				s.appendJobLogf(item.ProjectID, item.JobID, "warn",
					"worker 鍥炴敹鍓嶆渶鍚庨樁娈? stage=%s status=%s stage_updated_at=%s",
					item.LastStage, item.LastStageStatus, timePtrToISO(item.LastStageUpdatedAt),
				)
				continue
			}
			s.appendJobLogf(item.ProjectID, item.JobID, "warn",
				"worker 鍥炴敹鍓嶆渶鍚庨樁娈? stage=%s status=%s stage_updated_at=%s stage_error=%s",
				item.LastStage, item.LastStageStatus, timePtrToISO(item.LastStageUpdatedAt), stageErr,
			)
		}
	}

	go s.runMonitorScheduler()
	go s.runScanWorker()
	log.Printf("[Worker] execution workers started (monitor poll=%v, scan poll=%v)", schedulerPollInterval, scanWorkerPollInterval)
	select {}
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
	// Auth routes (login is public, check requires auth)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/check", s.handleAuthCheck)

	s.mux.HandleFunc("/api/projects", s.handleProjects)
	s.mux.HandleFunc("/api/dashboard/summary", s.handleDashboard)
	s.mux.HandleFunc("/api/jobs", s.handleJobs)
	s.mux.HandleFunc("/api/jobs/cancel", s.handleCancelJob)
	s.mux.HandleFunc("/api/jobs/delete", s.handleDeleteJob)
	s.mux.HandleFunc("/api/jobs/logs", s.handleJobLogs)
	s.mux.HandleFunc("/api/assets/detail", s.handleAssetDetail)
	s.mux.HandleFunc("/api/assets", s.handleAssets)
	s.mux.HandleFunc("/api/ports", s.handlePorts)
	s.mux.HandleFunc("/api/vulns", s.handleVulns)
	s.mux.HandleFunc("/api/vulns/bulk-status", s.handleBulkVulnStatus)
	s.mux.HandleFunc("/api/vulns/bulk-delete", s.handleBulkDeleteVulns)
	s.mux.HandleFunc("/api/vulns/status", s.handlePatchVulnStatus)
	s.mux.HandleFunc("/api/vulns/events", s.handleVulnEvents)
	s.mux.HandleFunc("/api/graph/relations", s.handleRelations)
	s.mux.HandleFunc("/api/monitor/targets", s.handleMonitorTargets)
	s.mux.HandleFunc("/api/monitor/runs", s.handleMonitorRuns)
	s.mux.HandleFunc("/api/monitor/snapshots", s.handleMonitorSnapshots)
	s.mux.HandleFunc("/api/monitor/diff", s.handleMonitorDiff)
	s.mux.HandleFunc("/api/monitor/changes", s.handleMonitorChanges)
	s.mux.HandleFunc("/api/monitor/events", s.handleMonitorEvents)
	s.mux.HandleFunc("/api/monitor/events/status", s.handleMonitorEventStatus)
	s.mux.HandleFunc("/api/monitor/events/bulk-status", s.handleBulkMonitorEventStatus)
	s.mux.HandleFunc("/api/screenshots/domains", s.handleScreenshotDomains)
	s.mux.HandleFunc("/api/screenshots/delete", s.handleBulkDeleteScreenshots)
	s.mux.HandleFunc("/api/screenshots/file/", s.handleScreenshotFile)
	s.mux.HandleFunc("/api/screenshots/", s.handleScreenshots)
	s.mux.HandleFunc("/api/search", s.handleGlobalSearch)
	s.mux.HandleFunc("/api/bulk/assets/delete", s.handleBulkDeleteAssets)
	s.mux.HandleFunc("/api/settings", s.handleSettings)
	s.mux.HandleFunc("/api/settings/test-notify", s.handleTestNotify)
	s.mux.HandleFunc("/api/settings/test-ai", s.handleTestAI)
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
				AIEnabled:   p.AIEnabled,
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
			AIEnabled:   req.AIEnabled == nil || *req.AIEnabled,
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
		if req.AIEnabled != nil {
			updates["ai_enabled"] = *req.AIEnabled
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
		purgeData := isTruthy(r.URL.Query().Get("purge_data"))
		if !purgeData {
			if err := s.db.ArchiveProject(id); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.writeAudit(id, actorFromRequest(r), "project_archive", "project", id, nil, r)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"status":    "ok",
				"id":        id,
				"purgeData": false,
			})
			return
		}

		rootDomains, err := s.listProjectRootDomains(id)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeError(w, http.StatusNotFound, "project not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if err := s.db.DeleteProjectAndData(id); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				writeError(w, http.StatusNotFound, "project not found")
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		cleanedDirs := s.cleanupScreenshotDirsByRootDomains(id, rootDomains)
		s.writeAudit(id, actorFromRequest(r), "project_delete", "project", id, map[string]interface{}{
			"purgeData":      true,
			"rootDomains":    rootDomains,
			"cleanedScreens": cleanedDirs,
		}, r)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":    "ok",
			"id":        id,
			"purgeData": true,
		})
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
	} else {
		updates["fixed_at"] = nil
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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Monitor Scheduler 鈥?runs in worker process
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (s *Server) runScanWorker() {
	log.Printf("[Worker] scan worker started (poll=%v)", scanWorkerPollInterval)
	ticker := time.NewTicker(scanWorkerPollInterval)
	defer ticker.Stop()

	for range ticker.C {
		job, err := s.db.ClaimPendingScanJob()
		if err != nil {
			log.Printf("[Worker] claim pending scan job failed: %v", err)
			continue
		}
		if job == nil {
			continue
		}
		s.executeClaimedScanJob(job)
	}
}

func (s *Server) executeClaimedScanJob(job *db.ScanJob) {
	if job == nil {
		return
	}
	modules := sanitizeModules(strings.Split(job.Modules, ","))
	enableNuclei := job.EnableNuclei || containsAnyModule(modules, "nuclei")
	activeSubs := job.ActiveSubs || containsAnyModule(modules, "dnsx_bruteforce", "dictgen")
	dictSize := job.DictSize
	dnsResolvers := strings.TrimSpace(job.DNSResolvers)
	dryRun := job.DryRun
	notify := job.Notify
	log.Printf("[Worker] claimed scan job %s project=%s root=%s modules=%v", job.JobID, job.ProjectID, job.RootDomain, modules)
	s.appendJobLogf(job.ProjectID, job.JobID, "info", "Worker 宸查鍙栦换鍔? root=%s modules=%v", job.RootDomain, modules)
	s.runScanAsync(job.ProjectID, job.JobID, job.RootDomain, modules, enableNuclei, activeSubs, dictSize, dnsResolvers, dryRun, notify)
}

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
	if task == nil {
		return
	}
	jobID := fmt.Sprintf("task-%d", task.ID)
	rootDomain := task.RootDomain
	log.Printf("[Scheduler] executing monitor task %d for %s", task.ID, rootDomain)
	s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶浠诲姟寮€濮? root=%s attempt=%d/%d", rootDomain, task.Attempt+1, task.MaxAttempts)

	// Create a monitor run record
	run, err := s.db.CreateMonitorRun(task.ProjectID, rootDomain)
	if err != nil {
		log.Printf("[Scheduler] failed to create monitor run: %v", err)
		s.appendJobLogf(task.ProjectID, jobID, "error", "鍒涘缓 monitor run 澶辫触: %v", err)
		_ = s.db.HandleMonitorTaskFailure(task, fmt.Sprintf("create run failed: %v", err))
		return
	}
	s.appendJobLogf(task.ProjectID, jobID, "debug", "monitor run 宸插垱寤? runID=%d", run.ID)

	target, err := s.db.GetOrCreateMonitorTarget(task.ProjectID, rootDomain)
	if err != nil {
		log.Printf("[Scheduler] failed to get monitor target: %v", err)
		s.appendJobLogf(task.ProjectID, jobID, "error", "璇诲彇鐩戞帶鐩爣澶辫触: %v", err)
		_ = s.db.CompleteMonitorRun(run.ID, "failed", err.Error(), 0, 0, 0, 0, 0)
		_ = s.db.HandleMonitorTaskFailure(task, err.Error())
		return
	}
	establishBaseline := !target.BaselineDone

	// Collect subdomains
	s.appendJobLog(task.ProjectID, jobID, "info", "闃舵寮€濮? 瀛愬煙鏀堕泦")
	subResults, subdomains, err := s.collectSubdomains(context.Background(), []string{rootDomain}, true)
	if err != nil {
		errMsg := fmt.Sprintf("subdomain collection failed: %v", err)
		log.Printf("[Scheduler] %s", errMsg)
		s.appendJobLog(task.ProjectID, jobID, "error", errMsg)
		_ = s.db.CompleteMonitorRun(run.ID, "failed", errMsg, 0, 0, 0, 0, 0)
		_ = s.db.HandleMonitorTaskFailure(task, errMsg)
		return
	}
	s.appendJobLogf(task.ProjectID, jobID, "info", "瀛愬煙鏀堕泦瀹屾垚: unique=%d resultItems=%d", len(subdomains), len(subResults))

	// Run network pipeline (httpx + ports)
	s.appendJobLogf(task.ProjectID, jobID, "info", "闃舵寮€濮? 缃戠粶鎺㈡祴 (targets=%d)", len(subdomains))
	networkResults, err := s.runNetworkPipeline(context.Background(), subdomains, true, target.MonitorPorts, false, false, false, false, s.screenshotDir)
	if err != nil {
		log.Printf("[Scheduler] network pipeline warning for %s: %v", rootDomain, err)
		s.appendJobLogf(task.ProjectID, jobID, "warn", "缃戠粶鎺㈡祴鍛婅: %v", err)
	}
	networkCounts := countResults(networkResults)
	s.appendJobLogf(task.ProjectID, jobID, "info", "缃戠粶鎺㈡祴瀹屾垚: web=%d ports=%d", networkCounts["web_services"], networkCounts["ports"])
	currentSnapshot := buildMonitorSnapshotPayload(networkResults)

	allResults := append(subResults, networkResults...)

	// Save results to DB
	if dbErr := s.saveResultsToDB(task.ProjectID, rootDomain, fmt.Sprintf("mon-run-%d", run.ID), allResults); dbErr != nil {
		log.Printf("[Scheduler] DB save warning: %v", dbErr)
		s.appendJobLogf(task.ProjectID, jobID, "warn", "缁撴灉鍐欏叆鏁版嵁搴撳憡璀? %v", dbErr)
	}

	// Detect changes
	newLive, webChanged, portOpened, portClosed, svcChanged := s.detectChanges(task.ProjectID, rootDomain, run.ID, target, currentSnapshot)
	if snapErr := s.createMonitorSnapshotFromState(task.ProjectID, rootDomain, run.ID, currentSnapshot); snapErr != nil {
		s.appendJobLogf(task.ProjectID, jobID, "warn", "鐩戞帶蹇収鍐欏叆澶辫触: %v", snapErr)
	}

	// Optional: run vulnerability scan for incremental monitor changes.
	policy := monitorVulnPolicyFromTarget(target)
	monitorVulnCount := 0
	if policy.EnableVulnScan && (policy.EnableNuclei || policy.EnableCors || policy.EnableSubtakeover) {
		cooldown := time.Duration(policy.VulnCooldownMin) * time.Minute
		if target.LastVulnScanAt != nil && cooldown > 0 && time.Since(*target.LastVulnScanAt) < cooldown {
			nextAt := target.LastVulnScanAt.Add(cooldown)
			s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶澧為噺婕忔壂鍐峰嵈涓紝璺宠繃鏈疆锛歯ext=%s", timeToISO(nextAt))
		} else {
			vulnTargets, targetErr := s.collectMonitorVulnTargets(task.ProjectID, run.ID, policy.VulnOnNewLive, policy.VulnOnWebChanged, policy.VulnMaxURLs)
			if targetErr != nil {
				s.appendJobLogf(task.ProjectID, jobID, "warn", "鐩戞帶澧為噺婕忔壂鐩爣鎻愬彇澶辫触: %v", targetErr)
			} else if len(vulnTargets) == 0 {
				s.appendJobLog(task.ProjectID, jobID, "info", "鐩戞帶澧為噺婕忔壂璺宠繃锛氭湰杞棤绗﹀悎绛栫暐鐨勫閲?URL")
			} else {
				s.appendJobLogf(task.ProjectID, jobID, "info", "闃舵寮€濮? 澧為噺婕忔礊鎵弿 (urls=%d nuclei=%v cors=%v subtakeover=%v)", len(vulnTargets), policy.EnableNuclei, policy.EnableCors, policy.EnableSubtakeover)
				vulnResults, vulnErr := s.runMonitorVulnPipeline(task.ProjectID, rootDomain, run.ID, vulnTargets, policy.EnableNuclei, policy.EnableCors, policy.EnableSubtakeover)
				if vulnErr != nil {
					s.appendJobLogf(task.ProjectID, jobID, "warn", "鐩戞帶澧為噺婕忔壂鍛婅: %v", vulnErr)
				}
				monitorVulnCount = countResults(vulnResults)["vulnerabilities"]
				s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶澧為噺婕忔壂瀹屾垚: new_vulns=%d", monitorVulnCount)
				_ = s.db.UpdateMonitorTargetLastVulnScan(task.ProjectID, rootDomain, time.Now())
			}
		}
	}

	// Complete run
	status := "success"
	_ = s.db.CompleteMonitorRun(run.ID, status, "", newLive, webChanged, portOpened, portClosed, svcChanged)

	// Update target last run info and establish baseline version on first successful run.
	now := time.Now()
	_ = s.db.UpdateMonitorTargetAfterRun(task.ProjectID, rootDomain, now, establishBaseline)

	// Complete task and schedule next
	_ = s.db.CompleteMonitorTaskSuccess(task.ID)

	totalChanges := newLive + webChanged + portOpened + portClosed + svcChanged
	log.Printf("[Scheduler] monitor task %d completed for %s: %d total changes", task.ID, rootDomain, totalChanges)
	s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶浠诲姟瀹屾垚: changes=%d (new_live=%d web_changed=%d port_opened=%d port_closed=%d service_changed=%d) new_vulns=%d",
		totalChanges, newLive, webChanged, portOpened, portClosed, svcChanged, monitorVulnCount)

	// Send notification if changes detected
	if totalChanges > 0 {
		s.settingsMu.RLock()
		notifyEnabled := s.settings.Notifications.Enabled
		s.settingsMu.RUnlock()
		if notifyEnabled {
			notifier := plugins.NewDingTalkNotifierFromEnv(true)
			if notifier.Enabled() {
				assetLines, omittedAssets, portLines, omittedPorts, notifiedEventIDs, suppressedByWindow, detailErr := s.buildMonitorNotifyDetails(task.ProjectID, run.ID, monitorEventNotifyWindow)
				if detailErr != nil {
					s.appendJobLogf(task.ProjectID, jobID, "warn", "鐩戞帶閫氱煡璇︽儏鏋勫缓澶辫触锛岄檷绾т负鎽樿閫氱煡: %v", detailErr)
				}
				if len(assetLines) == 0 && len(portLines) == 0 {
					s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶閫氱煡琚獥鍙ｆ姂鍒? root=%s window=%s suppressed=%d", rootDomain, monitorEventNotifyWindow, suppressedByWindow)
					return
				}
				stats := map[string]int{
					"new_live": newLive, "web_changed": webChanged,
					"port_opened": portOpened, "port_closed": portClosed,
					"service_changed": svcChanged,
				}
				aiSummary := ""
				if target != nil && target.NotifyAISummary {
					summary, aiErr := s.buildMonitorNotifyAISummary(task.ProjectID, rootDomain, stats, assetLines, portLines, omittedAssets, omittedPorts)
					if aiErr != nil {
						s.appendJobLogf(task.ProjectID, jobID, "warn", "monitor ai summary failed: %v", aiErr)
					} else {
						aiSummary = summary
					}
				}
				if err := notifier.SendMonitorRunDigest(
					task.ProjectID,
					rootDomain,
					run.ID,
					time.Since(run.StartedAt),
					stats,
					assetLines,
					portLines,
					omittedAssets,
					omittedPorts,
					aiSummary,
				); err != nil {
					s.appendJobLogf(task.ProjectID, jobID, "warn", "閫氱煡鍙戦€佸け璐? %v", err)
				} else {
					now := time.Now()
					if len(notifiedEventIDs) > 0 {
						if err := s.db.DB.Model(&db.MonitorEvent{}).
							Where("project_id = ? AND id IN ?", task.ProjectID, notifiedEventIDs).
							Updates(map[string]interface{}{
								"last_notified_at": now,
								"notify_count":     gorm.Expr("COALESCE(notify_count, 0) + 1"),
							}).Error; err != nil {
							s.appendJobLogf(task.ProjectID, jobID, "warn", "閫氱煡鐘舵€佸洖鍐欏け璐? %v", err)
						}
					}
					s.appendJobLogf(task.ProjectID, jobID, "info", "鐩戞帶閫氱煡宸插彂閫? run=%d assets=%d ports=%d notified=%d suppressed=%d",
						run.ID, len(assetLines), len(portLines), len(notifiedEventIDs), suppressedByWindow)
				}
			}
		}
	}
}

// detectChanges compares current run snapshot with the previous successful snapshot.
func (s *Server) detectChanges(projectID, rootDomain string, runID uint, target *db.MonitorTarget, current monitorSnapshotPayload) (newLive, webChanged, portOpened, portClosed, svcChanged int) {
	if target == nil || !target.BaselineDone {
		// First successful run establishes baseline only.
		return 0, 0, 0, 0, 0
	}

	prev, err := s.getPreviousMonitorSnapshotPayload(projectID, rootDomain, runID)
	if err != nil {
		log.Printf("[Monitor] get previous snapshot failed project=%s root=%s run=%d: %v", projectID, rootDomain, runID, err)
		return 0, 0, 0, 0, 0
	}
	if prev == nil {
		return 0, 0, 0, 0, 0
	}

	newLive, webChanged, _ = s.syncLiveMonitorEvents(projectID, rootDomain, runID, prev.LiveAssets, current.LiveAssets)
	if target.MonitorPorts {
		portOpened, portClosed, svcChanged = s.syncPortMonitorEvents(projectID, rootDomain, runID, prev.Ports, current.Ports)
	}

	return newLive, webChanged, portOpened, portClosed, svcChanged
}

func (s *Server) createMonitorSnapshot(projectID, rootDomain string, runID uint) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	rootDomain = normalizeRootDomain(rootDomain)
	if rootDomain == "" || runID == 0 {
		return nil
	}

	state, err := s.buildMonitorSnapshotPayloadFromDB(projectID, rootDomain)
	if err != nil {
		return err
	}
	return s.createMonitorSnapshotFromState(projectID, rootDomain, runID, state)
}

func (s *Server) createMonitorSnapshotFromState(projectID, rootDomain string, runID uint, state monitorSnapshotPayload) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	rootDomain = normalizeRootDomain(rootDomain)
	if rootDomain == "" || runID == 0 {
		return nil
	}

	var openEventCount int64
	if err := s.db.DB.Model(&db.MonitorEvent{}).
		Where("project_id = ? AND root_domain = ? AND status = ?", projectID, rootDomain, monitorEventStatusOpen).
		Count(&openEventCount).Error; err != nil {
		return err
	}

	state.GeneratedAt = timeToISO(time.Now())
	summaryJSON, _ := json.Marshal(state)
	return s.db.SaveMonitorSnapshot(&db.MonitorSnapshot{
		ProjectID:      projectID,
		RootDomain:     rootDomain,
		RunID:          runID,
		AssetCount:     len(state.LiveAssets),
		PortCount:      len(state.Ports),
		OpenEventCount: int(openEventCount),
		Summary:        db.JSONB(summaryJSON),
	})
}

func buildMonitorSnapshotPayload(results []engine.Result) monitorSnapshotPayload {
	liveByKey := make(map[string]monitorSnapshotAssetState)
	portByKey := make(map[string]monitorSnapshotPortState)
	serviceCounts := make(map[string]int)

	for _, result := range results {
		data, ok := result.Data.(map[string]interface{})
		if !ok {
			continue
		}

		switch result.Type {
		case "web_service":
			item, ok := buildMonitorSnapshotAssetState(data)
			if !ok {
				continue
			}
			if existing, exists := liveByKey[item.EventKey]; !exists || shouldReplaceMonitorAssetState(existing, item) {
				liveByKey[item.EventKey] = item
			}
		case "open_port", "port_service":
			item, ok := buildMonitorSnapshotPortState(data)
			if !ok {
				continue
			}
			if existing, exists := portByKey[item.EventKey]; !exists || shouldReplaceMonitorPortState(existing, item) {
				portByKey[item.EventKey] = item
			}
		}
	}

	liveAssets := make([]monitorSnapshotAssetState, 0, len(liveByKey))
	for _, item := range liveByKey {
		liveAssets = append(liveAssets, item)
	}
	sort.Slice(liveAssets, func(i, j int) bool {
		return liveAssets[i].EventKey < liveAssets[j].EventKey
	})

	ports := make([]monitorSnapshotPortState, 0, len(portByKey))
	for _, item := range portByKey {
		ports = append(ports, item)
		serviceName := strings.TrimSpace(item.Service)
		if serviceName == "" {
			serviceName = "unknown"
		}
		serviceCounts[serviceName]++
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].EventKey < ports[j].EventKey
	})

	serviceDistribution := buildMonitorSnapshotServiceDistribution(serviceCounts)
	return monitorSnapshotPayload{
		ServiceDistribution: serviceDistribution,
		GeneratedAt:         timeToISO(time.Now()),
		LiveAssets:          liveAssets,
		Ports:               ports,
	}
}

func buildMonitorSnapshotAssetState(data map[string]interface{}) (monitorSnapshotAssetState, bool) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "domain")), "."))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "host")), "."))
	}
	rawURL := strings.TrimSpace(mapString(data, "url"))
	if rawURL == "" {
		return monitorSnapshotAssetState{}, false
	}

	host, ip, port := buildMonitorLiveIdentity(domain, rawURL, mapString(data, "ip"))
	eventKey := buildMonitorLiveEventKey(host, ip, port)
	if eventKey == "" {
		return monitorSnapshotAssetState{}, false
	}
	displayDomain := host
	if displayDomain == "" {
		displayDomain = domain
	}

	return monitorSnapshotAssetState{
		EventKey:     eventKey,
		Domain:       displayDomain,
		URL:          rawURL,
		IP:           ip,
		Port:         port,
		StatusCode:   mapInt(data, "status_code"),
		Title:        strings.TrimSpace(mapString(data, "title")),
		Technologies: normalizeStringSlice(data["technologies"]),
	}, true
}

func buildMonitorSnapshotPortState(data map[string]interface{}) (monitorSnapshotPortState, bool) {
	ip := strings.TrimSpace(mapString(data, "ip"))
	port := mapInt(data, "port")
	if ip == "" || port <= 0 {
		return monitorSnapshotPortState{}, false
	}

	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "domain")), "."))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "host")), "."))
	}
	protocol := strings.ToLower(strings.TrimSpace(mapString(data, "protocol")))
	if protocol == "" {
		protocol = "tcp"
	}
	eventKey := buildMonitorPortEventKey(domain, ip, port, protocol)
	if eventKey == "" {
		return monitorSnapshotPortState{}, false
	}

	return monitorSnapshotPortState{
		EventKey: eventKey,
		Domain:   normalizeMonitorHost(domain),
		IP:       ip,
		Port:     port,
		Protocol: protocol,
		Service:  strings.TrimSpace(mapString(data, "service")),
		Version:  strings.TrimSpace(mapString(data, "version")),
	}, true
}

func shouldReplaceMonitorAssetState(existing, candidate monitorSnapshotAssetState) bool {
	existingScore := monitorAssetStateQuality(existing)
	candidateScore := monitorAssetStateQuality(candidate)
	if candidateScore != existingScore {
		return candidateScore > existingScore
	}
	return len(candidate.URL) > len(existing.URL)
}

func shouldReplaceMonitorPortState(existing, candidate monitorSnapshotPortState) bool {
	existingScore := monitorPortStateQuality(existing)
	candidateScore := monitorPortStateQuality(candidate)
	if candidateScore != existingScore {
		return candidateScore > existingScore
	}
	return len(candidate.Domain) > len(existing.Domain)
}

func monitorAssetStateQuality(item monitorSnapshotAssetState) int {
	score := 0
	if strings.TrimSpace(item.URL) != "" {
		score += 4
	}
	if item.StatusCode > 0 {
		score += 2
	}
	if strings.TrimSpace(item.Title) != "" {
		score += 2
	}
	if len(item.Technologies) > 0 {
		score++
	}
	return score
}

func monitorPortStateQuality(item monitorSnapshotPortState) int {
	score := 0
	if strings.TrimSpace(item.Domain) != "" {
		score += 2
	}
	if strings.TrimSpace(item.Service) != "" {
		score += 2
	}
	if strings.TrimSpace(item.Version) != "" {
		score++
	}
	return score
}

func buildMonitorSnapshotServiceDistribution(serviceCounts map[string]int) []dashboardCountItemResponse {
	items := make([]dashboardCountItemResponse, 0, len(serviceCounts))
	for name, count := range serviceCounts {
		serviceName := strings.TrimSpace(name)
		if serviceName == "" {
			serviceName = "unknown"
		}
		items = append(items, dashboardCountItemResponse{Name: serviceName, Value: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		return items[i].Name < items[j].Name
	})
	if len(items) > 10 {
		items = items[:10]
	}
	return items
}

func normalizeStringSlice(raw interface{}) []string {
	if raw == nil {
		return nil
	}

	seen := make(map[string]bool)
	out := make([]string, 0, 8)
	appendValue := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	switch vv := raw.(type) {
	case []string:
		for _, item := range vv {
			appendValue(item)
		}
	case []interface{}:
		for _, item := range vv {
			if text, ok := item.(string); ok {
				appendValue(text)
			}
		}
	}

	sort.Strings(out)
	return out
}

func mustMarshalStringSlice(items []string) []byte {
	if len(items) == 0 {
		data, _ := json.Marshal([]string{})
		return data
	}
	data, _ := json.Marshal(items)
	return data
}

func monitorSnapshotHasState(data db.JSONB) bool {
	if len(data) == 0 {
		return false
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	_, hasLive := raw["liveAssets"]
	_, hasPorts := raw["ports"]
	return hasLive || hasPorts
}

func (s *Server) getPreviousMonitorSnapshotPayload(projectID, rootDomain string, currentRunID uint) (*monitorSnapshotPayload, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	rootDomain = normalizeRootDomain(rootDomain)
	if rootDomain == "" || currentRunID == 0 {
		return nil, nil
	}

	var snap db.MonitorSnapshot
	err := s.db.DB.Model(&db.MonitorSnapshot{}).
		Joins("JOIN monitor_runs mr ON mr.id = monitor_snapshots.run_id AND mr.project_id = monitor_snapshots.project_id AND mr.root_domain = monitor_snapshots.root_domain AND mr.deleted_at IS NULL").
		Where("monitor_snapshots.project_id = ? AND monitor_snapshots.root_domain = ? AND monitor_snapshots.run_id < ? AND mr.status = ?", projectID, rootDomain, currentRunID, "success").
		Order("monitor_snapshots.run_id desc").
		First(&snap).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !monitorSnapshotHasState(snap.Summary) {
		return nil, nil
	}

	payload, err := decodeMonitorSnapshotPayload(snap.Summary)
	if err != nil {
		return nil, err
	}
	return &payload, nil
}

func decodeMonitorSnapshotPayload(data db.JSONB) (monitorSnapshotPayload, error) {
	if len(data) == 0 {
		return monitorSnapshotPayload{}, nil
	}
	var payload monitorSnapshotPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return monitorSnapshotPayload{}, err
	}
	if payload.LiveAssets == nil {
		payload.LiveAssets = []monitorSnapshotAssetState{}
	}
	if payload.Ports == nil {
		payload.Ports = []monitorSnapshotPortState{}
	}
	if payload.ServiceDistribution == nil {
		payload.ServiceDistribution = []dashboardCountItemResponse{}
	}
	return payload, nil
}

func (s *Server) buildMonitorSnapshotPayloadFromDB(projectID, rootDomain string) (monitorSnapshotPayload, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	rootDomain = normalizeRootDomain(rootDomain)
	if rootDomain == "" {
		return monitorSnapshotPayload{}, nil
	}

	pattern := "%." + rootDomain
	var assets []db.Asset
	if err := s.db.DB.Model(&db.Asset{}).
		Where("project_id = ? AND (root_domain = ? OR domain = ? OR domain LIKE ?) AND status_code > 0 AND BTRIM(COALESCE(url, '')) <> ''",
			projectID, rootDomain, rootDomain, pattern).
		Find(&assets).Error; err != nil {
		return monitorSnapshotPayload{}, err
	}

	var ports []db.Port
	if err := s.db.DB.Model(&db.Port{}).
		Where("project_id = ? AND (root_domain = ? OR domain = ? OR domain LIKE ?)", projectID, rootDomain, rootDomain, pattern).
		Find(&ports).Error; err != nil {
		return monitorSnapshotPayload{}, err
	}

	liveStates := make([]monitorSnapshotAssetState, 0, len(assets))
	liveByKey := make(map[string]monitorSnapshotAssetState)
	for _, asset := range assets {
		host, ip, port := buildMonitorLiveIdentity(asset.Domain, asset.URL, asset.IP)
		eventKey := buildMonitorLiveEventKey(host, ip, port)
		if eventKey == "" {
			continue
		}
		item := monitorSnapshotAssetState{
			EventKey:     eventKey,
			Domain:       host,
			URL:          asset.URL,
			IP:           ip,
			Port:         port,
			StatusCode:   asset.StatusCode,
			Title:        strings.TrimSpace(asset.Title),
			Technologies: decodeJSONBStrings(asset.Technologies),
		}
		if existing, exists := liveByKey[eventKey]; !exists || shouldReplaceMonitorAssetState(existing, item) {
			liveByKey[eventKey] = item
		}
	}
	for _, item := range liveByKey {
		liveStates = append(liveStates, item)
	}
	sort.Slice(liveStates, func(i, j int) bool { return liveStates[i].EventKey < liveStates[j].EventKey })

	portStates := make([]monitorSnapshotPortState, 0, len(ports))
	portByKey := make(map[string]monitorSnapshotPortState)
	serviceCounts := make(map[string]int)
	for _, port := range ports {
		eventKey := buildMonitorPortEventKey(port.Domain, port.IP, port.Port, port.Protocol)
		if eventKey == "" {
			continue
		}
		item := monitorSnapshotPortState{
			EventKey: eventKey,
			Domain:   normalizeMonitorHost(port.Domain),
			IP:       strings.TrimSpace(port.IP),
			Port:     port.Port,
			Protocol: strings.ToLower(strings.TrimSpace(port.Protocol)),
			Service:  strings.TrimSpace(port.Service),
			Version:  strings.TrimSpace(port.Version),
		}
		if existing, exists := portByKey[eventKey]; !exists || shouldReplaceMonitorPortState(existing, item) {
			portByKey[eventKey] = item
		}
	}
	for _, item := range portByKey {
		portStates = append(portStates, item)
		serviceName := strings.TrimSpace(item.Service)
		if serviceName == "" {
			serviceName = "unknown"
		}
		serviceCounts[serviceName]++
	}
	sort.Slice(portStates, func(i, j int) bool { return portStates[i].EventKey < portStates[j].EventKey })

	return monitorSnapshotPayload{
		ServiceDistribution: buildMonitorSnapshotServiceDistribution(serviceCounts),
		GeneratedAt:         timeToISO(time.Now()),
		LiveAssets:          liveStates,
		Ports:               portStates,
	}, nil
}

func (s *Server) collectMonitorVulnTargets(projectID string, runID uint, includeNewLive, includeWebChanged bool, limit int) ([]string, error) {
	types := make([]string, 0, 2)
	if includeNewLive {
		types = append(types, "new_live")
	}
	if includeWebChanged {
		types = append(types, "web_changed")
	}
	if len(types) == 0 || runID == 0 {
		return []string{}, nil
	}
	limit = clampMonitorVulnMaxURLs(limit)

	var rows []db.AssetChange
	queryLimit := limit * 4
	if queryLimit < 100 {
		queryLimit = 100
	}
	if queryLimit > 2000 {
		queryLimit = 2000
	}
	if err := s.db.DB.
		Where("project_id = ? AND run_id = ? AND change_type IN ? AND BTRIM(COALESCE(url, '')) <> ''", projectID, runID, types).
		Order("id desc").
		Limit(queryLimit).
		Find(&rows).Error; err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(rows))
	urls := make([]string, 0, limit)
	for _, row := range rows {
		u := strings.TrimSpace(row.URL)
		if u == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(u, "/"))
		if seen[key] {
			continue
		}
		seen[key] = true
		urls = append(urls, u)
		if len(urls) >= limit {
			break
		}
	}
	return urls, nil
}

func (s *Server) runMonitorVulnPipeline(projectID, rootDomain string, runID uint, urls []string, enableNuclei, enableCors, enableSubtakeover bool) ([]engine.Result, error) {
	if len(urls) == 0 {
		return []engine.Result{}, nil
	}

	inputs := make([]string, 0, len(urls))
	for _, u := range urls {
		trimmed := strings.TrimSpace(u)
		if trimmed == "" {
			continue
		}
		inputs = append(inputs, trimmed+"|"+rootDomain)
	}
	if len(inputs) == 0 {
		return []engine.Result{}, nil
	}

	allResults := make([]engine.Result, 0, 64)
	var firstErr error

	if enableNuclei {
		nucleiResults, err := plugins.NewNucleiPlugin().Execute(context.Background(), inputs)
		if err != nil {
			firstErr = err
		}
		allResults = append(allResults, nucleiResults...)
	}
	if enableCors {
		corsResults, err := plugins.NewCorsPlugin().Execute(context.Background(), inputs)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		allResults = append(allResults, corsResults...)
	}
	if enableSubtakeover {
		subtakeoverResults, err := plugins.NewSubTakeoverPlugin().Execute(context.Background(), inputs)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		allResults = append(allResults, subtakeoverResults...)
	}

	if len(allResults) > 0 {
		jobID := fmt.Sprintf("mon-run-%d-vuln", runID)
		if err := s.saveResultsToDB(projectID, rootDomain, jobID, allResults); err != nil {
			if firstErr == nil {
				firstErr = err
			} else {
				firstErr = fmt.Errorf("%v; save vuln results failed: %w", firstErr, err)
			}
		}
	}
	return allResults, firstErr
}

func (s *Server) syncLiveMonitorEvents(projectID, rootDomain string, runID uint, previous, current []monitorSnapshotAssetState) (opened, webChanged, resolved int) {
	now := time.Now()
	prevSeen := make(map[string]monitorSnapshotAssetState, len(previous))
	for _, item := range previous {
		if strings.TrimSpace(item.EventKey) == "" {
			continue
		}
		prevSeen[item.EventKey] = item
	}
	currSeen := make(map[string]monitorSnapshotAssetState, len(current))
	for _, item := range current {
		if strings.TrimSpace(item.EventKey) == "" || strings.TrimSpace(item.URL) == "" {
			continue
		}
		currSeen[item.EventKey] = item
	}

	var existing []db.MonitorEvent
	if err := s.db.DB.
		Where("project_id = ? AND root_domain = ? AND event_type = ?", projectID, rootDomain, "new_live").
		Find(&existing).Error; err != nil {
		log.Printf("[Monitor] query live events failed project=%s root=%s: %v", projectID, rootDomain, err)
		return 0, 0, 0
	}
	existingByKey := make(map[string]db.MonitorEvent, len(existing))
	for _, e := range existing {
		existingByKey[e.EventKey] = e
	}

	for key, a := range currSeen {
		e, exists := existingByKey[key]
		legacyMatched := ""
		legacyKey := buildMonitorLegacyLiveEventKey(a.Domain)
		legacyIPKey := buildMonitorLiveEventKeyWithIP(normalizeMonitorHost(a.Domain), a.IP, a.Port)
		if !exists && legacyKey != "" {
			if legacyEvent, ok := existingByKey[legacyKey]; ok {
				e = legacyEvent
				exists = true
				legacyMatched = legacyKey
			}
		}
		if !exists && legacyIPKey != "" {
			if legacyEvent, ok := existingByKey[legacyIPKey]; ok {
				e = legacyEvent
				exists = true
				legacyMatched = legacyIPKey
			}
		}
		displayDomain := normalizeMonitorHost(a.Domain)
		if displayDomain == "" {
			displayDomain = strings.ToLower(strings.TrimSpace(a.Domain))
		}
		_, wasPresent := prevSeen[key]
		if !exists {
			event := db.MonitorEvent{
				ProjectID:       projectID,
				RootDomain:      rootDomain,
				EventKey:        key,
				EventType:       "new_live",
				Status:          monitorEventStatusOpen,
				Domain:          displayDomain,
				URL:             a.URL,
				IP:              a.IP,
				Port:            a.Port,
				Title:           a.Title,
				StatusCode:      a.StatusCode,
				FirstSeenAt:     now,
				LastSeenAt:      now,
				LastChangedAt:   now,
				OccurrenceCount: 1,
				LastRunID:       runID,
			}
			if err := s.db.DB.Create(&event).Error; err != nil {
				log.Printf("[Monitor] create live event failed key=%s: %v", key, err)
				continue
			}
			if !wasPresent {
				opened++
			}
			_ = s.db.SaveAssetChange(&db.AssetChange{
				ProjectID:    projectID,
				RunID:        runID,
				RootDomain:   rootDomain,
				ChangeType:   "new_live",
				Domain:       displayDomain,
				IP:           a.IP,
				Port:         a.Port,
				URL:          a.URL,
				StatusCode:   a.StatusCode,
				Title:        a.Title,
				Technologies: db.JSONB(mustMarshalStringSlice(a.Technologies)),
			})
			continue
		}

		updates := map[string]interface{}{
			"domain":           displayDomain,
			"url":              a.URL,
			"ip":               a.IP,
			"port":             a.Port,
			"title":            a.Title,
			"status_code":      a.StatusCode,
			"last_seen_at":     now,
			"occurrence_count": e.OccurrenceCount + 1,
			"last_run_id":      runID,
		}
		if legacyMatched != "" {
			updates["event_key"] = key
		}

		if !wasPresent || strings.EqualFold(strings.TrimSpace(e.Status), monitorEventStatusResolved) {
			updates["status"] = monitorEventStatusOpen
			updates["resolved_at"] = nil
			updates["last_changed_at"] = now
			opened++
			_ = s.db.SaveAssetChange(&db.AssetChange{
				ProjectID:    projectID,
				RunID:        runID,
				RootDomain:   rootDomain,
				ChangeType:   "new_live",
				Domain:       displayDomain,
				IP:           a.IP,
				Port:         a.Port,
				URL:          a.URL,
				StatusCode:   a.StatusCode,
				Title:        a.Title,
				Technologies: db.JSONB(mustMarshalStringSlice(a.Technologies)),
			})
		} else if prev := prevSeen[key]; prev.StatusCode != a.StatusCode || strings.TrimSpace(prev.Title) != strings.TrimSpace(a.Title) {
			updates["last_changed_at"] = now
			webChanged++
			_ = s.db.SaveAssetChange(&db.AssetChange{
				ProjectID:    projectID,
				RunID:        runID,
				RootDomain:   rootDomain,
				ChangeType:   "web_changed",
				Domain:       displayDomain,
				IP:           a.IP,
				Port:         a.Port,
				URL:          a.URL,
				StatusCode:   a.StatusCode,
				Title:        a.Title,
				Technologies: db.JSONB(mustMarshalStringSlice(a.Technologies)),
			})
		}

		if err := s.db.DB.Model(&db.MonitorEvent{}).Where("id = ?", e.ID).Updates(updates).Error; err != nil {
			log.Printf("[Monitor] update live event failed id=%d: %v", e.ID, err)
		}
	}

	for key, prev := range prevSeen {
		if _, stillPresent := currSeen[key]; stillPresent {
			continue
		}
		e, exists := existingByKey[key]
		if !exists {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(e.Status), monitorEventStatusResolved) {
			continue
		}
		if err := s.db.DB.Model(&db.MonitorEvent{}).Where("id = ?", e.ID).Updates(map[string]interface{}{
			"status":          monitorEventStatusResolved,
			"resolved_at":     now,
			"last_changed_at": now,
			"last_run_id":     runID,
		}).Error; err != nil {
			log.Printf("[Monitor] resolve live event failed id=%d: %v", e.ID, err)
			continue
		}
		resolved++
		_ = s.db.SaveAssetChange(&db.AssetChange{
			ProjectID:  projectID,
			RunID:      runID,
			RootDomain: rootDomain,
			ChangeType: "live_resolved",
			Domain:     prev.Domain,
			IP:         prev.IP,
			Port:       prev.Port,
			URL:        prev.URL,
			StatusCode: prev.StatusCode,
			Title:      prev.Title,
		})
	}

	return opened, webChanged, resolved
}

func (s *Server) syncPortMonitorEvents(projectID, rootDomain string, runID uint, previous, current []monitorSnapshotPortState) (opened, closed, serviceChanged int) {
	now := time.Now()
	prevSeen := make(map[string]monitorSnapshotPortState, len(previous))
	for _, item := range previous {
		if strings.TrimSpace(item.EventKey) == "" {
			continue
		}
		prevSeen[item.EventKey] = item
	}
	currSeen := make(map[string]monitorSnapshotPortState, len(current))
	for _, item := range current {
		if strings.TrimSpace(item.EventKey) == "" {
			continue
		}
		currSeen[item.EventKey] = item
	}

	var existing []db.MonitorEvent
	if err := s.db.DB.
		Where("project_id = ? AND root_domain = ? AND event_type = ?", projectID, rootDomain, "port_opened").
		Find(&existing).Error; err != nil {
		log.Printf("[Monitor] query port events failed project=%s root=%s: %v", projectID, rootDomain, err)
		return 0, 0, 0
	}
	existingByKey := make(map[string]db.MonitorEvent, len(existing))
	for _, e := range existing {
		existingByKey[e.EventKey] = e
	}

	for key, p := range currSeen {
		e, exists := existingByKey[key]
		_, wasPresent := prevSeen[key]
		if !exists {
			event := db.MonitorEvent{
				ProjectID:       projectID,
				RootDomain:      rootDomain,
				EventKey:        key,
				EventType:       "port_opened",
				Status:          monitorEventStatusOpen,
				Domain:          normalizeMonitorHost(p.Domain),
				IP:              p.IP,
				Port:            p.Port,
				Protocol:        p.Protocol,
				Service:         p.Service,
				Version:         p.Version,
				FirstSeenAt:     now,
				LastSeenAt:      now,
				LastChangedAt:   now,
				OccurrenceCount: 1,
				LastRunID:       runID,
			}
			if err := s.db.DB.Create(&event).Error; err != nil {
				log.Printf("[Monitor] create port event failed key=%s: %v", key, err)
				continue
			}
			if !wasPresent {
				opened++
			}
			_ = s.db.SavePortChange(&db.PortChange{
				ProjectID:  projectID,
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "opened",
				Domain:     normalizeMonitorHost(p.Domain),
				IP:         p.IP,
				Port:       p.Port,
				Protocol:   p.Protocol,
				Service:    p.Service,
				Version:    p.Version,
			})
			continue
		}

		updates := map[string]interface{}{
			"domain":           normalizeMonitorHost(p.Domain),
			"ip":               p.IP,
			"port":             p.Port,
			"protocol":         p.Protocol,
			"service":          p.Service,
			"version":          p.Version,
			"last_seen_at":     now,
			"occurrence_count": e.OccurrenceCount + 1,
			"last_run_id":      runID,
		}

		if !wasPresent || strings.EqualFold(strings.TrimSpace(e.Status), monitorEventStatusResolved) {
			updates["status"] = monitorEventStatusOpen
			updates["resolved_at"] = nil
			updates["last_changed_at"] = now
			opened++
			_ = s.db.SavePortChange(&db.PortChange{
				ProjectID:  projectID,
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "opened",
				Domain:     normalizeMonitorHost(p.Domain),
				IP:         p.IP,
				Port:       p.Port,
				Protocol:   p.Protocol,
				Service:    p.Service,
				Version:    p.Version,
			})
		} else if prev := prevSeen[key]; strings.TrimSpace(prev.Service) != strings.TrimSpace(p.Service) || strings.TrimSpace(prev.Version) != strings.TrimSpace(p.Version) {
			updates["last_changed_at"] = now
			serviceChanged++
			_ = s.db.SavePortChange(&db.PortChange{
				ProjectID:  projectID,
				RunID:      runID,
				RootDomain: rootDomain,
				ChangeType: "service_changed",
				Domain:     normalizeMonitorHost(p.Domain),
				IP:         p.IP,
				Port:       p.Port,
				Protocol:   p.Protocol,
				Service:    p.Service,
				Version:    p.Version,
			})
		}

		if err := s.db.DB.Model(&db.MonitorEvent{}).Where("id = ?", e.ID).Updates(updates).Error; err != nil {
			log.Printf("[Monitor] update port event failed id=%d: %v", e.ID, err)
		}
	}

	for key, prev := range prevSeen {
		if _, stillPresent := currSeen[key]; stillPresent {
			continue
		}
		e, exists := existingByKey[key]
		if !exists {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(e.Status), monitorEventStatusResolved) {
			continue
		}
		if err := s.db.DB.Model(&db.MonitorEvent{}).Where("id = ?", e.ID).Updates(map[string]interface{}{
			"status":          monitorEventStatusResolved,
			"resolved_at":     now,
			"last_changed_at": now,
			"last_run_id":     runID,
		}).Error; err != nil {
			log.Printf("[Monitor] resolve port event failed id=%d: %v", e.ID, err)
			continue
		}
		closed++
		_ = s.db.SavePortChange(&db.PortChange{
			ProjectID:  projectID,
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

	return opened, closed, serviceChanged
}

func (s *Server) buildMonitorNotifyDetails(projectID string, runID uint, window time.Duration) (assetLines []string, omittedAssets int, portLines []string, omittedPorts int, notifiedEventIDs []uint, suppressedByWindow int, err error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	if runID == 0 {
		return nil, 0, nil, 0, nil, 0, nil
	}

	type notifyItem struct {
		eventKey string
		line     string
	}

	var assetChanges []db.AssetChange
	if err := s.db.DB.
		Where("project_id = ? AND run_id = ? AND change_type IN ?", projectID, runID, []string{"new_live", "web_changed"}).
		Order("id desc").
		Limit(300).
		Find(&assetChanges).Error; err != nil {
		return nil, 0, nil, 0, nil, 0, err
	}

	sort.SliceStable(assetChanges, func(i, j int) bool {
		ai := monitorAssetChangePriority(assetChanges[i].ChangeType)
		aj := monitorAssetChangePriority(assetChanges[j].ChangeType)
		if ai != aj {
			return ai < aj
		}
		return assetChanges[i].ID > assetChanges[j].ID
	})

	assetItems := make([]notifyItem, 0, len(assetChanges))
	assetSeen := make(map[string]bool, len(assetChanges))
	allKeys := make([]string, 0, len(assetChanges))
	for _, ch := range assetChanges {
		key := buildMonitorLiveEventKey(ch.Domain, ch.IP, ch.Port)
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(ch.URL))
		}
		if key == "" {
			key = fmt.Sprintf("new_live|%s|%s|%d", strings.ToLower(strings.TrimSpace(ch.Domain)), strings.TrimSpace(ch.IP), ch.Port)
		}
		if key == "" || assetSeen[key] {
			continue
		}
		assetSeen[key] = true
		assetItems = append(assetItems, notifyItem{eventKey: key, line: formatMonitorAssetNotifyLine(ch)})
		allKeys = append(allKeys, key)
	}

	var portChanges []db.PortChange
	if err := s.db.DB.
		Where("project_id = ? AND run_id = ? AND change_type IN ?", projectID, runID, []string{"opened", "closed", "service_changed"}).
		Order("id desc").
		Limit(400).
		Find(&portChanges).Error; err != nil {
		return nil, 0, nil, 0, nil, 0, err
	}

	sort.SliceStable(portChanges, func(i, j int) bool {
		pi := monitorPortChangePriority(portChanges[i].ChangeType)
		pj := monitorPortChangePriority(portChanges[j].ChangeType)
		if pi != pj {
			return pi < pj
		}
		return portChanges[i].ID > portChanges[j].ID
	})

	portItems := make([]notifyItem, 0, len(portChanges))
	portSeen := make(map[string]bool, len(portChanges))
	for _, ch := range portChanges {
		key := buildMonitorPortEventKey(ch.Domain, ch.IP, ch.Port, ch.Protocol)
		if key == "" {
			proto := strings.ToLower(strings.TrimSpace(ch.Protocol))
			key = fmt.Sprintf("port_opened|%s|%s|%d|%s", strings.TrimSpace(ch.Domain), strings.TrimSpace(ch.IP), ch.Port, proto)
		}
		if portSeen[key] {
			continue
		}
		portSeen[key] = true
		portItems = append(portItems, notifyItem{eventKey: key, line: formatMonitorPortNotifyLine(ch)})
		allKeys = append(allKeys, key)
	}

	eventByKey := map[string]db.MonitorEvent{}
	if len(allKeys) > 0 {
		var events []db.MonitorEvent
		if err := s.db.DB.Where("project_id = ? AND event_key IN ?", projectID, dedupTrimmed(allKeys)).Find(&events).Error; err != nil {
			return nil, 0, nil, 0, nil, 0, err
		}
		for _, e := range events {
			eventByKey[e.EventKey] = e
		}
	}

	now := time.Now()
	cutoff := time.Time{}
	if window > 0 {
		cutoff = now.Add(-window)
	}
	notifiedSet := map[uint]bool{}

	appendAllowed := func(items []notifyItem, limit int) (lines []string, omitted int) {
		lines = make([]string, 0, limit)
		totalAllowed := 0
		for _, item := range items {
			if evt, ok := eventByKey[item.eventKey]; ok {
				if !cutoff.IsZero() && evt.LastNotifiedAt != nil && evt.LastNotifiedAt.After(cutoff) {
					suppressedByWindow++
					continue
				}
				notifiedSet[evt.ID] = true
			}
			totalAllowed++
			if len(lines) < limit {
				lines = append(lines, item.line)
			}
		}
		omitted = totalAllowed - len(lines)
		return lines, omitted
	}

	assetLines, omittedAssets = appendAllowed(assetItems, monitorNotifyMaxAssets)
	portLines, omittedPorts = appendAllowed(portItems, monitorNotifyMaxPorts)

	notifiedEventIDs = make([]uint, 0, len(notifiedSet))
	for id := range notifiedSet {
		notifiedEventIDs = append(notifiedEventIDs, id)
	}
	sort.Slice(notifiedEventIDs, func(i, j int) bool { return notifiedEventIDs[i] < notifiedEventIDs[j] })

	return assetLines, omittedAssets, portLines, omittedPorts, notifiedEventIDs, suppressedByWindow, nil
}

func (s *Server) buildMonitorNotifyAISummary(
	projectID, rootDomain string,
	stats map[string]int,
	assetLines, portLines []string,
	omittedAssets, omittedPorts int,
) (string, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}

	s.settingsMu.RLock()
	cfg := normalizeRuntimeAISettings(s.settings.AI)
	s.settingsMu.RUnlock()
	if !cfg.Enabled {
		return "", nil
	}

	projectAIEnabled, err := s.isProjectAIEnabled(projectID)
	if err != nil {
		return "", err
	}
	if !projectAIEnabled {
		return "", nil
	}

	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.APIKey) == "" || strings.TrimSpace(cfg.Model) == "" {
		return "", fmt.Errorf("ai settings not configured")
	}

	trimLines := func(lines []string, limit int) []string {
		if len(lines) == 0 || limit <= 0 {
			return nil
		}
		if len(lines) > limit {
			return lines[:limit]
		}
		return lines
	}
	assetPreview := trimLines(assetLines, 8)
	portPreview := trimLines(portLines, 8)

	var prompt strings.Builder
	prompt.WriteString("You are a security monitoring assistant.\n")
	prompt.WriteString("Generate a concise Simplified-Chinese digest from the monitor run data.\n")
	prompt.WriteString("Output exactly 3 bullet points, each <= 60 Chinese characters.\n")
	prompt.WriteString("1) New live/web-changed assets highlights.\n")
	prompt.WriteString("2) Port/service changes and risk judgment.\n")
	prompt.WriteString("3) Next actions in priority order.\n")
	prompt.WriteString("If risk is low, explicitly say low noise.\n")
	prompt.WriteString(fmt.Sprintf("Project: %s\n", projectID))
	prompt.WriteString(fmt.Sprintf("RootDomain: %s\n", strings.TrimSpace(rootDomain)))
	prompt.WriteString(fmt.Sprintf(
		"Stats: new_live=%d web_changed=%d port_opened=%d port_closed=%d service_changed=%d\n",
		stats["new_live"], stats["web_changed"], stats["port_opened"], stats["port_closed"], stats["service_changed"],
	))
	if len(assetPreview) > 0 {
		prompt.WriteString("AssetLines:\n")
		for _, line := range assetPreview {
			prompt.WriteString("- ")
			prompt.WriteString(strings.TrimSpace(line))
			prompt.WriteString("\n")
		}
		if omittedAssets > 0 {
			prompt.WriteString(fmt.Sprintf("- omitted_assets=%d\n", omittedAssets))
		}
	}
	if len(portPreview) > 0 {
		prompt.WriteString("PortLines:\n")
		for _, line := range portPreview {
			prompt.WriteString("- ")
			prompt.WriteString(strings.TrimSpace(line))
			prompt.WriteString("\n")
		}
		if omittedPorts > 0 {
			prompt.WriteString(fmt.Sprintf("- omitted_ports=%d\n", omittedPorts))
		}
	}

	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	reply, _, err := s.testOpenAICompatible(ctx, cfg, prompt.String())
	if err != nil {
		return "", err
	}
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return "", fmt.Errorf("ai summary is empty")
	}
	return trimForNotify(reply, 1200), nil
}

func monitorPortChangePriority(changeType string) int {
	switch strings.ToLower(strings.TrimSpace(changeType)) {
	case "opened":
		return 0
	case "service_changed":
		return 1
	case "closed":
		return 2
	default:
		return 3
	}
}

func monitorAssetChangePriority(changeType string) int {
	switch strings.ToLower(strings.TrimSpace(changeType)) {
	case "new_live":
		return 0
	case "web_changed":
		return 1
	default:
		return 2
	}
}

func formatMonitorAssetNotifyLine(ch db.AssetChange) string {
	target := strings.TrimSpace(ch.URL)
	if target == "" {
		target = strings.TrimSpace(ch.Domain)
	}
	if target == "" && strings.TrimSpace(ch.IP) != "" && ch.Port > 0 {
		target = fmt.Sprintf("%s:%d", strings.TrimSpace(ch.IP), ch.Port)
	}
	if target == "" {
		target = "-"
	}

	statusText := "-"
	if ch.StatusCode > 0 {
		statusText = strconv.Itoa(ch.StatusCode)
	}
	title := strings.TrimSpace(ch.Title)
	if title == "" {
		title = "-"
	}

	techs := decodeJSONBStrings(ch.Technologies)
	techText := "-"
	if len(techs) > 0 {
		if len(techs) > 6 {
			techs = append(techs[:6], "...")
		}
		techText = strings.Join(techs, ", ")
	}
	label := "NEW"
	if strings.EqualFold(strings.TrimSpace(ch.ChangeType), "web_changed") {
		label = "CHANGED"
	}
	return fmt.Sprintf("[%s %s] %s | %s | %s",
		label,
		statusText,
		trimForNotify(target, 110),
		trimForNotify(title, 70),
		trimForNotify(techText, 70),
	)
}

func formatMonitorPortNotifyLine(ch db.PortChange) string {
	action := "CHANGED"
	switch strings.ToLower(strings.TrimSpace(ch.ChangeType)) {
	case "opened":
		action = "OPEN"
	case "closed":
		action = "CLOSED"
	case "service_changed":
		action = "CHANGED"
	}

	target := strings.TrimSpace(ch.Domain)
	ip := strings.TrimSpace(ch.IP)
	if target == "" {
		target = ip
	} else if ip != "" && !strings.EqualFold(target, ip) {
		target = target + " (" + ip + ")"
	}
	if target == "" {
		target = "-"
	}

	proto := strings.ToLower(strings.TrimSpace(ch.Protocol))
	if proto == "" {
		proto = "tcp"
	}

	svc := strings.TrimSpace(ch.Service)
	ver := strings.TrimSpace(ch.Version)
	svcText := "-"
	if svc != "" {
		svcText = svc
	}
	if ver != "" {
		if svcText == "-" {
			svcText = ver
		} else {
			svcText += " " + ver
		}
	}

	return fmt.Sprintf("%s %s:%d/%s | %s",
		action,
		trimForNotify(target, 85),
		ch.Port,
		proto,
		trimForNotify(svcText, 70),
	)
}

func buildMonitorLiveEventKey(host, ip string, port int) string {
	host = normalizeMonitorHost(host)
	if host == "" {
		host = normalizeMonitorHost(ip)
	}
	if host == "" {
		return ""
	}
	if port < 0 {
		port = 0
	}
	return fmt.Sprintf("new_live|host=%s|port=%d", host, port)
}

func buildMonitorLiveEventKeyWithIP(host, ip string, port int) string {
	host = normalizeMonitorHost(host)
	ip = strings.TrimSpace(ip)
	if host == "" && ip == "" {
		return ""
	}
	if host == "" {
		host = "-"
	}
	if ip == "" {
		ip = "-"
	}
	if port < 0 {
		port = 0
	}
	return fmt.Sprintf("new_live|host=%s|ip=%s|port=%d", host, ip, port)
}

func buildMonitorLegacyLiveEventKey(domain string) string {
	host := normalizeMonitorHost(domain)
	if host == "" {
		return ""
	}
	return "new_live|domain=" + host
}

func buildMonitorLiveIdentity(domain, rawURL, ip string) (host, normalizedIP string, port int) {
	host = normalizeMonitorHost(domain)
	normalizedIP = strings.TrimSpace(ip)
	port = 0

	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err == nil && parsed != nil {
		if parsed.Hostname() != "" && host == "" {
			host = normalizeMonitorHost(parsed.Hostname())
		}
		if p := strings.TrimSpace(parsed.Port()); p != "" {
			if v, convErr := strconv.Atoi(p); convErr == nil && v > 0 {
				port = v
			}
		} else {
			switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
			case "https":
				port = 443
			case "http":
				port = 80
			}
		}
	}

	return host, normalizedIP, port
}

func normalizeMonitorHost(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	if idx := strings.Index(value, "/"); idx != -1 {
		value = value[:idx]
	}
	if idx := strings.Index(value, ":"); idx != -1 {
		value = value[:idx]
	}
	return strings.TrimSuffix(strings.TrimSpace(value), ".")
}

func buildMonitorPortEventKey(domain, ip string, port int, protocol string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || port <= 0 {
		return ""
	}
	host := normalizeMonitorHost(domain)
	if host == "" {
		host = normalizeMonitorHost(ip)
	}
	if host == "" {
		host = "-"
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "tcp"
	}
	return fmt.Sprintf("port_opened|host=%s|ip=%s|port=%d|proto=%s", host, ip, port, protocol)
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Dashboard
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

	qAsset24 := s.db.DB.Model(&db.AssetCandidate{}).Where("project_id = ? AND created_at >= ?", projectID, since24h)
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
		qSub := s.db.DB.Model(&db.AssetCandidate{}).Where("project_id = ? AND created_at >= ? AND created_at < ?", projectID, dayStart, dayEnd)
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

	type dashboardAggRow struct {
		Name  string `gorm:"column:name"`
		Value int64  `gorm:"column:value"`
	}
	serviceRows := make([]dashboardAggRow, 0, 10)
	if err := s.db.DB.Raw(`
		SELECT
			COALESCE(NULLIF(BTRIM(service), ''), 'unknown') AS name,
			COUNT(1) AS value
		FROM ports
		WHERE project_id = ? AND deleted_at IS NULL
		GROUP BY 1
		ORDER BY COUNT(1) DESC, name ASC
		LIMIT 10
	`, projectID).Scan(&serviceRows).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	serviceDistribution := make([]dashboardCountItemResponse, 0, len(serviceRows))
	for _, row := range serviceRows {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			name = "unknown"
		}
		serviceDistribution = append(serviceDistribution, dashboardCountItemResponse{
			Name:  name,
			Value: int(row.Value),
		})
	}

	severityRows := make([]dashboardAggRow, 0, 8)
	if err := s.db.DB.Raw(`
		SELECT
			COALESCE(NULLIF(BTRIM(LOWER(severity)), ''), 'unknown') AS name,
			COUNT(1) AS value
		FROM vulnerabilities
		WHERE project_id = ? AND deleted_at IS NULL
		GROUP BY 1
		ORDER BY COUNT(1) DESC, name ASC
	`, projectID).Scan(&severityRows).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	severityDistribution := make([]dashboardCountItemResponse, 0, len(severityRows))
	for _, row := range severityRows {
		name := strings.TrimSpace(strings.ToLower(row.Name))
		if name == "" {
			name = "unknown"
		}
		severityDistribution = append(severityDistribution, dashboardCountItemResponse{
			Name:  name,
			Value: int(row.Value),
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
			ServiceDistribution:   serviceDistribution,
			SeverityDistribution:  severityDistribution,
		},
		Trend: trend,
	}
	writeJSON(w, http.StatusOK, resp)
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Assets / Ports / Vulns
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
	monitorNew := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("monitor_new")))
	pool := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pool")))
	if pool == "" {
		pool = "verified"
	}
	if pool != "verified" && pool != "candidate" {
		writeError(w, http.StatusBadRequest, "invalid pool (use verified|candidate)")
		return
	}

	if pool == "candidate" {
		base := s.db.DB.Model(&db.AssetCandidate{}).Where("project_id = ?", projectID)
		if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
			pattern := "%." + rd
			base = base.Where(
				"root_domain = ? OR domain = ? OR domain LIKE ?",
				rd, rd, pattern,
			)
		}
		if search != "" {
			pattern := "%" + search + "%"
			base = base.Where(
				"LOWER(domain) LIKE ? OR LOWER(last_url) LIKE ? OR LOWER(last_ip) LIKE ? OR LOWER(last_title) LIKE ?",
				pattern, pattern, pattern, pattern,
			)
		}
		if liveOnly {
			base = base.Where("verify_status = ? AND last_status_code > 0 AND BTRIM(COALESCE(last_url, '')) <> ''", "verified")
		}
		switch monitorNew {
		case "", "all":
			// no-op
		case "open":
			sub := s.db.DB.Model(&db.MonitorEvent{}).
				Select("1").
				Where("project_id = ? AND event_type = ? AND status = ? AND (domain = asset_candidates.domain OR (asset_candidates.last_ip <> '' AND ip = asset_candidates.last_ip))",
					projectID, "new_live", monitorEventStatusOpen)
			base = base.Where("EXISTS (?)", sub)
		case "recent24h":
			since := time.Now().Add(-24 * time.Hour)
			sub := s.db.DB.Model(&db.AssetChange{}).
				Select("1").
				Where("project_id = ? AND change_type IN ? AND created_at >= ? AND (domain = asset_candidates.domain OR (asset_candidates.last_ip <> '' AND ip = asset_candidates.last_ip))",
					projectID, []string{"new_live", "new_live_subdomain"}, since)
			base = base.Where("EXISTS (?)", sub)
		default:
			writeError(w, http.StatusBadRequest, "invalid monitor_new (use open|recent24h)")
			return
		}

		var items []db.AssetCandidate
		query := base.Order(resolveAssetCandidateOrder(r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir")))
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
			if err := query.Find(&items).Error; err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			resp := make([]assetResponse, 0, len(items))
			for _, c := range items {
				resp = append(resp, assetResponse{
					ID:           int(c.ID),
					Domain:       c.Domain,
					URL:          c.LastURL,
					IP:           c.LastIP,
					Pool:         "candidate",
					VerifyStatus: strings.ToLower(strings.TrimSpace(c.VerifyStatus)),
					StatusCode:   c.LastStatusCode,
					Title:        c.LastTitle,
					CreatedAt:    timeToISO(c.CreatedAt),
					UpdatedAt:    timeToISO(c.UpdatedAt),
					LastSeen:     timeToISO(c.LastSeen),
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
		if err := query.Find(&items).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp := make([]assetResponse, 0, len(items))
		for _, c := range items {
			resp = append(resp, assetResponse{
				ID:           int(c.ID),
				Domain:       c.Domain,
				URL:          c.LastURL,
				IP:           c.LastIP,
				Pool:         "candidate",
				VerifyStatus: strings.ToLower(strings.TrimSpace(c.VerifyStatus)),
				StatusCode:   c.LastStatusCode,
				Title:        c.LastTitle,
				CreatedAt:    timeToISO(c.CreatedAt),
				UpdatedAt:    timeToISO(c.UpdatedAt),
				LastSeen:     timeToISO(c.LastSeen),
			})
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	base := s.db.DB.Model(&db.Asset{}).Where("project_id = ?", projectID)
	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		base = base.Where(
			"root_domain = ? OR domain = ? OR domain LIKE ?",
			rd, rd, pattern,
		)
	}
	if search != "" {
		pattern := "%" + search + "%"
		base = base.Where(
			"LOWER(domain) LIKE ? OR LOWER(url) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(title) LIKE ?",
			pattern, pattern, pattern, pattern,
		)
	}
	if liveOnly {
		base = base.Where("status_code > 0 AND BTRIM(COALESCE(url, '')) <> ''")
	}
	switch monitorNew {
	case "", "all":
		// no-op
	case "open":
		sub := s.db.DB.Model(&db.MonitorEvent{}).
			Select("1").
			Where("project_id = ? AND event_type = ? AND status = ? AND (domain = assets.domain OR (assets.ip <> '' AND ip = assets.ip))",
				projectID, "new_live", monitorEventStatusOpen)
		base = base.Where("EXISTS (?)", sub)
	case "recent24h":
		since := time.Now().Add(-24 * time.Hour)
		sub := s.db.DB.Model(&db.AssetChange{}).
			Select("1").
			Where("project_id = ? AND change_type IN ? AND created_at >= ? AND (domain = assets.domain OR (assets.ip <> '' AND ip = assets.ip))",
				projectID, []string{"new_live", "new_live_subdomain"}, since)
		base = base.Where("EXISTS (?)", sub)
	default:
		writeError(w, http.StatusBadRequest, "invalid monitor_new (use open|recent24h)")
		return
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
				Pool:         "verified",
				VerifyStatus: "verified",
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
			Pool:         "verified",
			VerifyStatus: "verified",
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
	// Suppress stale split rows: when the same ip:port/proto exists with both
	// empty-domain and non-empty-domain records, keep the domain-bound one.
	base = base.Where(`NOT (
		COALESCE(domain, '') = '' AND EXISTS (
			SELECT 1 FROM ports p2
			WHERE p2.project_id = ports.project_id
			  AND p2.ip = ports.ip
			  AND p2.port = ports.port
			  AND p2.protocol = ports.protocol
			  AND COALESCE(p2.domain, '') <> ''
			  AND p2.deleted_at IS NULL
		)
	)`)

	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		pattern := "%." + rd
		base = base.Where(
			"root_domain = ? OR domain = ? OR domain LIKE ?",
			rd, rd, pattern,
		)
	}
	if search != "" {
		pattern := "%" + search + "%"
		base = base.Where(
			"LOWER(domain) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(service) LIKE ? OR LOWER(version) LIKE ? OR LOWER(banner) LIKE ?",
			pattern, pattern, pattern, pattern, pattern,
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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Jobs 鈥?persistent scan_jobs table
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

	type jobListRow struct {
		ID           string     `gorm:"column:id"`
		ProjectID    string     `gorm:"column:project_id"`
		RootDomain   string     `gorm:"column:root_domain"`
		Mode         string     `gorm:"column:mode"`
		Modules      string     `gorm:"column:modules"`
		Status       string     `gorm:"column:status"`
		StartedAt    time.Time  `gorm:"column:started_at"`
		FinishedAt   *time.Time `gorm:"column:finished_at"`
		DurationSec  int        `gorm:"column:duration_sec"`
		ErrorMessage string     `gorm:"column:error_message"`
		SubdomainCnt int        `gorm:"column:subdomain_cnt"`
		PortCnt      int        `gorm:"column:port_cnt"`
		VulnCnt      int        `gorm:"column:vuln_cnt"`
	}

	baseCombinedSQL := `
SELECT
	sj.job_id AS id,
	sj.project_id AS project_id,
	sj.root_domain AS root_domain,
	sj.mode AS mode,
	COALESCE(sj.modules, '') AS modules,
	COALESCE(sj.status, '') AS status,
	COALESCE(sj.started_at, sj.created_at) AS started_at,
	sj.finished_at AS finished_at,
	COALESCE(sj.duration_sec, 0) AS duration_sec,
	COALESCE(sj.error_message, '') AS error_message,
	COALESCE(sj.subdomain_cnt, 0) AS subdomain_cnt,
	COALESCE(sj.port_cnt, 0) AS port_cnt,
	COALESCE(sj.vuln_cnt, 0) AS vuln_cnt
FROM scan_jobs sj
WHERE sj.project_id = ? AND sj.deleted_at IS NULL
UNION ALL
SELECT
	('task-' || mt.id::text) AS id,
	mt.project_id AS project_id,
	mt.root_domain AS root_domain,
	'monitor' AS mode,
	'subs,ports,monitor' AS modules,
	COALESCE(mt.status, '') AS status,
	COALESCE(mt.started_at, mt.created_at) AS started_at,
	mt.finished_at AS finished_at,
	CASE
		WHEN mt.started_at IS NOT NULL AND mt.finished_at IS NOT NULL AND mt.finished_at >= mt.started_at
			THEN EXTRACT(EPOCH FROM (mt.finished_at - mt.started_at))::int
		ELSE 0
	END AS duration_sec,
	COALESCE(mt.last_error, '') AS error_message,
	0 AS subdomain_cnt,
	0 AS port_cnt,
	0 AS vuln_cnt
FROM monitor_tasks mt
WHERE mt.project_id = ? AND mt.deleted_at IS NULL
`
	whereParts := make([]string, 0, 4)
	args := []interface{}{projectFilter, projectFilter}

	if rootDomainFilter != "" {
		whereParts = append(whereParts, "root_domain = ?")
		args = append(args, rootDomainFilter)
	}

	if statusFilter != "" && statusFilter != "all" {
		switch statusFilter {
		case "running":
			whereParts = append(whereParts, "LOWER(status) IN ('running', 'pending')")
		case "success":
			whereParts = append(whereParts, "LOWER(status) IN ('success', 'ok', 'done', 'completed')")
		case "failed":
			whereParts = append(whereParts, "LOWER(status) IN ('failed', 'error', 'fail')")
		case "pending":
			whereParts = append(whereParts, "LOWER(status) = 'pending'")
		case "canceled":
			whereParts = append(whereParts, "LOWER(status) = 'canceled'")
		default:
			whereParts = append(whereParts, "LOWER(status) = ?")
			args = append(args, statusFilter)
		}
	}

	if search != "" {
		pattern := "%" + search + "%"
		whereParts = append(whereParts, "(LOWER(id) LIKE ? OR LOWER(root_domain) LIKE ? OR LOWER(status) LIKE ? OR LOWER(error_message) LIKE ? OR LOWER(modules) LIKE ?)")
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}

	whereSQL := ""
	if len(whereParts) > 0 {
		whereSQL = " WHERE " + strings.Join(whereParts, " AND ")
	}

	var total int64
	if paged {
		countSQL := "SELECT COUNT(1) FROM (" + baseCombinedSQL + ") AS combined" + whereSQL
		if err := s.db.DB.Raw(countSQL, args...).Scan(&total).Error; err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	dataSQL := "SELECT id, project_id, root_domain, mode, modules, status, started_at, finished_at, duration_sec, error_message, subdomain_cnt, port_cnt, vuln_cnt FROM (" + baseCombinedSQL + ") AS combined" + whereSQL + " ORDER BY " + resolveJobOrder(r.URL.Query().Get("sort_by"), r.URL.Query().Get("sort_dir"))
	dataArgs := append([]interface{}{}, args...)
	if paged {
		offset := (page - 1) * pageSize
		dataSQL += " OFFSET ? LIMIT ?"
		dataArgs = append(dataArgs, offset, pageSize)
	} else {
		dataSQL += " LIMIT ?"
		dataArgs = append(dataArgs, 500)
	}

	var rows []jobListRow
	if err := s.db.DB.Raw(dataSQL, dataArgs...).Scan(&rows).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jobs := make([]jobOverviewResponse, 0, len(rows))
	for _, row := range rows {
		modules := make([]string, 0, 8)
		if strings.TrimSpace(row.Modules) != "" {
			for _, item := range strings.Split(row.Modules, ",") {
				v := strings.TrimSpace(item)
				if v != "" {
					modules = append(modules, v)
				}
			}
		}
		jobs = append(jobs, jobOverviewResponse{
			ID:           row.ID,
			ProjectID:    row.ProjectID,
			RootDomain:   row.RootDomain,
			Mode:         row.Mode,
			Modules:      modules,
			Status:       normalizeHealthStatus(row.Status),
			StartedAt:    timeToISO(row.StartedAt),
			FinishedAt:   timePtrToISO(row.FinishedAt),
			DurationSec:  row.DurationSec,
			ErrorMessage: row.ErrorMessage,
			SubdomainCnt: row.SubdomainCnt,
			PortCnt:      row.PortCnt,
			VulnCnt:      row.VulnCnt,
		})
	}

	if paged {
		writeJSON(w, http.StatusOK, pagedJobsResponse{
			Items:    jobs,
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		})
		return
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
	if mode == "monitor" {
		writeError(w, http.StatusBadRequest, "monitor tasks must be created from /api/monitor/targets")
		return
	}
	if mode != "scan" {
		writeError(w, http.StatusBadRequest, "mode must be scan")
		return
	}
	notify := true
	if req.Notify != nil {
		notify = *req.Notify
	}
	s.settingsMu.RLock()
	defaultNuclei := s.settings.Scanner.DefaultNuclei
	defaultActiveSubs := s.settings.Scanner.DefaultActiveSubs
	s.settingsMu.RUnlock()

	enableNuclei := defaultNuclei
	if req.EnableNuclei != nil {
		enableNuclei = *req.EnableNuclei
	}
	autoCorsWithNuclei := shouldEnableCorsWithNuclei()
	activeSubs := defaultActiveSubs
	if req.ActiveSubs != nil {
		activeSubs = *req.ActiveSubs
	}

	modules := sanitizeModules(req.Modules)
	if len(modules) == 0 {
		if mode == "monitor" {
			modules = []string{"subs", "ports", "monitor"}
		} else {
			modules = []string{"subs", "ports", "httpx"}
			if enableNuclei {
				modules = append(modules, "nuclei")
				if autoCorsWithNuclei {
					modules = append(modules, "cors")
				}
			}
			if activeSubs {
				modules = append(modules, "dnsx_bruteforce")
			}
		}
	} else if mode == "scan" {
		if enableNuclei && !containsAnyModule(modules, "nuclei") {
			modules = append(modules, "nuclei")
		}
		if activeSubs && !containsAnyModule(modules, "dnsx_bruteforce", "dictgen") {
			modules = append(modules, "dnsx_bruteforce")
		}
	}

	now := time.Now().UTC()
	jobID := fmt.Sprintf("scan-%d", now.UnixNano())

	// Persist scan job to DB
	scanJob := db.ScanJob{
		JobID:        jobID,
		ProjectID:    projectID,
		RootDomain:   rootDomain,
		Mode:         mode,
		Modules:      strings.Join(modules, ","),
		Status:       "pending",
		EnableNuclei: enableNuclei,
		ActiveSubs:   activeSubs,
		DictSize:     req.DictSize,
		DNSResolvers: strings.TrimSpace(req.DNSResolvers),
		DryRun:       req.DryRun,
		Notify:       notify,
	}
	if err := s.db.CreateScanJob(&scanJob); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create scan job: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, jobOverviewResponse{
		ID: jobID, ProjectID: projectID, RootDomain: rootDomain, Mode: mode, Modules: modules,
		Status: "pending", StartedAt: now.Format(time.RFC3339),
	})
	s.appendJobLogf(projectID, jobID, "info", "浠诲姟宸插垱寤哄苟杩涘叆闃熷垪: root=%s modules=%v dryRun=%v notify=%v", rootDomain, modules, req.DryRun, notify)
	s.writeAudit(projectID, actorFromRequest(r), "create_scan", "job", jobID, map[string]interface{}{
		"domain": rootDomain, "modules": modules, "dryRun": req.DryRun, "notify": notify,
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
		s.appendJobLog(job.ProjectID, body.JobID, "warn", "浠诲姟宸茶鐢ㄦ埛鍙栨秷")
		s.writeAudit(job.ProjectID, actorFromRequest(r), "cancel_scan", "job", body.JobID, map[string]interface{}{
			"rootDomain": job.RootDomain,
		}, r)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "canceled", "jobId": body.JobID})
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "job_id is required")
		return
	}

	if strings.HasPrefix(jobID, "task-") {
		taskIDRaw := strings.TrimPrefix(jobID, "task-")
		taskID, err := strconv.ParseUint(taskIDRaw, 10, 64)
		if err != nil || taskID == 0 {
			writeError(w, http.StatusBadRequest, "invalid monitor task id")
			return
		}
		if err := s.db.DeleteMonitorTaskHistory(projectID, uint(taskID)); err != nil {
			switch {
			case errors.Is(err, gorm.ErrRecordNotFound):
				writeError(w, http.StatusNotFound, "job not found")
				return
			case errors.Is(err, db.ErrMonitorTaskActive):
				writeError(w, http.StatusConflict, "job is running or pending; cancel it first")
				return
			default:
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		s.writeAudit(projectID, actorFromRequest(r), "delete_monitor_task", "monitor_task", jobID, map[string]interface{}{}, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "jobId": jobID})
		return
	}

	if err := s.db.DeleteScanJobHistory(projectID, jobID); err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			writeError(w, http.StatusNotFound, "job not found")
			return
		case errors.Is(err, db.ErrJobActive):
			writeError(w, http.StatusConflict, "job is running or pending; cancel it first")
			return
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	s.writeAudit(projectID, actorFromRequest(r), "delete_scan_job", "job", jobID, map[string]interface{}{}, r)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "jobId": jobID})
}

func (s *Server) handleJobLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	jobID := strings.TrimSpace(r.URL.Query().Get("job_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "job_id is required")
		return
	}

	sinceID := uint(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("since_id")); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since_id")
			return
		}
		sinceID = uint(n)
	}
	beforeID := uint(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("before_id")); raw != "" {
		n, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid before_id")
			return
		}
		beforeID = uint(n)
	}

	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		limit = n
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	rows, hasMoreBefore, err := s.db.ListJobLogs(projectID, jobID, sinceID, beforeID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]jobLogItemResponse, 0, len(rows))
	nextSinceID := sinceID
	for _, row := range rows {
		if row.ID > nextSinceID {
			nextSinceID = row.ID
		}
		resp = append(resp, jobLogItemResponse{
			ID:        row.ID,
			Level:     row.Level,
			Message:   row.Message,
			CreatedAt: timeToISO(row.CreatedAt),
		})
	}

	status := s.resolveJobStatus(projectID, jobID)
	writeJSON(w, http.StatusOK, jobLogsResponse{
		Items:         resp,
		SinceID:       nextSinceID,
		JobStatus:     status,
		HasMoreBefore: hasMoreBefore,
	})
}

func (s *Server) resolveJobStatus(projectID, jobID string) string {
	projectID = strings.TrimSpace(projectID)
	jobID = strings.TrimSpace(jobID)
	if projectID == "" || jobID == "" {
		return "unknown"
	}

	if strings.HasPrefix(jobID, "task-") {
		taskIDRaw := strings.TrimPrefix(jobID, "task-")
		taskID, err := strconv.ParseUint(taskIDRaw, 10, 64)
		if err != nil || taskID == 0 {
			return "unknown"
		}
		var task db.MonitorTask
		if err := s.db.DB.Where("project_id = ? AND id = ?", projectID, uint(taskID)).First(&task).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return "deleted"
			}
			return "unknown"
		}
		return strings.TrimSpace(task.Status)
	}

	var scanJob db.ScanJob
	if err := s.db.DB.Where("project_id = ? AND job_id = ?", projectID, jobID).First(&scanJob).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "deleted"
		}
		return "unknown"
	}
	return strings.TrimSpace(scanJob.Status)
}

// runScanAsync executes the scan pipeline in a background goroutine.
func (s *Server) runScanAsync(projectID, jobID, rootDomain string, modules []string, enableNuclei, activeSubs bool, dictSize int, dnsResolvers string, dryRun, notify bool) {
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

	log.Printf("[Scan] Job %s started for %s, modules=%v dryRun=%v", jobID, rootDomain, modules, dryRun)
	s.appendJobLogf(projectID, jobID, "info", "鎵弿寮€濮? root=%s modules=%v dryRun=%v", rootDomain, modules, dryRun)

	// Frontend may send stage modules (subs/ports/httpx/...) or concrete tool
	// modules (subfinder/findomain/bbot/naabu/nmap/...); normalize behavior here.
	hasPassiveSubs := containsAnyModule(modules, "subs", "subfinder", "findomain", "bbot", "shosubgo")
	hasBbotActive := containsAnyModule(modules, "bbot_active")
	hasActiveSubs := activeSubs || containsAnyModule(modules, "dnsx_bruteforce", "dictgen")
	hasSubs := hasPassiveSubs || hasBbotActive || hasActiveSubs
	hasPorts := containsAnyModule(modules, "ports", "naabu", "nmap")
	hasWitness := containsAnyModule(modules, "witness", "gowitness")
	hasNuclei := enableNuclei || containsAnyModule(modules, "nuclei")
	hasCors := containsAnyModule(modules, "cors")
	hasSubTakeover := containsAnyModule(modules, "subtakeover")
	// Nuclei/Cors/Witness depend on live HTTP targets from httpx.
	// SubTakeover scans hostnames directly and does not require httpx.
	hasHttpx := containsAnyModule(modules, "httpx") || hasNuclei || hasCors || hasWitness

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
	s.appendJobLogf(projectID, jobID, "debug", "鎵ц鍙傛暟: hasSubs=%v hasBbotActive=%v hasActiveSubs=%v hasHttpx=%v hasPorts=%v hasNuclei=%v hasCors=%v hasSubTakeover=%v hasWitness=%v dictSize=%d",
		hasSubs, hasBbotActive, hasActiveSubs, hasHttpx, hasPorts, hasNuclei, hasCors, hasSubTakeover, hasWitness, dictSize)

	var allResults []engine.Result
	var scanErr error

	domains := []string{rootDomain}

	if err := s.checkScanCanceled(ctx, jobID); err != nil {
		s.finishScan(projectID, rootDomain, jobID, startTime, nil, err, dryRun, notify)
		return
	}

	if hasSubs {
		s.appendJobLog(projectID, jobID, "info", "闃舵寮€濮? 瀛愬煙鏀堕泦")
		includePassiveBBOT := !hasBbotActive
		subResults, subdomains, err := s.collectSubdomains(ctx, domains, includePassiveBBOT)
		allResults = append(allResults, subResults...)
		if err != nil {
			scanErr = fmt.Errorf("subdomain collection failed: %v", err)
			s.appendJobLogf(projectID, jobID, "error", "瀛愬煙鏀堕泦澶辫触: %v", err)
			s.finishScan(projectID, rootDomain, jobID, startTime, allResults, scanErr, dryRun, notify)
			return
		}
		s.appendJobLogf(projectID, jobID, "info", "瀛愬煙鏀堕泦瀹屾垚: unique=%d resultItems=%d", len(subdomains), len(subResults))
		if err := s.checkScanCanceled(ctx, jobID); err != nil {
			s.appendJobLog(projectID, jobID, "warn", "任务已取消")
			s.finishScan(projectID, rootDomain, jobID, startTime, allResults, err, dryRun, notify)
			return
		}

		if hasBbotActive {
			s.appendJobLog(projectID, jobID, "info", "闃舵寮€濮? BBOT 涓诲姩鎵╁睍")
			bbotResults, bbotSubdomains, err := s.expandBbotActiveSubdomains(ctx, domains)
			allResults = append(allResults, bbotResults...)
			if err != nil {
				log.Printf("[Scan] Job %s bbot active warning: %v", jobID, err)
				s.appendJobLogf(projectID, jobID, "warn", "BBOT 涓诲姩鎵╁睍鍛婅: %v", err)
			} else {
				before := len(subdomains)
				subdomains = mergeUnique(subdomains, bbotSubdomains)
				s.appendJobLogf(projectID, jobID, "info", "BBOT 涓诲姩鎵╁睍瀹屾垚: 鏂板=%d, 鍚堝苟鍚?%d", len(subdomains)-before, len(subdomains))
			}
			if err := s.checkScanCanceled(ctx, jobID); err != nil {
				s.appendJobLog(projectID, jobID, "warn", "任务已取消")
				s.finishScan(projectID, rootDomain, jobID, startTime, allResults, err, dryRun, notify)
				return
			}
		}

		if hasActiveSubs {
			s.appendJobLogf(projectID, jobID, "info", "闃舵寮€濮? 涓诲姩鏋氫妇 (dictSize=%d)", dictSize)
			activeResults, activeSubdomains, err := s.expandActiveSubdomains(ctx, domains, subdomains, dictSize, dnsResolvers)
			allResults = append(allResults, activeResults...)
			if err != nil {
				log.Printf("[Scan] Job %s active subs warning: %v", jobID, err)
				s.appendJobLogf(projectID, jobID, "warn", "涓诲姩鏋氫妇鍛婅: %v", err)
			} else {
				subdomains = mergeUnique(subdomains, activeSubdomains)
				s.appendJobLogf(projectID, jobID, "info", "涓诲姩鏋氫妇瀹屾垚: 鏂板=%d, 鍚堝苟鍚?%d", len(activeSubdomains), len(subdomains))
			}
			if err := s.checkScanCanceled(ctx, jobID); err != nil {
				s.appendJobLog(projectID, jobID, "warn", "任务已取消")
				s.finishScan(projectID, rootDomain, jobID, startTime, allResults, err, dryRun, notify)
				return
			}
		}

		if hasPorts || hasHttpx || hasSubTakeover {
			s.appendJobLogf(projectID, jobID, "info", "闃舵寮€濮? 缃戠粶鎺㈡祴 (targets=%d httpx=%v ports=%v nuclei=%v cors=%v subtakeover=%v witness=%v)",
				len(subdomains), hasHttpx, hasPorts, hasNuclei, hasCors, hasSubTakeover, hasWitness)
			networkResults, err := s.runNetworkPipeline(ctx, subdomains, hasHttpx, hasPorts, hasNuclei, hasCors, hasSubTakeover, hasWitness, screenshotDir)
			allResults = append(allResults, networkResults...)
			if err != nil {
				scanErr = fmt.Errorf("network stage failed: %v", err)
				s.appendJobLogf(projectID, jobID, "error", "缃戠粶鎺㈡祴澶辫触: %v", err)
			}
			networkCounts := countResults(networkResults)
			s.appendJobLogf(projectID, jobID, "info", "缃戠粶鎺㈡祴瀹屾垚: web=%d ports=%d vulns=%d",
				networkCounts["web_services"], networkCounts["ports"], networkCounts["vulnerabilities"])
			if err := s.checkScanCanceled(ctx, jobID); err != nil {
				s.appendJobLog(projectID, jobID, "warn", "任务已取消")
				s.finishScan(projectID, rootDomain, jobID, startTime, allResults, err, dryRun, notify)
				return
			}
		}
	} else if hasPorts || hasHttpx || hasSubTakeover {
		s.appendJobLogf(projectID, jobID, "info", "闃舵寮€濮? 缃戠粶鎺㈡祴 (targets=%d httpx=%v ports=%v nuclei=%v cors=%v subtakeover=%v witness=%v)",
			len(domains), hasHttpx, hasPorts, hasNuclei, hasCors, hasSubTakeover, hasWitness)
		networkResults, err := s.runNetworkPipeline(ctx, domains, hasHttpx, hasPorts, hasNuclei, hasCors, hasSubTakeover, hasWitness, screenshotDir)
		allResults = append(allResults, networkResults...)
		if err != nil {
			scanErr = fmt.Errorf("network stage failed: %v", err)
			s.appendJobLogf(projectID, jobID, "error", "缃戠粶鎺㈡祴澶辫触: %v", err)
		}
		networkCounts := countResults(networkResults)
		s.appendJobLogf(projectID, jobID, "info", "缃戠粶鎺㈡祴瀹屾垚: web=%d ports=%d vulns=%d",
			networkCounts["web_services"], networkCounts["ports"], networkCounts["vulnerabilities"])
		if err := s.checkScanCanceled(ctx, jobID); err != nil {
			s.appendJobLog(projectID, jobID, "warn", "任务已取消")
			s.finishScan(projectID, rootDomain, jobID, startTime, allResults, err, dryRun, notify)
			return
		}
	}

	s.appendPluginStatusLogs(projectID, jobID, allResults)
	s.finishScan(projectID, rootDomain, jobID, startTime, allResults, scanErr, dryRun, notify)
}

func (s *Server) checkScanCanceled(ctx context.Context, jobID string) error {
	select {
	case <-ctx.Done():
		return errScanCanceled
	default:
	}
	job, err := s.db.GetScanJob(jobID)
	if err != nil {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(job.Status), "canceled") {
		return errScanCanceled
	}
	return nil
}

func (s *Server) finishScan(projectID, rootDomain, jobID string, startTime time.Time, results []engine.Result, scanErr error, dryRun, notify bool) {
	duration := int(time.Since(startTime).Seconds())
	var dbErr error
	if !dryRun {
		dbErr = s.saveResultsToDB(projectID, rootDomain, jobID, results)
		if dbErr != nil {
			s.appendJobLogf(projectID, jobID, "error", "缁撴灉鍐欏叆鏁版嵁搴撳け璐? %v", dbErr)
		}
	}

	finalStatus := "success"
	errMsg := ""
	if errors.Is(scanErr, errScanCanceled) {
		finalStatus = "canceled"
		errMsg = errScanCanceled.Error()
	} else if scanErr != nil {
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

	log.Printf("[Scan] Job %s finished: status=%s duration=%ds subs=%d ports=%d vulns=%d screenshots=%d dryRun=%v",
		jobID, finalStatus, duration, counts["subdomains"], counts["ports"], counts["vulnerabilities"], counts["screenshots"], dryRun)
	s.appendJobLogf(projectID, jobID, "info", "鎵弿缁撴潫: status=%s duration=%ds subs=%d ports=%d vulns=%d screenshots=%d dryRun=%v",
		finalStatus, duration, counts["subdomains"], counts["ports"], counts["vulnerabilities"], counts["screenshots"], dryRun)
	s.writeAudit(projectID, "system", "finish_scan", "job", jobID, map[string]interface{}{
		"status": finalStatus, "durationSec": duration, "subdomains": counts["subdomains"], "ports": counts["ports"], "vulns": counts["vulnerabilities"], "screenshots": counts["screenshots"], "dryRun": dryRun,
	}, nil)

	if !notify || dryRun {
		return
	}
	s.settingsMu.RLock()
	notifyEnabled := s.settings.Notifications.Enabled
	s.settingsMu.RUnlock()
	if !notifyEnabled {
		return
	}
	notifier := plugins.NewDingTalkNotifierFromEnv(true)
	if !notifier.Enabled() {
		return
	}
	if err := notifier.SendReconEnd(finalStatus == "success", time.Duration(duration)*time.Second, counts, errMsg); err != nil {
		log.Printf("[Notify] scan finish notification failed for job %s: %v", jobID, err)
		s.appendJobLogf(projectID, jobID, "warn", "閫氱煡鍙戦€佸け璐? %v", err)
	}
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Scan pipeline helpers
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (s *Server) appendPluginStatusLogs(projectID, jobID string, results []engine.Result) {
	for _, result := range results {
		if result.Type != "plugin_status" {
			continue
		}
		data, ok := result.Data.(map[string]interface{})
		if !ok {
			continue
		}
		scanner := mapString(data, "scanner")
		if scanner == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(mapString(data, "status")))
		successCount := mapInt(data, "success_count")
		failureCount := mapInt(data, "failure_count")
		timeoutCount := mapInt(data, "timeout_count")
		durationMS := mapInt(data, "duration_ms")
		errMsg := strings.TrimSpace(mapString(data, "error"))

		level := "info"
		if status == "error" || failureCount > 0 {
			level = "warn"
		}
		if errMsg == "" {
			s.appendJobLogf(projectID, jobID, level, "鎵弿鍣ㄧ姸鎬? %s status=%s success=%d failure=%d timeout=%d duration=%dms",
				scanner, status, successCount, failureCount, timeoutCount, durationMS)
		} else {
			s.appendJobLogf(projectID, jobID, level, "鎵弿鍣ㄧ姸鎬? %s status=%s success=%d failure=%d timeout=%d duration=%dms error=%s",
				scanner, status, successCount, failureCount, timeoutCount, durationMS, trimForNotify(errMsg, 260))
		}

		if strings.EqualFold(scanner, "nmap") && status == "ok" && successCount == 0 {
			s.appendJobLog(projectID, jobID, "warn", "Nmap 已执行但未识别到服务指纹，端口页可能只显示开放端口而没有 service/version")
		}
	}
}

func (s *Server) collectSubdomains(ctx context.Context, rootDomains []string, includePassiveBBOT bool) ([]engine.Result, []string, error) {
	pipeline := engine.NewPipeline()
	isBatch := len(rootDomains) > 1
	pipeline.AddDomainScanner(plugins.NewSubfinderPlugin(isBatch))
	pipeline.AddDomainScanner(plugins.NewChaosPlugin(isBatch))
	pipeline.AddDomainScanner(plugins.NewFindomainPlugin())
	if includePassiveBBOT {
		pipeline.AddDomainScanner(plugins.NewBBOTPlugin(true))
	}
	pipeline.AddDomainScanner(plugins.NewShosubgoPlugin())
	results, err := pipeline.Execute(ctx, rootDomains)
	subdomains := extractDomains(results)
	log.Printf("[Scan] Passive collection: %d unique subdomains", len(subdomains))
	return results, subdomains, err
}

func (s *Server) expandBbotActiveSubdomains(ctx context.Context, rootDomains []string) ([]engine.Result, []string, error) {
	scanner := plugins.NewBBOTPlugin(false)
	results, err := scanner.Execute(ctx, rootDomains)
	subdomains := extractDomains(results)
	log.Printf("[Scan] BBOT active expansion: %d unique subdomains", len(subdomains))
	return results, subdomains, err
}

func (s *Server) expandActiveSubdomains(ctx context.Context, rootDomains, passiveSubdomains []string, dictSize int, dnsResolvers string) ([]engine.Result, []string, error) {
	var allResults []engine.Result
	dictPlugin := plugins.NewDictgenPlugin(dictSize)
	dictInput := append(append([]string{}, passiveSubdomains...), rootDomains...)
	dictResults, err := dictPlugin.Execute(ctx, dictInput)
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
	bruteResults, err := brutePlugin.Execute(ctx, words)
	allResults = append(allResults, bruteResults...)
	if err != nil {
		return allResults, nil, err
	}
	return allResults, extractDomains(bruteResults), nil
}

func (s *Server) runNetworkPipeline(ctx context.Context, targets []string, enableHTTPX, enablePorts, enableNuclei, enableCors, enableSubTakeover, enableWitness bool, screenshotDir string) ([]engine.Result, error) {
	pipeline := engine.NewPipeline()
	if enableHTTPX {
		pipeline.SetHttpxScanner(plugins.NewHttpxPlugin())
	}
	if enablePorts {
		switch configuredPortScannerEngine() {
		case "naabu_nmap":
			pipeline.AddPortScanner(plugins.NewNaabuPlugin())
			pipeline.AddPortScanner(plugins.NewNmapPlugin())
		default:
			pipeline.AddPortScanner(plugins.NewTscanPortPlugin())
		}
	}
	if enableNuclei {
		pipeline.AddVulnScanner(plugins.NewNucleiPlugin())
	}
	if enableCors {
		pipeline.AddVulnScanner(plugins.NewCorsPlugin())
	}
	if enableSubTakeover {
		pipeline.AddVulnScanner(plugins.NewSubTakeoverPlugin())
	}
	if enableWitness {
		pipeline.SetScreenshotScanner(plugins.NewGowitnessPlugin(screenshotDir))
	}
	return pipeline.ExecuteFromSubdomains(ctx, targets)
}

func configuredPortScannerEngine() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("PORT_SCANNER_ENGINE")))
	switch raw {
	case "", "tscan", "tscanclient":
		return "tscan"
	case "naabu_nmap", "naabu", "nmap":
		return "naabu_nmap"
	default:
		return "tscan"
	}
}

func (s *Server) saveResultsToDB(projectID, rootDomain, jobID string, results []engine.Result) error {
	failureCount := 0
	for _, result := range results {
		var err error
		sourceModule := result.Type
		switch result.Type {
		case "domain":
			if subdomain, ok := result.Data.(string); ok {
				err = s.db.SaveOrUpdateAssetCandidate(map[string]interface{}{
					"project_id":    projectID,
					"root_domain":   rootDomain,
					"source_job_id": jobID,
					"source_module": sourceModule,
					"domain":        subdomain,
					"verify_status": "pending",
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
					_ = s.db.SaveOrUpdateAssetCandidate(map[string]interface{}{
						"project_id":          projectID,
						"root_domain":         mapString(data, "root_domain"),
						"source_job_id":       jobID,
						"source_module":       sourceModule,
						"domain":              mapString(data, "domain"),
						"last_ip":             mapString(data, "ip"),
						"last_url":            mapString(data, "url"),
						"last_status_code":    mapInt(data, "status_code"),
						"last_title":          mapString(data, "title"),
						"verify_status":       "verified",
						"verification_method": "httpx",
					})
				}
				if err == nil {
					s.saveSimpleEdge(projectID, rootDomain, "domain", mapString(data, "domain"), "ip", mapString(data, "ip"), "resolves_to", jobID)
				}
			}
		case "port_service", "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
				// Normalize host/domain from different port scanners (naabu/nmap)
				// to avoid split rows without fingerprint enrichment.
				if mapString(data, "domain") == "" {
					if host := strings.ToLower(strings.TrimSpace(mapString(data, "host"))); host != "" {
						data["domain"] = strings.TrimSuffix(host, ".")
					}
				}
				data["project_id"] = projectID
				if mapString(data, "root_domain") == "" {
					data["root_domain"] = rootDomain
				}
				data["source_job_id"] = jobID
				data["source_module"] = sourceModule
				err = s.db.SaveOrUpdatePort(data)
				if err == nil && strings.TrimSpace(mapString(data, "domain")) != "" {
					_ = s.db.SaveOrUpdateAssetCandidate(map[string]interface{}{
						"project_id":          projectID,
						"root_domain":         mapString(data, "root_domain"),
						"source_job_id":       jobID,
						"source_module":       sourceModule,
						"domain":              mapString(data, "domain"),
						"last_ip":             mapString(data, "ip"),
						"verify_status":       "verified",
						"verification_method": "open_port",
					})
				}
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
	counts := map[string]int{
		"subdomains":      0,
		"web_services":    0,
		"ports":           0,
		"vulnerabilities": 0,
		"screenshots":     0,
	}
	portBuckets := make(map[string]map[string]struct{})
	portBucketsWithEmptyDomain := make(map[string]bool)
	for _, r := range results {
		switch r.Type {
		case "domain":
			counts["subdomains"]++
		case "web_service":
			counts["web_services"]++
		case "port_service", "open_port":
			baseKey, domain, ok := portResultCountKey(r)
			if !ok {
				continue
			}
			if _, exists := portBuckets[baseKey]; !exists {
				portBuckets[baseKey] = make(map[string]struct{})
			}
			if domain == "" {
				portBucketsWithEmptyDomain[baseKey] = true
				continue
			}
			portBuckets[baseKey][domain] = struct{}{}
		case "vulnerability":
			counts["vulnerabilities"]++
		case "screenshot":
			if data, ok := r.Data.(map[string]interface{}); ok {
				counts["screenshots"] += mapInt(data, "screenshot_count")
			}
		}
	}
	for baseKey, domains := range portBuckets {
		if len(domains) > 0 {
			counts["ports"] += len(domains)
			continue
		}
		if portBucketsWithEmptyDomain[baseKey] {
			counts["ports"]++
		}
	}
	return counts
}

func portResultCountKey(result engine.Result) (string, string, bool) {
	data, ok := result.Data.(map[string]interface{})
	if !ok {
		return "", "", false
	}

	ip := strings.TrimSpace(mapString(data, "ip"))
	port := mapInt(data, "port")
	if ip == "" || port <= 0 {
		return "", "", false
	}

	protocol := strings.ToLower(strings.TrimSpace(mapString(data, "protocol")))
	if protocol == "" {
		protocol = "tcp"
	}

	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "domain")), "."))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(mapString(data, "host")), "."))
	}

	return fmt.Sprintf("%s|%d|%s", ip, port, protocol), domain, true
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Monitor targets/runs/changes API
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (s *Server) handleMonitorTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListMonitorTargets(w, r)
	case http.MethodPost:
		s.handleCreateMonitorTarget(w, r)
	case http.MethodPut:
		s.handleUpdateMonitorTarget(w, r)
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
		policy := monitorVulnPolicyFromTarget(&t)
		resp = append(resp, monitorTargetResponse{
			ID:                int(t.ID),
			ProjectID:         t.ProjectID,
			RootDomain:        t.RootDomain,
			Enabled:           t.Enabled,
			IntervalSec:       t.IntervalSec,
			MonitorPorts:      t.MonitorPorts,
			NotifyAISummary:   t.NotifyAISummary,
			EnableVulnScan:    policy.EnableVulnScan,
			EnableNuclei:      policy.EnableNuclei,
			EnableCors:        policy.EnableCors,
			EnableSubtakeover: policy.EnableSubtakeover,
			VulnOnNewLive:     policy.VulnOnNewLive,
			VulnOnWebChanged:  policy.VulnOnWebChanged,
			VulnMaxURLs:       policy.VulnMaxURLs,
			VulnCooldownMin:   policy.VulnCooldownMin,
			LastVulnScanAt:    timePtrToISO(t.LastVulnScanAt),
			BaselineDone:      t.BaselineDone,
			BaselineVersion:   t.BaselineVersion,
			BaselineAt:        timePtrToISO(t.BaselineAt),
			LastRunAt:         timePtrToISO(t.LastRunAt),
			CreatedAt:         timeToISO(t.CreatedAt),
			UpdatedAt:         timeToISO(t.UpdatedAt),
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
	taskID, err := s.db.EnableMonitorTarget(projectID, domain, intervalSec, 3, buildMonitorTargetOptions(req))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeAudit(projectID, actorFromRequest(r), "create_monitor_target", "monitor_target", domain, map[string]interface{}{
		"intervalSec":       intervalSec,
		"monitorPorts":      req.MonitorPorts,
		"notifyAiSummary":   req.NotifyAISummary,
		"enableVulnScan":    req.EnableVulnScan,
		"enableNuclei":      req.EnableNuclei,
		"enableCors":        req.EnableCors,
		"enableSubtakeover": req.EnableSubtakeover,
		"vulnOnNewLive":     req.VulnOnNewLive,
		"vulnOnWebChanged":  req.VulnOnWebChanged,
		"vulnMaxUrls":       req.VulnMaxURLs,
		"vulnCooldownMin":   req.VulnCooldownMin,
		"taskId":            taskID,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"projectId":   projectID,
		"domain":      domain,
		"intervalSec": intervalSec,
		"jobId":       fmt.Sprintf("task-%d", taskID),
	})
}

func (s *Server) handleUpdateMonitorTarget(w http.ResponseWriter, r *http.Request) {
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
	opts := buildMonitorTargetOptions(req)
	if opts == nil {
		writeError(w, http.StatusBadRequest, "no monitor policy fields provided")
		return
	}
	if err := s.db.UpdateMonitorTargetOptions(projectID, domain, opts); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusNotFound, "monitor target not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeAudit(projectID, actorFromRequest(r), "update_monitor_target", "monitor_target", domain, map[string]interface{}{
		"monitorPorts":      req.MonitorPorts,
		"notifyAiSummary":   req.NotifyAISummary,
		"enableVulnScan":    req.EnableVulnScan,
		"enableNuclei":      req.EnableNuclei,
		"enableCors":        req.EnableCors,
		"enableSubtakeover": req.EnableSubtakeover,
		"vulnOnNewLive":     req.VulnOnNewLive,
		"vulnOnWebChanged":  req.VulnOnWebChanged,
		"vulnMaxUrls":       req.VulnMaxURLs,
		"vulnCooldownMin":   req.VulnCooldownMin,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "projectId": projectID, "domain": domain})
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
		s.writeAudit(projectID, actorFromRequest(r), "stop_monitor_target", "monitor_target", domain, nil, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped", "projectId": projectID, "domain": domain})
	case "delete":
		if err := s.db.DeleteMonitorDataByRootDomain(projectID, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeAudit(projectID, actorFromRequest(r), "delete_monitor_target", "monitor_target", domain, map[string]interface{}{
			"deleteData": true,
		}, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "projectId": projectID, "domain": domain})
	default:
		// Default: toggle stop
		if err := s.db.StopMonitorTarget(projectID, domain); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeAudit(projectID, actorFromRequest(r), "stop_monitor_target", "monitor_target", domain, nil, r)
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

func (s *Server) handleMonitorSnapshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 60, 1, 300)

	query := s.db.DB.Model(&db.MonitorSnapshot{}).Where("project_id = ?", projectID).Order("run_id desc").Limit(limit)
	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		query = query.Where("root_domain = ?", rd)
	}
	var snapshots []db.MonitorSnapshot
	if err := query.Find(&snapshots).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := make([]monitorSnapshotResponse, 0, len(snapshots))
	for _, snap := range snapshots {
		resp = append(resp, toMonitorSnapshotResponse(snap))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMonitorDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	rootFilter := normalizeRootDomain(r.URL.Query().Get("root_domain"))
	runIDRaw := parseBoundedInt(r.URL.Query().Get("run_id"), 0, 0, 1_000_000_000)

	runQuery := s.db.DB.Model(&db.MonitorRun{}).Where("project_id = ?", projectID)
	if rootFilter != "" {
		runQuery = runQuery.Where("root_domain = ?", rootFilter)
	}
	var currentRun db.MonitorRun
	var err error
	if runIDRaw > 0 {
		err = runQuery.Where("id = ?", runIDRaw).First(&currentRun).Error
	} else {
		err = runQuery.Where("status = ?", "success").Order("id desc").First(&currentRun).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = runQuery.Order("id desc").First(&currentRun).Error
		}
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeJSON(w, http.StatusOK, monitorDiffResponse{})
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var currentSnap db.MonitorSnapshot
	if err := s.db.DB.Where("project_id = ? AND root_domain = ? AND run_id = ?", projectID, currentRun.RootDomain, currentRun.ID).First(&currentSnap).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		currentSnap = db.MonitorSnapshot{
			ProjectID:      projectID,
			RootDomain:     currentRun.RootDomain,
			RunID:          currentRun.ID,
			AssetCount:     0,
			PortCount:      0,
			OpenEventCount: 0,
		}
	}

	var previousRun db.MonitorRun
	prevExists := s.db.DB.Where("project_id = ? AND root_domain = ? AND id < ? AND status = ?", projectID, currentRun.RootDomain, currentRun.ID, "success").
		Order("id desc").First(&previousRun).Error == nil

	var previousResp *monitorSnapshotResponse
	resp := monitorDiffResponse{
		ProjectID:  projectID,
		RootDomain: currentRun.RootDomain,
		RunID:      int(currentRun.ID),
		Snapshot:   toMonitorSnapshotResponse(currentSnap),
	}

	if prevExists {
		resp.PrevRunID = int(previousRun.ID)
		var prevSnap db.MonitorSnapshot
		if err := s.db.DB.Where("project_id = ? AND root_domain = ? AND run_id = ?", projectID, currentRun.RootDomain, previousRun.ID).First(&prevSnap).Error; err == nil {
			prev := toMonitorSnapshotResponse(prevSnap)
			previousResp = &prev
			resp.Previous = previousResp
		}
	}
	if previousResp != nil {
		resp.Delta.AssetCount = resp.Snapshot.AssetCount - previousResp.AssetCount
		resp.Delta.PortCount = resp.Snapshot.PortCount - previousResp.PortCount
		resp.Delta.OpenEventCount = resp.Snapshot.OpenEventCount - previousResp.OpenEventCount
	}

	limit := parseBoundedInt(r.URL.Query().Get("limit"), 200, 20, 500)

	var assetChanges []db.AssetChange
	if err := s.db.DB.Where("project_id = ? AND run_id = ?", projectID, currentRun.ID).Order("id desc").Limit(limit).Find(&assetChanges).Error; err == nil {
		resp.AssetChanges = make([]monitorChangeResponse, 0, len(assetChanges))
		for _, ac := range assetChanges {
			resp.AssetChanges = append(resp.AssetChanges, monitorChangeResponse{
				RunID:      int(ac.RunID),
				ProjectID:  ac.ProjectID,
				RootDomain: ac.RootDomain,
				ChangeType: ac.ChangeType,
				Domain:     ac.Domain,
				IP:         ac.IP,
				Port:       ac.Port,
				StatusCode: ac.StatusCode,
				Title:      ac.Title,
				CreatedAt:  timeToISO(ac.CreatedAt),
			})
		}
	}

	var portChanges []db.PortChange
	if err := s.db.DB.Where("project_id = ? AND run_id = ?", projectID, currentRun.ID).Order("id desc").Limit(limit).Find(&portChanges).Error; err == nil {
		resp.PortChanges = make([]monitorChangeResponse, 0, len(portChanges))
		for _, pc := range portChanges {
			title := strings.TrimSpace(pc.Service)
			if strings.TrimSpace(pc.Version) != "" {
				if title == "" {
					title = strings.TrimSpace(pc.Version)
				} else {
					title += " " + strings.TrimSpace(pc.Version)
				}
			}
			resp.PortChanges = append(resp.PortChanges, monitorChangeResponse{
				RunID:      int(pc.RunID),
				ProjectID:  pc.ProjectID,
				RootDomain: pc.RootDomain,
				ChangeType: pc.ChangeType,
				Domain:     pc.Domain,
				IP:         pc.IP,
				Port:       pc.Port,
				Title:      title,
				CreatedAt:  timeToISO(pc.CreatedAt),
			})
		}
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
					Domain: ac.Domain, IP: ac.IP, Port: ac.Port, StatusCode: ac.StatusCode, Title: ac.Title,
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

func (s *Server) handleMonitorEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}

	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	eventTypeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("event_type")))
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit := parseBoundedInt(r.URL.Query().Get("limit"), 200, 1, 1000)

	query := s.db.DB.Model(&db.MonitorEvent{}).Where("project_id = ?", projectID)
	if rd := normalizeRootDomain(r.URL.Query().Get("root_domain")); rd != "" {
		query = query.Where("root_domain = ?", rd)
	}
	if statusFilter != "" && statusFilter != "all" {
		query = query.Where("status = ?", statusFilter)
	}
	if eventTypeFilter != "" && eventTypeFilter != "all" {
		query = query.Where("event_type = ?", eventTypeFilter)
	}
	if search != "" {
		pattern := "%" + search + "%"
		query = query.Where(
			"LOWER(event_type) LIKE ? OR LOWER(status) LIKE ? OR LOWER(domain) LIKE ? OR LOWER(ip) LIKE ? OR CAST(port AS TEXT) LIKE ? OR LOWER(title) LIKE ?",
			pattern, pattern, pattern, pattern, pattern, pattern,
		)
	}

	var events []db.MonitorEvent
	if err := query.Order("last_changed_at desc, id desc").Limit(limit).Find(&events).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]monitorEventResponse, 0, len(events))
	for _, e := range events {
		resp = append(resp, monitorEventResponse{
			ID:              int(e.ID),
			ProjectID:       e.ProjectID,
			RootDomain:      e.RootDomain,
			EventKey:        e.EventKey,
			EventType:       e.EventType,
			Status:          normalizeMonitorEventStatus(e.Status),
			Domain:          e.Domain,
			URL:             e.URL,
			IP:              e.IP,
			Port:            e.Port,
			Protocol:        e.Protocol,
			Service:         e.Service,
			Version:         e.Version,
			Title:           e.Title,
			StatusCode:      e.StatusCode,
			FirstSeenAt:     timeToISO(e.FirstSeenAt),
			LastSeenAt:      timeToISO(e.LastSeenAt),
			LastChangedAt:   timeToISO(e.LastChangedAt),
			ResolvedAt:      timePtrToISO(e.ResolvedAt),
			OccurrenceCount: e.OccurrenceCount,
			LastRunID:       int(e.LastRunID),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleMonitorEventStatus updates status of a single monitor event (ack/ignored/open/resolved).
func (s *Server) handleMonitorEventStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ProjectID string `json:"projectId"`
		EventID   int    `json:"eventId"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status, ok := parseMonitorEventStatus(body.Status)
	if body.ProjectID == "" || body.EventID <= 0 {
		writeError(w, http.StatusBadRequest, "projectId and eventId are required")
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid status; must be open/resolved/ack/ignored")
		return
	}
	now := time.Now()
	updates := map[string]interface{}{
		"status":          status,
		"last_changed_at": now,
	}
	if status == "resolved" {
		updates["resolved_at"] = &now
	} else {
		updates["resolved_at"] = nil
	}
	result := s.db.DB.Model(&db.MonitorEvent{}).Where("id = ? AND project_id = ?", body.EventID, body.ProjectID).Updates(updates)
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "eventId": body.EventID, "newStatus": status})
}

// handleBulkMonitorEventStatus updates status of multiple monitor events at once.
func (s *Server) handleBulkMonitorEventStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ProjectID string `json:"projectId"`
		EventIDs  []int  `json:"eventIds"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	status, ok := parseMonitorEventStatus(body.Status)
	if body.ProjectID == "" || len(body.EventIDs) == 0 {
		writeError(w, http.StatusBadRequest, "projectId and eventIds are required")
		return
	}
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid status; must be open/resolved/ack/ignored")
		return
	}
	if len(body.EventIDs) > 500 {
		writeError(w, http.StatusBadRequest, "max 500 IDs per request")
		return
	}
	now := time.Now()
	updates := map[string]interface{}{
		"status":          status,
		"last_changed_at": now,
	}
	if status == "resolved" {
		updates["resolved_at"] = &now
	} else {
		updates["resolved_at"] = nil
	}
	result := s.db.DB.Model(&db.MonitorEvent{}).Where("id IN ? AND project_id = ?", body.EventIDs, body.ProjectID).Updates(updates)
	if result.Error != nil {
		writeError(w, http.StatusInternalServerError, result.Error.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "updated": result.RowsAffected, "newStatus": status})
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Screenshots
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

func (s *Server) handleScreenshotDomains(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}
	var scopes []db.ProjectScope
	if err := s.db.DB.Where("project_id = ? AND enabled = ?", projectID, true).Find(&scopes).Error; err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(scopes) == 0 {
		writeJSON(w, http.StatusOK, []screenshotDomainResponse{})
		return
	}
	scopeSet := make(map[string]bool, len(scopes))
	for _, sc := range scopes {
		rd := normalizeRootDomain(sc.RootDomain)
		if rd != "" {
			scopeSet[rd] = true
		}
	}

	domains, err := plugins.ListScreenshotDomains(s.screenshotDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []screenshotDomainResponse{})
		return
	}
	resp := make([]screenshotDomainResponse, 0, len(domains))
	for _, rootDomain := range domains {
		if !scopeSet[normalizeRootDomain(rootDomain)] {
			continue
		}
		domainDir := filepath.Join(s.screenshotDir, rootDomain)
		ssDir := filepath.Join(domainDir, "screenshots")
		count := 0
		if entries, err := os.ReadDir(ssDir); err == nil {
			for _, e := range entries {
				name := strings.ToLower(e.Name())
				if !e.IsDir() && (strings.HasSuffix(name, ".png") || strings.HasSuffix(name, ".jpg") || strings.HasSuffix(name, ".jpeg")) {
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
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
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
	ok, err := s.isDomainInProjectScope(projectID, rootDomain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
		return
	}
	if !ok {
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
			ProjectID:    projectID,
			URL:          item.URL,
			Filename:     item.Filename,
			Title:        item.Title,
			StatusCode:   item.StatusCode,
			CreatedAt:    item.ProbedAt,
			RootDomain:   rootDomain,
			ThumbnailURL: fmt.Sprintf("/api/screenshots/file/%s/%s?project_id=%s", rootDomain, url.PathEscape(item.Filename), url.QueryEscape(projectID)),
			FullURL:      fmt.Sprintf("/api/screenshots/file/%s/%s?project_id=%s", rootDomain, url.PathEscape(item.Filename), url.QueryEscape(projectID)),
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleBulkDeleteScreenshots(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ProjectID  string   `json:"projectId"`
		RootDomain string   `json:"rootDomain"`
		Filenames  []string `json:"filenames"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	projectID := strings.TrimSpace(body.ProjectID)
	rootDomain := normalizeRootDomain(body.RootDomain)
	if projectID == "" || rootDomain == "" || len(body.Filenames) == 0 {
		writeError(w, http.StatusBadRequest, "projectId, rootDomain and filenames are required")
		return
	}
	if len(body.Filenames) > 1000 {
		writeError(w, http.StatusBadRequest, "max 1000 filenames per request")
		return
	}
	ok, err := s.isDomainInProjectScope(projectID, rootDomain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "domain is not in project scope")
		return
	}

	screenshotDir := filepath.Join(s.screenshotDir, rootDomain, "screenshots")
	deleted := 0
	skipped := make([]string, 0)
	seen := make(map[string]bool, len(body.Filenames))
	for _, raw := range body.Filenames {
		filename := filepath.Base(strings.TrimSpace(raw))
		filename = strings.TrimSpace(filename)
		if filename == "" || seen[filename] {
			continue
		}
		seen[filename] = true
		ext := strings.ToLower(filepath.Ext(filename))
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
			skipped = append(skipped, filename)
			continue
		}
		filePath := filepath.Join(screenshotDir, filename)
		if err := os.Remove(filePath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				skipped = append(skipped, filename)
				continue
			}
			writeError(w, http.StatusInternalServerError, "failed to delete screenshot: "+err.Error())
			return
		}
		deleted++
	}

	plugins.InvalidateScreenshotCache(s.screenshotDir, rootDomain)
	s.writeAudit(projectID, actorFromRequest(r), "bulk_delete_screenshots", "screenshot", rootDomain, map[string]interface{}{
		"rootDomain": rootDomain,
		"deleted":    deleted,
		"requested":  len(body.Filenames),
		"skipped":    skipped,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "ok",
		"deleted":   deleted,
		"requested": len(body.Filenames),
		"skipped":   skipped,
	})
}

func (s *Server) handleScreenshotFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
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
	ok, err := s.isDomainInProjectScope(projectID, rootDomain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "project scope check failed: "+err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "domain is not in project scope")
		return
	}
	filePath := filepath.Join(s.screenshotDir, rootDomain, "screenshots", filepath.Base(filename))
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	http.ServeFile(w, r, filePath)
}

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Settings
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
		AI: aiSettingsResponse{
			Enabled:           settings.AI.Enabled,
			BaseURL:           settings.AI.BaseURL,
			APIKey:            maskSecret(settings.AI.APIKey),
			Model:             settings.AI.Model,
			TimeoutSec:        settings.AI.TimeoutSec,
			MaxRetries:        settings.AI.MaxRetries,
			RequestsPerMinute: settings.AI.RequestsPerMinute,
			Configured:        strings.TrimSpace(settings.AI.APIKey) != "",
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
	aiChanged := false
	var aiSnapshot runtimeAISettings
	if p := patch.Database; p != nil {
		if p.Host != nil {
			s.settings.Database.Host = strings.TrimSpace(*p.Host)
		}
		if p.Port != nil {
			s.settings.Database.Port = *p.Port
		}
		if p.User != nil {
			s.settings.Database.User = strings.TrimSpace(*p.User)
		}
		if p.DBName != nil {
			s.settings.Database.DBName = strings.TrimSpace(*p.DBName)
		}
		if p.SSLMode != nil {
			s.settings.Database.SSLMode = strings.TrimSpace(*p.SSLMode)
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
	if p := patch.AI; p != nil {
		aiChanged = true
		if p.Enabled != nil {
			s.settings.AI.Enabled = *p.Enabled
		}
		if p.BaseURL != nil {
			s.settings.AI.BaseURL = strings.TrimSpace(*p.BaseURL)
		}
		if p.APIKey != nil {
			if next := strings.TrimSpace(*p.APIKey); next != "" {
				s.settings.AI.APIKey = next
			}
		}
		if p.Model != nil {
			s.settings.AI.Model = strings.TrimSpace(*p.Model)
		}
		if p.TimeoutSec != nil {
			s.settings.AI.TimeoutSec = *p.TimeoutSec
		}
		if p.MaxRetries != nil {
			s.settings.AI.MaxRetries = *p.MaxRetries
		}
		if p.RequestsPerMinute != nil {
			s.settings.AI.RequestsPerMinute = *p.RequestsPerMinute
		}
		s.settings.AI = normalizeRuntimeAISettings(s.settings.AI)
		aiSnapshot = s.settings.AI
	}
	s.settingsMu.Unlock()
	if aiChanged {
		if err := s.persistAISettings(aiSnapshot); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist ai settings: "+err.Error())
			return
		}
		s.resetAILimiter()
	}

	s.handleGetSettings(w, r)
}

type aiSettingsPersistedPayload struct {
	Enabled           bool   `json:"enabled"`
	BaseURL           string `json:"baseUrl"`
	APIKey            string `json:"apiKey"`
	Model             string `json:"model"`
	TimeoutSec        int    `json:"timeoutSec"`
	MaxRetries        int    `json:"maxRetries"`
	RequestsPerMinute int    `json:"requestsPerMinute"`
}

func (s *Server) loadPersistedSettings() error {
	raw, err := s.db.GetAppSetting(appSettingAIKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var payload aiSettingsPersistedPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return fmt.Errorf("decode persisted ai settings failed: %w", err)
	}
	s.settingsMu.Lock()
	s.settings.AI.Enabled = payload.Enabled
	if strings.TrimSpace(payload.BaseURL) != "" {
		s.settings.AI.BaseURL = payload.BaseURL
	}
	if strings.TrimSpace(payload.APIKey) != "" {
		s.settings.AI.APIKey = payload.APIKey
	}
	if strings.TrimSpace(payload.Model) != "" {
		s.settings.AI.Model = payload.Model
	}
	if payload.TimeoutSec > 0 {
		s.settings.AI.TimeoutSec = payload.TimeoutSec
	}
	if payload.MaxRetries >= 0 {
		s.settings.AI.MaxRetries = payload.MaxRetries
	}
	if payload.RequestsPerMinute >= 0 {
		s.settings.AI.RequestsPerMinute = payload.RequestsPerMinute
	}
	s.settings.AI = normalizeRuntimeAISettings(s.settings.AI)
	s.settingsMu.Unlock()
	s.resetAILimiter()
	return nil
}

func (s *Server) persistAISettings(cfg runtimeAISettings) error {
	cfg = normalizeRuntimeAISettings(cfg)
	payload := aiSettingsPersistedPayload{
		Enabled:           cfg.Enabled,
		BaseURL:           cfg.BaseURL,
		APIKey:            cfg.APIKey,
		Model:             cfg.Model,
		TimeoutSec:        cfg.TimeoutSec,
		MaxRetries:        cfg.MaxRetries,
		RequestsPerMinute: cfg.RequestsPerMinute,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.db.UpsertAppSetting(appSettingAIKey, string(raw))
}

func normalizeRuntimeAISettings(cfg runtimeAISettings) runtimeAISettings {
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com/v1"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	cfg.Model = strings.TrimSpace(cfg.Model)
	if cfg.Model == "" {
		cfg.Model = "gpt-4o-mini"
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 30
	}
	cfg.TimeoutSec = clampIntRange(cfg.TimeoutSec, 5, 120)
	if cfg.MaxRetries < 0 {
		cfg.MaxRetries = 2
	}
	cfg.MaxRetries = clampIntRange(cfg.MaxRetries, 0, 5)
	if cfg.RequestsPerMinute < 0 {
		cfg.RequestsPerMinute = 60
	}
	cfg.RequestsPerMinute = clampIntRange(cfg.RequestsPerMinute, 0, 600)
	return cfg
}

func (s *Server) resetAILimiter() {
	s.aiLimiterMu.Lock()
	s.aiLimiterWindowStart = time.Time{}
	s.aiLimiterUsed = 0
	s.aiLimiterMu.Unlock()
}

func (s *Server) checkAndConsumeAILimit(limit int) (bool, time.Duration) {
	if limit <= 0 {
		return true, 0
	}
	now := time.Now()
	s.aiLimiterMu.Lock()
	defer s.aiLimiterMu.Unlock()
	if s.aiLimiterWindowStart.IsZero() || now.Sub(s.aiLimiterWindowStart) >= time.Minute {
		s.aiLimiterWindowStart = now
		s.aiLimiterUsed = 0
	}
	if s.aiLimiterUsed < limit {
		s.aiLimiterUsed++
		return true, 0
	}
	wait := time.Minute - now.Sub(s.aiLimiterWindowStart)
	if wait < 0 {
		wait = 0
	}
	return false, wait
}

func ensureCommonToolPaths() {
	cur := os.Getenv("PATH")
	existing := make(map[string]bool)
	for _, item := range filepath.SplitList(cur) {
		cleaned := filepath.Clean(item)
		if cleaned == "" || cleaned == "." {
			continue
		}
		existing[cleaned] = true
	}

	candidates := []string{
		"/root/go/bin",
		"/snap/bin",
	}
	toAppend := make([]string, 0, len(candidates))
	for _, path := range candidates {
		st, err := os.Stat(path)
		if err != nil || !st.IsDir() {
			continue
		}
		cleaned := filepath.Clean(path)
		if existing[cleaned] {
			continue
		}
		existing[cleaned] = true
		toAppend = append(toAppend, cleaned)
	}

	if len(toAppend) == 0 {
		return
	}
	if strings.TrimSpace(cur) == "" {
		_ = os.Setenv("PATH", strings.Join(toAppend, string(os.PathListSeparator)))
		return
	}
	_ = os.Setenv("PATH", cur+string(os.PathListSeparator)+strings.Join(toAppend, string(os.PathListSeparator)))
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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Utilities
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
		AI: runtimeAISettings{
			Enabled:           envBoolOrDefault("OPENAI_ENABLED", true),
			BaseURL:           envOrDefault("OPENAI_BASE_URL", "https://api.openai.com/v1"),
			APIKey:            strings.TrimSpace(os.Getenv("OPENAI_API_KEY")),
			Model:             envOrDefault("OPENAI_MODEL", "gpt-4o-mini"),
			TimeoutSec:        envIntOrDefault("OPENAI_TIMEOUT_SEC", 30),
			MaxRetries:        envIntOrDefault("OPENAI_MAX_RETRIES", 2),
			RequestsPerMinute: envIntOrDefault("OPENAI_REQUESTS_PER_MINUTE", 60),
		},
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func envBoolOrDefault(key string, defaultVal bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return defaultVal
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return defaultVal
	}
}

func clampIntRange(v, minVal, maxVal int) int {
	if v < minVal {
		return minVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}

func shouldEnableCorsWithNuclei() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CORS_WITH_NUCLEI")))
	switch raw {
	case "", "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return true
	}
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

func normalizeMonitorEventStatus(raw string) string {
	if status, ok := parseMonitorEventStatus(raw); ok {
		return status
	}
	return monitorEventStatusOpen
}

func parseMonitorEventStatus(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "open", "resolved", "ack", "ignored":
		return s, true
	default:
		return "", false
	}
}

func sanitizeModules(raw []string) []string {
	allowed := map[string]bool{
		"subfinder": true, "findomain": true, "bbot": true, "shosubgo": true,
		"bbot_active": true, "chaos": true,
		"dictgen": true, "dnsx_bruteforce": true,
		"naabu": true, "nmap": true,
		"httpx": true, "gowitness": true, "nuclei": true, "cors": true, "subtakeover": true,
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

type monitorVulnPolicy struct {
	MonitorPorts      bool
	EnableVulnScan    bool
	EnableNuclei      bool
	EnableCors        bool
	EnableSubtakeover bool
	VulnOnNewLive     bool
	VulnOnWebChanged  bool
	VulnMaxURLs       int
	VulnCooldownMin   int
}

type monitorSnapshotAssetState struct {
	EventKey     string   `json:"eventKey"`
	Domain       string   `json:"domain"`
	URL          string   `json:"url"`
	IP           string   `json:"ip"`
	Port         int      `json:"port"`
	StatusCode   int      `json:"statusCode"`
	Title        string   `json:"title"`
	Technologies []string `json:"technologies,omitempty"`
}

type monitorSnapshotPortState struct {
	EventKey string `json:"eventKey"`
	Domain   string `json:"domain"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
}

type monitorSnapshotPayload struct {
	ServiceDistribution []dashboardCountItemResponse `json:"serviceDistribution,omitempty"`
	GeneratedAt         string                       `json:"generatedAt,omitempty"`
	LiveAssets          []monitorSnapshotAssetState  `json:"liveAssets,omitempty"`
	Ports               []monitorSnapshotPortState   `json:"ports,omitempty"`
}

func clampMonitorVulnMaxURLs(n int) int {
	if n <= 0 {
		return defaultMonitorVulnMaxURLs
	}
	if n > maxMonitorVulnMaxURLs {
		return maxMonitorVulnMaxURLs
	}
	return n
}

func clampMonitorVulnCooldownMin(n int) int {
	if n <= 0 {
		return defaultMonitorVulnCooldown
	}
	if n > maxMonitorVulnCooldownMin {
		return maxMonitorVulnCooldownMin
	}
	return n
}

func monitorVulnPolicyFromTarget(target *db.MonitorTarget) monitorVulnPolicy {
	policy := monitorVulnPolicy{
		MonitorPorts:      true,
		EnableVulnScan:    false,
		EnableNuclei:      false,
		EnableCors:        false,
		EnableSubtakeover: false,
		VulnOnNewLive:     true,
		VulnOnWebChanged:  false,
		VulnMaxURLs:       defaultMonitorVulnMaxURLs,
		VulnCooldownMin:   defaultMonitorVulnCooldown,
	}
	if target == nil {
		return policy
	}
	policy.EnableVulnScan = target.EnableVulnScan
	policy.MonitorPorts = target.MonitorPorts
	policy.EnableNuclei = target.EnableNuclei
	policy.EnableCors = target.EnableCors
	policy.EnableSubtakeover = target.EnableSubtakeover
	policy.VulnOnNewLive = target.VulnOnNewLive
	policy.VulnOnWebChanged = target.VulnOnWebChanged
	policy.VulnMaxURLs = clampMonitorVulnMaxURLs(target.VulnMaxURLs)
	policy.VulnCooldownMin = clampMonitorVulnCooldownMin(target.VulnCooldownMin)
	// Guard against misconfiguration where no trigger is selected.
	if !policy.VulnOnNewLive && !policy.VulnOnWebChanged {
		policy.VulnOnNewLive = true
	}
	return policy
}

func buildMonitorTargetOptions(req createMonitorRequest) *db.MonitorTargetOptions {
	if req.MonitorPorts == nil &&
		req.NotifyAISummary == nil &&
		req.EnableVulnScan == nil &&
		req.EnableNuclei == nil &&
		req.EnableCors == nil &&
		req.EnableSubtakeover == nil &&
		req.VulnOnNewLive == nil &&
		req.VulnOnWebChanged == nil &&
		req.VulnMaxURLs == nil &&
		req.VulnCooldownMin == nil {
		return nil
	}
	opts := &db.MonitorTargetOptions{
		MonitorPorts:      req.MonitorPorts,
		NotifyAISummary:   req.NotifyAISummary,
		EnableVulnScan:    req.EnableVulnScan,
		EnableNuclei:      req.EnableNuclei,
		EnableCors:        req.EnableCors,
		EnableSubtakeover: req.EnableSubtakeover,
		VulnOnNewLive:     req.VulnOnNewLive,
		VulnOnWebChanged:  req.VulnOnWebChanged,
		VulnMaxURLs:       req.VulnMaxURLs,
		VulnCooldownMin:   req.VulnCooldownMin,
	}
	return opts
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func trimForNotify(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if s == "" || maxLen <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	return string(r[:maxLen]) + "..."
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

func decodeJSONBObject(data db.JSONB) map[string]interface{} {
	if len(data) == 0 {
		return nil
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil
	}
	return obj
}

func toMonitorSnapshotResponse(snap db.MonitorSnapshot) monitorSnapshotResponse {
	summary := decodeJSONBObject(snap.Summary)
	if summary != nil {
		delete(summary, "liveAssets")
		delete(summary, "ports")
	}
	return monitorSnapshotResponse{
		ID:             int(snap.ID),
		ProjectID:      snap.ProjectID,
		RootDomain:     snap.RootDomain,
		RunID:          int(snap.RunID),
		AssetCount:     snap.AssetCount,
		PortCount:      snap.PortCount,
		OpenEventCount: snap.OpenEventCount,
		Summary:        summary,
		CreatedAt:      timeToISO(snap.CreatedAt),
	}
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

func (s *Server) listProjectRootDomains(projectID string) ([]string, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("project id is required")
	}
	var p db.Project
	if err := s.db.DB.Where("id = ?", projectID).First(&p).Error; err != nil {
		return nil, err
	}
	var scopes []db.ProjectScope
	if err := s.db.DB.Where("project_id = ?", projectID).Find(&scopes).Error; err != nil {
		return nil, err
	}
	rootDomains := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, sc := range scopes {
		rd := normalizeRootDomain(sc.RootDomain)
		if rd == "" || seen[rd] {
			continue
		}
		seen[rd] = true
		rootDomains = append(rootDomains, rd)
	}
	sort.Strings(rootDomains)
	return rootDomains, nil
}

func (s *Server) cleanupScreenshotDirsByRootDomains(deletedProjectID string, rootDomains []string) []string {
	if len(rootDomains) == 0 {
		return nil
	}
	cleaned := make([]string, 0, len(rootDomains))
	for _, rd := range rootDomains {
		rootDomain := normalizeRootDomain(rd)
		if rootDomain == "" {
			continue
		}
		var refs int64
		err := s.db.DB.Model(&db.ProjectScope{}).
			Where("root_domain = ? AND project_id <> ?", rootDomain, deletedProjectID).
			Count(&refs).Error
		if err != nil {
			log.Printf("[Project] screenshot cleanup check failed root=%s: %v", rootDomain, err)
			continue
		}
		if refs > 0 {
			continue
		}
		dir := filepath.Join(s.screenshotDir, rootDomain)
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("[Project] screenshot dir cleanup failed root=%s path=%s: %v", rootDomain, dir, err)
			continue
		}
		cleaned = append(cleaned, rootDomain)
	}
	sort.Strings(cleaned)
	return cleaned
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
	// Allow all origins to avoid frontend origin mismatch issues.
	return true, nil
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

func resolveAssetCandidateOrder(sortByRaw, sortDirRaw string) string {
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
		"status_code": "last_status_code",
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

func resolveJobOrder(sortByRaw, sortDirRaw string) string {
	sortBy := strings.ToLower(strings.TrimSpace(sortByRaw))
	sortDir := strings.ToLower(strings.TrimSpace(sortDirRaw))
	if sortDir != "asc" {
		sortDir = "desc"
	}
	allowed := map[string]string{
		"started_at":   "started_at",
		"finished_at":  "finished_at",
		"duration_sec": "duration_sec",
		"status":       "status",
		"root_domain":  "root_domain",
	}
	column, ok := allowed[sortBy]
	if !ok {
		column = "started_at"
	}
	switch column {
	case "finished_at":
		return fmt.Sprintf("%s %s NULLS LAST, started_at desc, id desc", column, sortDir)
	case "duration_sec":
		return fmt.Sprintf("%s %s, started_at desc, id desc", column, sortDir)
	default:
		return fmt.Sprintf("%s %s, id desc", column, sortDir)
	}
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

func normalizeJobLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "info", "warn", "error":
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return "info"
	}
}

func (s *Server) appendJobLog(projectID, jobID, level, message string) {
	if s == nil || s.db == nil {
		return
	}
	msg := strings.TrimSpace(message)
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(jobID) == "" || msg == "" {
		return
	}
	if err := s.db.CreateJobLog(projectID, jobID, normalizeJobLogLevel(level), msg); err != nil {
		log.Printf("[JobLog] write failed project=%s job=%s: %v", projectID, jobID, err)
	}
}

func (s *Server) appendJobLogf(projectID, jobID, level, format string, args ...interface{}) {
	s.appendJobLog(projectID, jobID, level, fmt.Sprintf(format, args...))
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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Asset Detail
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Bulk Operations
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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
	var deletedAssets int64
	deletedDeps := map[string]int64{
		"ports":      0,
		"vulns":      0,
		"vulnEvents": 0,
		"edges":      0,
		"candidates": 0,
	}
	err := s.db.DB.Transaction(func(tx *gorm.DB) error {
		var targets []db.Asset
		if err := tx.Where("project_id = ? AND id IN ?", body.ProjectID, body.IDs).Find(&targets).Error; err != nil {
			return err
		}
		if len(targets) == 0 {
			return nil
		}

		assetIDs := make([]uint, 0, len(targets))
		domainSet := map[string]bool{}
		ipSet := map[string]bool{}
		identifierSet := map[string]bool{}
		for _, a := range targets {
			assetIDs = append(assetIDs, a.ID)
			identifierSet[strconv.Itoa(int(a.ID))] = true
			domain := strings.ToLower(strings.TrimSpace(a.Domain))
			if domain != "" {
				domainSet[domain] = true
				identifierSet[domain] = true
			}
			ip := strings.TrimSpace(a.IP)
			if ip != "" {
				ipSet[ip] = true
				identifierSet[ip] = true
			}
		}

		domains := make([]string, 0, len(domainSet))
		for d := range domainSet {
			domains = append(domains, d)
		}
		ips := make([]string, 0, len(ipSet))
		for ip := range ipSet {
			ips = append(ips, ip)
		}

		if len(assetIDs) > 0 {
			r := tx.Where("project_id = ? AND asset_id IN ?", body.ProjectID, assetIDs).Delete(&db.Port{})
			if r.Error != nil {
				return r.Error
			}
			deletedDeps["ports"] += r.RowsAffected
		}
		if len(domains) > 0 || len(ips) > 0 {
			var r *gorm.DB
			switch {
			case len(domains) > 0 && len(ips) > 0:
				r = tx.Where("project_id = ? AND (domain IN ? OR ip IN ?)", body.ProjectID, domains, ips).Delete(&db.Port{})
			case len(domains) > 0:
				r = tx.Where("project_id = ? AND domain IN ?", body.ProjectID, domains).Delete(&db.Port{})
			default:
				r = tx.Where("project_id = ? AND ip IN ?", body.ProjectID, ips).Delete(&db.Port{})
			}
			if r.Error != nil {
				return r.Error
			}
			deletedDeps["ports"] += r.RowsAffected
		}

		vulnIDSet := map[uint]bool{}
		collectVulnIDs := func(q *gorm.DB) error {
			var ids []uint
			if err := q.Pluck("id", &ids).Error; err != nil {
				return err
			}
			for _, id := range ids {
				vulnIDSet[id] = true
			}
			return nil
		}
		if len(assetIDs) > 0 {
			if err := collectVulnIDs(tx.Model(&db.Vulnerability{}).Where("project_id = ? AND asset_id IN ?", body.ProjectID, assetIDs)); err != nil {
				return err
			}
		}
		if len(domains) > 0 {
			if err := collectVulnIDs(tx.Model(&db.Vulnerability{}).Where("project_id = ? AND (domain IN ? OR host IN ?)", body.ProjectID, domains, domains)); err != nil {
				return err
			}
		}
		if len(ips) > 0 {
			if err := collectVulnIDs(tx.Model(&db.Vulnerability{}).Where("project_id = ? AND ip IN ?", body.ProjectID, ips)); err != nil {
				return err
			}
		}
		if len(vulnIDSet) > 0 {
			vulnIDs := make([]uint, 0, len(vulnIDSet))
			for id := range vulnIDSet {
				vulnIDs = append(vulnIDs, id)
				identifierSet[strconv.Itoa(int(id))] = true
			}
			rEvents := tx.Where("project_id = ? AND vuln_id IN ?", body.ProjectID, vulnIDs).Delete(&db.VulnEvent{})
			if rEvents.Error != nil {
				return rEvents.Error
			}
			deletedDeps["vulnEvents"] += rEvents.RowsAffected

			rVulns := tx.Where("project_id = ? AND id IN ?", body.ProjectID, vulnIDs).Delete(&db.Vulnerability{})
			if rVulns.Error != nil {
				return rVulns.Error
			}
			deletedDeps["vulns"] += rVulns.RowsAffected
		}

		identifiers := make([]string, 0, len(identifierSet))
		for item := range identifierSet {
			if strings.TrimSpace(item) != "" {
				identifiers = append(identifiers, item)
			}
		}
		if len(identifiers) > 0 {
			rEdges := tx.Where("project_id = ? AND (src_id IN ? OR dst_id IN ?)", body.ProjectID, identifiers, identifiers).Delete(&db.AssetEdge{})
			if rEdges.Error != nil {
				return rEdges.Error
			}
			deletedDeps["edges"] += rEdges.RowsAffected
		}
		if len(domains) > 0 {
			rCandidates := tx.Where("project_id = ? AND domain IN ?", body.ProjectID, domains).Delete(&db.AssetCandidate{})
			if rCandidates.Error != nil {
				return rCandidates.Error
			}
			deletedDeps["candidates"] += rCandidates.RowsAffected
		}

		rAssets := tx.Where("id IN ? AND project_id = ?", body.IDs, body.ProjectID).Delete(&db.Asset{})
		if rAssets.Error != nil {
			return rAssets.Error
		}
		deletedAssets = rAssets.RowsAffected
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeAudit(body.ProjectID, actorFromRequest(r), "bulk_delete_assets", "asset", "", map[string]interface{}{
		"count": deletedAssets, "ids": body.IDs, "cascade": deletedDeps,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"deleted": deletedAssets,
		"cascade": deletedDeps,
	})
}

func (s *Server) handleBulkDeleteVulns(w http.ResponseWriter, r *http.Request) {
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

	deletedVulns := int64(0)
	deletedEvents := int64(0)
	err := s.db.DB.Transaction(func(tx *gorm.DB) error {
		rEvents := tx.Where("project_id = ? AND vuln_id IN ?", body.ProjectID, body.IDs).Delete(&db.VulnEvent{})
		if rEvents.Error != nil {
			return rEvents.Error
		}
		deletedEvents = rEvents.RowsAffected

		rVulns := tx.Where("project_id = ? AND id IN ?", body.ProjectID, body.IDs).Delete(&db.Vulnerability{})
		if rVulns.Error != nil {
			return rVulns.Error
		}
		deletedVulns = rVulns.RowsAffected
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.writeAudit(body.ProjectID, actorFromRequest(r), "bulk_delete_vulns", "vulnerability", "", map[string]interface{}{
		"count":         deletedVulns,
		"deletedEvents": deletedEvents,
		"ids":           body.IDs,
	}, r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"deleted":       deletedVulns,
		"deletedEvents": deletedEvents,
	})
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
	} else {
		updates["fixed_at"] = nil
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

// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
// Global Search
// 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

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

func (s *Server) isProjectAIEnabled(projectID string) (bool, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return true, nil
	}
	var project db.Project
	if err := s.db.DB.Select("id", "archived", "ai_enabled").Where("id = ?", projectID).First(&project).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, gorm.ErrRecordNotFound
		}
		return false, err
	}
	if project.Archived {
		return false, nil
	}
	return project.AIEnabled, nil
}
