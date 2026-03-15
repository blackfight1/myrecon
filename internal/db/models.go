package db

import (
	"database/sql/driver"
	"errors"
	"time"

	"gorm.io/gorm"
)

// JSONB custom JSONB type.
type JSONB []byte

// Value implements driver.Valuer.
func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

// Scan implements sql.Scanner.
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("failed to scan JSONB value")
	}

	*j = bytes
	return nil
}

// Asset asset model.
type Asset struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProjectID    string         `gorm:"index:idx_assets_project_domain,unique;not null;default:'default'" json:"project_id"`
	RootDomain   string         `gorm:"index" json:"root_domain"`
	Domain       string         `gorm:"index:idx_assets_project_domain,unique;not null" json:"domain"`
	URL          string         `json:"url"`
	IP           string         `json:"ip"`
	StatusCode   int            `json:"status_code"`
	Title        string         `json:"title"`
	Technologies JSONB          `gorm:"type:jsonb" json:"technologies"`
	SourceJobID  string         `gorm:"index" json:"source_job_id"`
	SourceModule string         `gorm:"index" json:"source_module"`
	FirstSeenAt  time.Time      `json:"first_seen_at"`
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	Ports        []Port         `gorm:"foreignKey:AssetID" json:"ports"`
}

// TableName table name.
func (Asset) TableName() string {
	return "assets"
}

// Port port model.
type Port struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProjectID    string         `gorm:"index:idx_ports_project_ip_port_proto_domain,priority:1;not null;default:'default'" json:"project_id"`
	RootDomain   string         `gorm:"index" json:"root_domain"`
	AssetID      uint           `gorm:"index;not null" json:"asset_id"`
	Domain       string         `gorm:"index:idx_ports_project_ip_port_proto_domain,priority:5" json:"domain"`
	IP           string         `gorm:"index:idx_ports_project_ip_port_proto_domain,priority:2;not null" json:"ip"`
	Port         int            `gorm:"index:idx_ports_project_ip_port_proto_domain,priority:3;not null" json:"port"`
	Protocol     string         `gorm:"index:idx_ports_project_ip_port_proto_domain,priority:4;default:tcp" json:"protocol"`
	Service      string         `json:"service"`
	Version      string         `json:"version"`
	Banner       string         `json:"banner"`
	SourceJobID  string         `gorm:"index" json:"source_job_id"`
	SourceModule string         `gorm:"index" json:"source_module"`
	FirstSeenAt  time.Time      `json:"first_seen_at"`
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (Port) TableName() string {
	return "ports"
}

// Vulnerability vulnerability finding model.
type Vulnerability struct {
	ID               uint           `gorm:"primarykey" json:"id"`
	ProjectID        string         `gorm:"index:idx_vulns_project_fingerprint,priority:1;index;not null;default:'default'" json:"project_id"`
	AssetID          *uint          `gorm:"index" json:"asset_id"`
	RootDomain       string         `gorm:"index" json:"root_domain"`
	Domain           string         `gorm:"index" json:"domain"`
	Host             string         `gorm:"index" json:"host"`
	URL              string         `gorm:"type:text" json:"url"`
	IP               string         `json:"ip"`
	TemplateID       string         `gorm:"index;not null" json:"template_id"`
	TemplateName     string         `json:"template_name"`
	Severity         string         `gorm:"index" json:"severity"`
	CVE              string         `gorm:"index" json:"cve"`
	MatcherName      string         `json:"matcher_name"`
	Description      string         `gorm:"type:text" json:"description"`
	Reference        string         `gorm:"type:text" json:"reference"`
	TemplateURL      string         `json:"template_url"`
	MatchedAt        string         `gorm:"type:text;not null" json:"matched_at"`
	Fingerprint      string         `gorm:"index:idx_vulns_project_fingerprint,priority:2,unique;not null" json:"fingerprint"`
	Status           string         `gorm:"index;not null;default:open" json:"status"`
	Assignee         string         `gorm:"index" json:"assignee"`
	TicketRef        string         `gorm:"index" json:"ticket_ref"`
	DueAt            *time.Time     `json:"due_at"`
	VerifiedAt       *time.Time     `json:"verified_at"`
	FixedAt          *time.Time     `json:"fixed_at"`
	ReopenCount      int            `json:"reopen_count"`
	LastTransitionAt *time.Time     `json:"last_transition_at"`
	SourceJobID      string         `gorm:"index" json:"source_job_id"`
	Raw              JSONB          `gorm:"type:jsonb" json:"raw"`
	FirstSeenAt      time.Time      `json:"first_seen_at"`
	LastSeen         time.Time      `json:"last_seen"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (Vulnerability) TableName() string {
	return "vulnerabilities"
}

// MonitorRun stores one monitoring execution record.
type MonitorRun struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	ProjectID     string         `gorm:"index" json:"project_id"`
	RootDomain    string         `gorm:"index;not null" json:"root_domain"`
	Status        string         `gorm:"index;not null" json:"status"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    *time.Time     `json:"finished_at"`
	DurationSec   int            `json:"duration_sec"`
	ErrorMessage  string         `gorm:"type:text" json:"error_message"`
	NewLiveCount  int            `json:"new_live_count"`
	WebChanged    int            `json:"web_changed_count"`
	PortOpened    int            `json:"port_opened_count"`
	PortClosed    int            `json:"port_closed_count"`
	ServiceChange int            `json:"service_changed_count"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (MonitorRun) TableName() string {
	return "monitor_runs"
}

// AssetChange stores live subdomain/web fingerprint changes.
type AssetChange struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProjectID    string         `gorm:"index" json:"project_id"`
	RunID        uint           `gorm:"index;not null" json:"run_id"`
	RootDomain   string         `gorm:"index;not null" json:"root_domain"`
	ChangeType   string         `gorm:"index;not null" json:"change_type"`
	Domain       string         `gorm:"index;not null" json:"domain"`
	URL          string         `gorm:"type:text" json:"url"`
	StatusCode   int            `json:"status_code"`
	Title        string         `gorm:"type:text" json:"title"`
	Technologies JSONB          `gorm:"type:jsonb" json:"technologies"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (AssetChange) TableName() string {
	return "asset_changes"
}

// PortChange stores port delta events.
type PortChange struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	ProjectID  string         `gorm:"index" json:"project_id"`
	RunID      uint           `gorm:"index;not null" json:"run_id"`
	RootDomain string         `gorm:"index;not null" json:"root_domain"`
	ChangeType string         `gorm:"index;not null" json:"change_type"`
	Domain     string         `gorm:"index" json:"domain"`
	IP         string         `gorm:"index;not null" json:"ip"`
	Port       int            `gorm:"index;not null" json:"port"`
	Protocol   string         `json:"protocol"`
	Service    string         `json:"service"`
	Version    string         `json:"version"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (PortChange) TableName() string {
	return "port_changes"
}

// MonitorEvent stores lifecycle of monitor findings.
type MonitorEvent struct {
	ID              uint           `gorm:"primarykey" json:"id"`
	ProjectID       string         `gorm:"index:idx_monitor_event_project_key,unique,priority:1;index;not null;default:'default'" json:"project_id"`
	RootDomain      string         `gorm:"index;not null" json:"root_domain"`
	EventKey        string         `gorm:"type:text;index:idx_monitor_event_project_key,unique,priority:2;not null" json:"event_key"`
	EventType       string         `gorm:"index;not null" json:"event_type"` // new_live / port_opened / ...
	Status          string         `gorm:"index;not null;default:open" json:"status"`
	Domain          string         `gorm:"index" json:"domain"`
	URL             string         `gorm:"type:text" json:"url"`
	IP              string         `gorm:"index" json:"ip"`
	Port            int            `gorm:"index" json:"port"`
	Protocol        string         `json:"protocol"`
	Service         string         `json:"service"`
	Version         string         `json:"version"`
	Title           string         `gorm:"type:text" json:"title"`
	StatusCode      int            `json:"status_code"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	LastChangedAt   time.Time      `json:"last_changed_at"`
	ResolvedAt      *time.Time     `json:"resolved_at"`
	OccurrenceCount int            `json:"occurrence_count"`
	LastRunID       uint           `gorm:"index" json:"last_run_id"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

func (MonitorEvent) TableName() string {
	return "monitor_events"
}

// MonitorTarget stores monitor target baseline state.
type MonitorTarget struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProjectID    string         `gorm:"index:idx_monitor_target_project_root,unique;not null;default:'default'" json:"project_id"`
	Owner        string         `gorm:"index" json:"owner"`
	RootDomain   string         `gorm:"index:idx_monitor_target_project_root,unique;not null" json:"root_domain"`
	Enabled      bool           `gorm:"default:true;index" json:"enabled"`
	BaselineDone bool           `gorm:"default:false" json:"baseline_done"`
	LastRunAt    *time.Time     `json:"last_run_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (MonitorTarget) TableName() string {
	return "monitor_targets"
}

// ScanJob stores scan task state persistently.
type ScanJob struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	JobID        string         `gorm:"uniqueIndex;not null" json:"job_id"` // e.g. "scan-1234567890"
	ProjectID    string         `gorm:"index;not null;default:'default'" json:"project_id"`
	RootDomain   string         `gorm:"index;not null" json:"root_domain"`
	Mode         string         `gorm:"not null" json:"mode"`         // scan or monitor
	Modules      string         `gorm:"type:text" json:"modules"`     // comma-separated
	Status       string         `gorm:"index;not null" json:"status"` // pending/running/success/failed/canceled
	EnableNuclei bool           `json:"enable_nuclei"`
	ActiveSubs   bool           `json:"active_subs"`
	DictSize     int            `json:"dict_size"`
	DNSResolvers string         `gorm:"type:text" json:"dns_resolvers"`
	DryRun       bool           `json:"dry_run"`
	ErrorMessage string         `gorm:"type:text" json:"error_message"`
	DurationSec  int            `json:"duration_sec"`
	SubdomainCnt int            `json:"subdomain_cnt"`
	PortCnt      int            `json:"port_cnt"`
	VulnCnt      int            `json:"vuln_cnt"`
	StartedAt    *time.Time     `json:"started_at"`
	FinishedAt   *time.Time     `json:"finished_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (ScanJob) TableName() string {
	return "scan_jobs"
}

// MonitorTask stores scheduled monitor jobs.
type MonitorTask struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	ProjectID   string         `gorm:"index;not null;default:'default'" json:"project_id"`
	RootDomain  string         `gorm:"index;not null" json:"root_domain"`
	Status      string         `gorm:"index;not null" json:"status"` // pending/running/success/failed/canceled
	RunAt       time.Time      `gorm:"index;not null" json:"run_at"`
	IntervalSec int            `gorm:"not null" json:"interval_sec"`
	Attempt     int            `gorm:"not null;default:0" json:"attempt"`
	MaxAttempts int            `gorm:"not null;default:3" json:"max_attempts"`
	LastError   string         `gorm:"type:text" json:"last_error"`
	StartedAt   *time.Time     `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (MonitorTask) TableName() string {
	return "monitor_tasks"
}

// Project stores project metadata and ownership.
type Project struct {
	ID          string         `gorm:"primaryKey;size:64" json:"id"`
	Name        string         `gorm:"index;not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	Owner       string         `gorm:"index" json:"owner"`
	Tags        JSONB          `gorm:"type:jsonb" json:"tags"`
	Archived    bool           `gorm:"index;default:false" json:"archived"`
	LastScanAt  *time.Time     `json:"last_scan_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Scopes      []ProjectScope `gorm:"foreignKey:ProjectID" json:"scopes"`
}

func (Project) TableName() string {
	return "projects"
}

// ProjectScope stores root-domain scope entries for projects.
type ProjectScope struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	ProjectID  string         `gorm:"index:idx_project_scope_project_domain,unique;not null" json:"project_id"`
	RootDomain string         `gorm:"index:idx_project_scope_project_domain,unique;not null" json:"root_domain"`
	Enabled    bool           `gorm:"index;default:true" json:"enabled"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

func (ProjectScope) TableName() string {
	return "project_scopes"
}

// VulnEvent stores vulnerability lifecycle transitions.
type VulnEvent struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	ProjectID  string         `gorm:"index;not null" json:"project_id"`
	VulnID     uint           `gorm:"index;not null" json:"vuln_id"`
	Action     string         `gorm:"index;not null" json:"action"`
	FromStatus string         `gorm:"index" json:"from_status"`
	ToStatus   string         `gorm:"index" json:"to_status"`
	Actor      string         `gorm:"index" json:"actor"`
	Reason     string         `gorm:"type:text" json:"reason"`
	Meta       JSONB          `gorm:"type:jsonb" json:"meta"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

func (VulnEvent) TableName() string {
	return "vuln_events"
}

// AssetEdge stores asset relationship edges for analysis.
type AssetEdge struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	ProjectID  string         `gorm:"index;not null" json:"project_id"`
	RootDomain string         `gorm:"index" json:"root_domain"`
	SrcType    string         `gorm:"index;not null" json:"src_type"`
	SrcID      string         `gorm:"index;not null" json:"src_id"`
	DstType    string         `gorm:"index;not null" json:"dst_type"`
	DstID      string         `gorm:"index;not null" json:"dst_id"`
	Relation   string         `gorm:"index;not null" json:"relation"`
	Confidence int            `json:"confidence"`
	Evidence   string         `gorm:"type:text" json:"evidence"`
	JobID      string         `gorm:"index" json:"job_id"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

func (AssetEdge) TableName() string {
	return "asset_edges"
}

// ScanStage stores stage execution status for each scan job.
type ScanStage struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	ProjectID   string         `gorm:"index;not null" json:"project_id"`
	JobID       string         `gorm:"index;not null" json:"job_id"`
	Stage       string         `gorm:"index;not null" json:"stage"`
	Module      string         `gorm:"index" json:"module"`
	Status      string         `gorm:"index;not null" json:"status"`
	InputCount  int            `json:"input_count"`
	OutputCount int            `json:"output_count"`
	Error       string         `gorm:"type:text" json:"error"`
	StartedAt   *time.Time     `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (ScanStage) TableName() string {
	return "scan_stages"
}

// ScanArtifact stores references to generated raw outputs.
type ScanArtifact struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	ProjectID    string         `gorm:"index;not null" json:"project_id"`
	JobID        string         `gorm:"index;not null" json:"job_id"`
	Stage        string         `gorm:"index" json:"stage"`
	Module       string         `gorm:"index" json:"module"`
	ArtifactType string         `gorm:"index;not null" json:"artifact_type"`
	Path         string         `gorm:"type:text" json:"path"`
	SHA256       string         `gorm:"index" json:"sha256"`
	Size         int64          `json:"size"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

func (ScanArtifact) TableName() string {
	return "scan_artifacts"
}

// AuditLog stores critical system actions for traceability.
type AuditLog struct {
	ID         uint           `gorm:"primarykey" json:"id"`
	ProjectID  string         `gorm:"index" json:"project_id"`
	Actor      string         `gorm:"index;not null" json:"actor"`
	Action     string         `gorm:"index;not null" json:"action"`
	TargetType string         `gorm:"index" json:"target_type"`
	TargetID   string         `gorm:"index" json:"target_id"`
	IP         string         `json:"ip"`
	UserAgent  string         `gorm:"type:text" json:"user_agent"`
	Detail     string         `gorm:"type:text" json:"detail"`
	Meta       JSONB          `gorm:"type:jsonb" json:"meta"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
