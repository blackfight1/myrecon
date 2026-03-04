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
	Domain       string         `gorm:"uniqueIndex;not null" json:"domain"`
	URL          string         `json:"url"`
	IP           string         `json:"ip"`
	StatusCode   int            `json:"status_code"`
	Title        string         `json:"title"`
	Technologies JSONB          `gorm:"type:jsonb" json:"technologies"`
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
	ID        uint           `gorm:"primarykey" json:"id"`
	AssetID   uint           `gorm:"index;not null" json:"asset_id"`
	Domain    string         `gorm:"index" json:"domain"`
	IP        string         `gorm:"not null" json:"ip"`
	Port      int            `gorm:"not null" json:"port"`
	Protocol  string         `gorm:"default:tcp" json:"protocol"`
	Service   string         `json:"service"`
	Version   string         `json:"version"`
	Banner    string         `json:"banner"`
	LastSeen  time.Time      `json:"last_seen"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (Port) TableName() string {
	return "ports"
}

// Vulnerability vulnerability finding model.
type Vulnerability struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	AssetID      *uint          `gorm:"index" json:"asset_id"`
	Domain       string         `gorm:"index" json:"domain"`
	Host         string         `gorm:"index" json:"host"`
	URL          string         `gorm:"type:text" json:"url"`
	IP           string         `json:"ip"`
	TemplateID   string         `gorm:"index;not null" json:"template_id"`
	TemplateName string         `json:"template_name"`
	Severity     string         `gorm:"index" json:"severity"`
	CVE          string         `gorm:"index" json:"cve"`
	MatcherName  string         `json:"matcher_name"`
	Description  string         `gorm:"type:text" json:"description"`
	Reference    string         `gorm:"type:text" json:"reference"`
	TemplateURL  string         `json:"template_url"`
	MatchedAt    string         `gorm:"type:text;not null" json:"matched_at"`
	Fingerprint  string         `gorm:"uniqueIndex;not null" json:"fingerprint"`
	Raw          JSONB          `gorm:"type:jsonb" json:"raw"`
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName table name.
func (Vulnerability) TableName() string {
	return "vulnerabilities"
}

// MonitorRun stores one monitoring execution record.
type MonitorRun struct {
	ID            uint           `gorm:"primarykey" json:"id"`
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

// MonitorTarget stores monitor target baseline state.
type MonitorTarget struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	RootDomain   string         `gorm:"uniqueIndex;not null" json:"root_domain"`
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

// MonitorTask stores scheduled monitor jobs.
type MonitorTask struct {
	ID          uint           `gorm:"primarykey" json:"id"`
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
