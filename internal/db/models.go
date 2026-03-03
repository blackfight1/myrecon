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
