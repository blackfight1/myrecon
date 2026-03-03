package db

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database wraps gorm DB.
type Database struct {
	DB *gorm.DB
}

// NewDatabase creates database connection.
func NewDatabase(dsn string) (*Database, error) {
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	if err := database.AutoMigrate(&Asset{}, &Port{}, &Vulnerability{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}

	return &Database{DB: database}, nil
}

// SaveOrUpdateAsset saves or updates asset info.
func (d *Database) SaveOrUpdateAsset(data map[string]interface{}) error {
	domain, ok := data["domain"].(string)
	if !ok || domain == "" {
		return fmt.Errorf("domain is required")
	}

	var techJSON []byte
	if technologies, exists := data["technologies"]; exists {
		if techSlice, ok := technologies.([]string); ok && len(techSlice) > 0 {
			techJSON, _ = json.Marshal(techSlice)
		} else {
			techJSON, _ = json.Marshal([]string{})
		}
	} else {
		techJSON, _ = json.Marshal([]string{})
	}

	var existingAsset Asset
	result := d.DB.Where("domain = ?", domain).First(&existingAsset)
	now := time.Now()

	if result.Error == gorm.ErrRecordNotFound {
		asset := Asset{
			Domain:       domain,
			URL:          getStringValue(data, "url"),
			IP:           getStringValue(data, "ip"),
			StatusCode:   getIntValue(data, "status_code"),
			Title:        getStringValue(data, "title"),
			Technologies: techJSON,
			LastSeen:     now,
		}
		if err := d.DB.Create(&asset).Error; err != nil {
			return fmt.Errorf("failed to create asset: %v", err)
		}
	} else if result.Error == nil {
		updates := map[string]interface{}{"last_seen": now}
		if url := getStringValue(data, "url"); url != "" {
			updates["url"] = url
		}
		if ip := getStringValue(data, "ip"); ip != "" {
			updates["ip"] = ip
		}
		if statusCode := getIntValue(data, "status_code"); statusCode > 0 {
			updates["status_code"] = statusCode
		}
		if title := getStringValue(data, "title"); title != "" {
			updates["title"] = title
		}
		if len(techJSON) > 2 {
			updates["technologies"] = techJSON
		}

		if err := d.DB.Model(&existingAsset).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update asset: %v", err)
		}
	} else {
		return fmt.Errorf("database query error: %v", result.Error)
	}

	return nil
}

// GetAssetCount returns total asset count.
func (d *Database) GetAssetCount() (int64, error) {
	var count int64
	if err := d.DB.Model(&Asset{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetRecentAssets returns assets created after given time.
func (d *Database) GetRecentAssets(since time.Time) ([]Asset, error) {
	var assets []Asset
	if err := d.DB.Where("created_at > ?", since).Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// SaveOrUpdatePort saves or updates port info.
func (d *Database) SaveOrUpdatePort(data map[string]interface{}) error {
	ip := getStringValue(data, "ip")
	port := getIntValue(data, "port")
	domain := getStringValue(data, "domain")

	if ip == "" || port == 0 {
		return fmt.Errorf("ip and port are required")
	}

	var asset Asset
	if domain != "" {
		result := d.DB.Where("domain = ?", domain).First(&asset)
		if result.Error == gorm.ErrRecordNotFound {
			asset = Asset{Domain: domain, IP: ip, LastSeen: time.Now()}
			if err := d.DB.Create(&asset).Error; err != nil {
				return fmt.Errorf("failed to create asset: %v", err)
			}
		} else if result.Error != nil {
			return fmt.Errorf("database query error: %v", result.Error)
		}
	} else {
		result := d.DB.Where("ip = ?", ip).First(&asset)
		if result.Error == gorm.ErrRecordNotFound {
			asset = Asset{Domain: ip, IP: ip, LastSeen: time.Now()}
			if err := d.DB.Create(&asset).Error; err != nil {
				return fmt.Errorf("failed to create asset: %v", err)
			}
		} else if result.Error != nil {
			return fmt.Errorf("database query error: %v", result.Error)
		}
	}

	var existingPort Port
	result := d.DB.Where("asset_id = ? AND ip = ? AND port = ?", asset.ID, ip, port).First(&existingPort)
	now := time.Now()

	if result.Error == gorm.ErrRecordNotFound {
		portRecord := Port{
			AssetID:  asset.ID,
			Domain:   domain,
			IP:       ip,
			Port:     port,
			Protocol: getStringValue(data, "protocol"),
			Service:  getStringValue(data, "service"),
			Version:  getStringValue(data, "version"),
			Banner:   getStringValue(data, "banner"),
			LastSeen: now,
		}
		if portRecord.Protocol == "" {
			portRecord.Protocol = "tcp"
		}
		if err := d.DB.Create(&portRecord).Error; err != nil {
			return fmt.Errorf("failed to create port: %v", err)
		}
	} else if result.Error == nil {
		updates := map[string]interface{}{"last_seen": now}
		if service := getStringValue(data, "service"); service != "" {
			updates["service"] = service
		}
		if version := getStringValue(data, "version"); version != "" {
			updates["version"] = version
		}
		if banner := getStringValue(data, "banner"); banner != "" {
			updates["banner"] = banner
		}
		if err := d.DB.Model(&existingPort).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update port: %v", err)
		}
	} else {
		return fmt.Errorf("database query error: %v", result.Error)
	}

	return nil
}

// SaveOrUpdateVulnerability saves or updates vulnerability finding by fingerprint.
func (d *Database) SaveOrUpdateVulnerability(data map[string]interface{}) error {
	templateID := getStringValue(data, "template_id")
	matchedAt := getStringValue(data, "matched_at")
	if templateID == "" || matchedAt == "" {
		return fmt.Errorf("template_id and matched_at are required")
	}

	domain := getStringValue(data, "domain")
	host := getStringValue(data, "host")
	fingerprint := getStringValue(data, "fingerprint")
	if fingerprint == "" {
		raw := templateID + "|" + matchedAt + "|" + host
		sum := sha1.Sum([]byte(raw))
		fingerprint = hex.EncodeToString(sum[:])
	}

	now := time.Now()

	var asset *Asset
	if domain != "" {
		var a Asset
		result := d.DB.Where("domain = ?", domain).First(&a)
		if result.Error == nil {
			asset = &a
		}
	}

	var rawJSON []byte
	if raw := getStringValue(data, "raw"); raw != "" {
		rawJSON = []byte(raw)
	} else {
		rawJSON, _ = json.Marshal(data)
	}

	var existing Vulnerability
	result := d.DB.Where("fingerprint = ?", fingerprint).First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		record := Vulnerability{
			Domain:       domain,
			Host:         host,
			URL:          getStringValue(data, "url"),
			IP:           getStringValue(data, "ip"),
			TemplateID:   templateID,
			TemplateName: getStringValue(data, "template_name"),
			Severity:     getStringValue(data, "severity"),
			CVE:          getStringValue(data, "cve"),
			MatcherName:  getStringValue(data, "matcher_name"),
			Description:  getStringValue(data, "description"),
			Reference:    getStringValue(data, "reference"),
			TemplateURL:  getStringValue(data, "template_url"),
			MatchedAt:    matchedAt,
			Fingerprint:  fingerprint,
			Raw:          rawJSON,
			LastSeen:     now,
		}
		if asset != nil {
			record.AssetID = &asset.ID
		}
		if record.URL == "" {
			record.URL = matchedAt
		}

		if err := d.DB.Create(&record).Error; err != nil {
			return fmt.Errorf("failed to create vulnerability: %v", err)
		}
	} else if result.Error == nil {
		updates := map[string]interface{}{
			"last_seen":     now,
			"severity":      getStringValue(data, "severity"),
			"template_name": getStringValue(data, "template_name"),
			"cve":           getStringValue(data, "cve"),
			"matcher_name":  getStringValue(data, "matcher_name"),
			"description":   getStringValue(data, "description"),
			"reference":     getStringValue(data, "reference"),
			"template_url":  getStringValue(data, "template_url"),
			"raw":           rawJSON,
		}
		if url := getStringValue(data, "url"); url != "" {
			updates["url"] = url
		}
		if ip := getStringValue(data, "ip"); ip != "" {
			updates["ip"] = ip
		}
		if domain != "" {
			updates["domain"] = domain
		}
		if host != "" {
			updates["host"] = host
		}
		if asset != nil {
			updates["asset_id"] = asset.ID
		}

		if err := d.DB.Model(&existing).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update vulnerability: %v", err)
		}
	} else {
		return fmt.Errorf("database query error: %v", result.Error)
	}

	return nil
}

// GetPortCount returns total port count.
func (d *Database) GetPortCount() (int64, error) {
	var count int64
	if err := d.DB.Model(&Port{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetVulnerabilityCount returns total vulnerability count.
func (d *Database) GetVulnerabilityCount() (int64, error) {
	var count int64
	if err := d.DB.Model(&Vulnerability{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetRecentPorts returns ports created after given time.
func (d *Database) GetRecentPorts(since time.Time) ([]Port, error) {
	var ports []Port
	if err := d.DB.Where("created_at > ?", since).Find(&ports).Error; err != nil {
		return nil, err
	}
	return ports, nil
}

// GetAssetByDomain returns asset by domain.
func (d *Database) GetAssetByDomain(domain string) (*Asset, error) {
	var asset Asset
	if err := d.DB.Where("domain = ?", domain).First(&asset).Error; err != nil {
		return nil, err
	}
	return &asset, nil
}

func getStringValue(data map[string]interface{}, key string) string {
	if value, exists := data[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

func getIntValue(data map[string]interface{}, key string) int {
	if value, exists := data[key]; exists {
		if intVal, ok := value.(int); ok {
			return intVal
		}
		if floatVal, ok := value.(float64); ok {
			return int(floatVal)
		}
	}
	return 0
}
