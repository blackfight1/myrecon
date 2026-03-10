package db

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

	if err := database.AutoMigrate(&Asset{}, &Port{}, &Vulnerability{}, &MonitorRun{}, &AssetChange{}, &PortChange{}, &MonitorTarget{}, &MonitorTask{}); err != nil {
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

// CreateMonitorRun creates a new monitor run record.
func (d *Database) CreateMonitorRun(rootDomain string) (*MonitorRun, error) {
	run := &MonitorRun{
		RootDomain: rootDomain,
		Status:     "running",
		StartedAt:  time.Now(),
	}
	if err := d.DB.Create(run).Error; err != nil {
		return nil, err
	}
	return run, nil
}

// CompleteMonitorRun marks a monitor run as completed.
func (d *Database) CompleteMonitorRun(runID uint, status string, errMsg string, newLive, webChanged, opened, closed, svcChanged int) error {
	finished := time.Now()
	durationSec := 0
	var run MonitorRun
	if err := d.DB.First(&run, runID).Error; err == nil {
		durationSec = int(finished.Sub(run.StartedAt).Seconds())
	}

	updates := map[string]interface{}{
		"status":         status,
		"finished_at":    finished,
		"duration_sec":   durationSec,
		"error_message":  errMsg,
		"new_live_count": newLive,
		"web_changed":    webChanged,
		"port_opened":    opened,
		"port_closed":    closed,
		"service_change": svcChanged,
	}
	return d.DB.Model(&MonitorRun{}).Where("id = ?", runID).Updates(updates).Error
}

// GetLiveAssetsByRootDomain returns live web assets by root domain.
func (d *Database) GetLiveAssetsByRootDomain(rootDomain string) ([]Asset, error) {
	var assets []Asset
	pattern := "%." + rootDomain
	if err := d.DB.
		Where("(domain = ? OR domain LIKE ?) AND url <> ''", rootDomain, pattern).
		Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// GetPortsByRootDomain returns ports by root domain.
func (d *Database) GetPortsByRootDomain(rootDomain string) ([]Port, error) {
	var ports []Port
	pattern := "%." + rootDomain
	if err := d.DB.
		Where("domain = ? OR domain LIKE ?", rootDomain, pattern).
		Find(&ports).Error; err != nil {
		return nil, err
	}
	return ports, nil
}

// SaveAssetChange saves a web asset change event.
func (d *Database) SaveAssetChange(change *AssetChange) error {
	return d.DB.Create(change).Error
}

// SavePortChange saves a port change event.
func (d *Database) SavePortChange(change *PortChange) error {
	return d.DB.Create(change).Error
}

// GetOrCreateMonitorTarget returns monitor target record for root domain.
func (d *Database) GetOrCreateMonitorTarget(rootDomain string) (*MonitorTarget, error) {
	var target MonitorTarget
	result := d.DB.Where("root_domain = ?", rootDomain).First(&target)
	if result.Error == gorm.ErrRecordNotFound {
		target = MonitorTarget{
			RootDomain:   rootDomain,
			Enabled:      true,
			BaselineDone: false,
		}
		if err := d.DB.Create(&target).Error; err != nil {
			return nil, err
		}
		return &target, nil
	}
	if result.Error != nil {
		return nil, result.Error
	}
	return &target, nil
}

// UpdateMonitorTarget updates baseline and last run time.
func (d *Database) UpdateMonitorTarget(rootDomain string, baselineDone bool, lastRunAt time.Time) error {
	updates := map[string]interface{}{
		"baseline_done": baselineDone,
		"last_run_at":   lastRunAt,
	}
	return d.DB.Model(&MonitorTarget{}).Where("root_domain = ?", rootDomain).Updates(updates).Error
}

// ListMonitorTargets returns all monitor targets.
func (d *Database) ListMonitorTargets() ([]MonitorTarget, error) {
	var targets []MonitorTarget
	if err := d.DB.Order("root_domain asc").Find(&targets).Error; err != nil {
		return nil, err
	}
	return targets, nil
}

// StopMonitorTarget disables monitoring for the given root domain.
func (d *Database) StopMonitorTarget(rootDomain string) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&MonitorTarget{}).
			Where("root_domain = ?", rootDomain).
			Update("enabled", false)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("monitor target not found: %s", rootDomain)
		}

		now := time.Now()
		if err := tx.Model(&MonitorTask{}).
			Where("root_domain = ? AND status IN ?", rootDomain, []string{"pending", "running"}).
			Updates(map[string]interface{}{
				"status":      "canceled",
				"finished_at": now,
			}).Error; err != nil {
			return err
		}
		return nil
	})
}

// DeleteMonitorDataByRootDomain removes monitor-only data for a root domain.
func (d *Database) DeleteMonitorDataByRootDomain(rootDomain string) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&PortChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&AssetChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorRun{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorTarget{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// EnableMonitorTarget enables monitor target and ensures one pending task exists.
func (d *Database) EnableMonitorTarget(rootDomain string, intervalSec, maxAttempts int) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var target MonitorTarget
		result := tx.Where("root_domain = ?", rootDomain).First(&target)
		if result.Error == gorm.ErrRecordNotFound {
			target = MonitorTarget{
				RootDomain:   rootDomain,
				Enabled:      true,
				BaselineDone: false,
			}
			if err := tx.Create(&target).Error; err != nil {
				return err
			}
		} else if result.Error != nil {
			return result.Error
		} else {
			if err := tx.Model(&target).Updates(map[string]interface{}{
				"enabled": true,
			}).Error; err != nil {
				return err
			}
		}

		var count int64
		if err := tx.Model(&MonitorTask{}).
			Where("root_domain = ? AND status IN ?", rootDomain, []string{"pending", "running"}).
			Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			task := MonitorTask{
				RootDomain:  rootDomain,
				Status:      "pending",
				RunAt:       time.Now(),
				IntervalSec: intervalSec,
				MaxAttempts: maxAttempts,
				Attempt:     0,
			}
			if err := tx.Create(&task).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ClaimDueMonitorTask atomically claims one due pending task.
func (d *Database) ClaimDueMonitorTask() (*MonitorTask, error) {
	var claimed *MonitorTask
	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var task MonitorTask
		now := time.Now()
		result := tx.Model(&MonitorTask{}).
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Joins("JOIN monitor_targets mt ON mt.root_domain = monitor_tasks.root_domain").
			Where("monitor_tasks.status = ? AND monitor_tasks.run_at <= ? AND mt.enabled = ?", "pending", now, true).
			Order("monitor_tasks.run_at asc").
			First(&task)
		if result.Error == gorm.ErrRecordNotFound {
			return nil
		}
		if result.Error != nil {
			return result.Error
		}

		if err := tx.Model(&MonitorTask{}).
			Where("id = ?", task.ID).
			Updates(map[string]interface{}{
				"status":     "running",
				"started_at": now,
			}).Error; err != nil {
			return err
		}
		task.Status = "running"
		task.StartedAt = &now
		claimed = &task
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

// CompleteMonitorTaskSuccess marks task success and enqueues next cycle task.
func (d *Database) CompleteMonitorTaskSuccess(taskID uint) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var task MonitorTask
		if err := tx.First(&task, taskID).Error; err != nil {
			return err
		}
		now := time.Now()
		if err := tx.Model(&task).Updates(map[string]interface{}{
			"status":      "success",
			"finished_at": now,
			"last_error":  "",
		}).Error; err != nil {
			return err
		}

		var target MonitorTarget
		if err := tx.Where("root_domain = ?", task.RootDomain).First(&target).Error; err == nil {
			if !target.Enabled {
				return nil
			}
		}

		next := MonitorTask{
			RootDomain:  task.RootDomain,
			Status:      "pending",
			RunAt:       now.Add(time.Duration(task.IntervalSec) * time.Second),
			IntervalSec: task.IntervalSec,
			MaxAttempts: task.MaxAttempts,
			Attempt:     0,
		}
		return tx.Create(&next).Error
	})
}

// HandleMonitorTaskFailure retries with backoff or marks failed and schedules next cycle.
func (d *Database) HandleMonitorTaskFailure(task *MonitorTask, errMsg string) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now()
		nextAttempt := task.Attempt + 1
		if nextAttempt < task.MaxAttempts {
			backoffSec := calcBackoffSec(nextAttempt)
			return tx.Model(&MonitorTask{}).Where("id = ?", task.ID).Updates(map[string]interface{}{
				"status":      "pending",
				"attempt":     nextAttempt,
				"run_at":      now.Add(time.Duration(backoffSec) * time.Second),
				"last_error":  errMsg,
				"started_at":  nil,
				"finished_at": nil,
			}).Error
		}

		if err := tx.Model(&MonitorTask{}).Where("id = ?", task.ID).Updates(map[string]interface{}{
			"status":      "failed",
			"finished_at": now,
			"last_error":  errMsg,
		}).Error; err != nil {
			return err
		}

		var target MonitorTarget
		if err := tx.Where("root_domain = ?", task.RootDomain).First(&target).Error; err == nil {
			if !target.Enabled {
				return nil
			}
		}

		next := MonitorTask{
			RootDomain:  task.RootDomain,
			Status:      "pending",
			RunAt:       now.Add(time.Duration(task.IntervalSec) * time.Second),
			IntervalSec: task.IntervalSec,
			MaxAttempts: task.MaxAttempts,
			Attempt:     0,
		}
		return tx.Create(&next).Error
	})
}

// RecoverStaleRunningTasks reclaims monitor tasks stuck in running state.
// Stale tasks are treated as failures and follow the same retry/backoff policy.
func (d *Database) RecoverStaleRunningTasks(staleAfter time.Duration) (int, error) {
	if staleAfter <= 0 {
		staleAfter = 2 * time.Hour
	}
	cutoff := time.Now().Add(-staleAfter)

	var staleTasks []MonitorTask
	if err := d.DB.
		Joins("JOIN monitor_targets mt ON mt.root_domain = monitor_tasks.root_domain").
		Where("monitor_tasks.status = ? AND monitor_tasks.started_at IS NOT NULL AND monitor_tasks.started_at <= ? AND mt.enabled = ?", "running", cutoff, true).
		Find(&staleTasks).Error; err != nil {
		return 0, err
	}
	if len(staleTasks) == 0 {
		return 0, nil
	}

	recovered := 0
	for i := range staleTasks {
		task := staleTasks[i]
		startedAt := "unknown"
		if task.StartedAt != nil {
			startedAt = task.StartedAt.Format(time.RFC3339)
		}
		errMsg := fmt.Sprintf("stale running task recovered (started_at=%s)", startedAt)
		if err := d.HandleMonitorTaskFailure(&task, errMsg); err != nil {
			return recovered, err
		}
		recovered++
	}

	return recovered, nil
}

func calcBackoffSec(attempt int) int {
	steps := []int{30, 120, 600}
	if attempt <= 0 {
		return steps[0]
	}
	idx := attempt - 1
	if idx >= len(steps) {
		return steps[len(steps)-1]
	}
	return steps[idx]
}

// HasRecentChangeRun reports whether there is a successful monitor run with
// non-zero changes for the same root domain in the given time window.
func (d *Database) HasRecentChangeRun(rootDomain string, excludeRunID uint, since time.Time) (bool, error) {
	query := d.DB.Model(&MonitorRun{}).
		Where("root_domain = ? AND status = ? AND finished_at IS NOT NULL AND finished_at >= ?", rootDomain, "success", since).
		Where("(new_live_count > 0 OR web_changed > 0 OR port_opened > 0 OR port_closed > 0 OR service_change > 0)")
	if excludeRunID > 0 {
		query = query.Where("id <> ?", excludeRunID)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetPreviousPortCloseState returns the close state for a specific port in the
// previous successful monitor run: "", "closed_pending", or "closed".
func (d *Database) GetPreviousPortCloseState(rootDomain string, currentRunID uint, ip string, port int) (string, error) {
	var prevRun MonitorRun
	q := d.DB.Where("root_domain = ? AND status = ?", rootDomain, "success")
	if currentRunID > 0 {
		q = q.Where("id < ?", currentRunID)
	}
	if err := q.Order("id desc").First(&prevRun).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil
		}
		return "", err
	}

	var pc PortChange
	err := d.DB.
		Where("run_id = ? AND ip = ? AND port = ? AND change_type IN ?", prevRun.ID, ip, port, []string{"closed_pending", "closed"}).
		Order("id desc").
		First(&pc).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return "", nil
		}
		return "", err
	}
	return pc.ChangeType, nil
}

// ListAssetDomains returns distinct domains from assets table.
func (d *Database) ListAssetDomains() ([]string, error) {
	var domains []string
	if err := d.DB.Model(&Asset{}).
		Distinct("domain").
		Where("domain <> ''").
		Order("domain asc").
		Pluck("domain", &domains).Error; err != nil {
		return nil, err
	}
	return domains, nil
}

// DeleteAllDataByRootDomain removes all related scan/monitor data for a root domain.
func (d *Database) DeleteAllDataByRootDomain(rootDomain string) error {
	pattern := "%." + rootDomain
	return d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		if err := tx.Where("domain = ? OR domain LIKE ? OR host = ? OR host LIKE ?", rootDomain, pattern, rootDomain, pattern).
			Delete(&Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Where("domain = ? OR domain LIKE ?", rootDomain, pattern).
			Delete(&Port{}).Error; err != nil {
			return err
		}
		if err := tx.Where("domain = ? OR domain LIKE ?", rootDomain, pattern).
			Delete(&Asset{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&PortChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&AssetChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorRun{}).Error; err != nil {
			return err
		}
		if err := tx.Where("root_domain = ?", rootDomain).Delete(&MonitorTarget{}).Error; err != nil {
			return err
		}
		return nil
	})
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
