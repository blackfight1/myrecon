package db

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"hunter/internal/common"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// Database wraps gorm DB.
type Database struct {
	DB *gorm.DB
}

var (
	ErrJobActive         = errors.New("job is running or pending")
	ErrMonitorTaskActive = errors.New("monitor task is running or pending")
)

const (
	defaultMonitorVulnMaxURLs     = 50
	defaultMonitorVulnCooldownMin = 30
	defaultMonitorIntervalSec     = 6 * 3600
	maxMonitorVulnMaxURLs         = 1000
	maxMonitorVulnCooldownMin     = 24 * 60
	projectScopedSchemaLockClass  = 913451
	projectScopedSchemaLockObject = 20260322
)

type MonitorTargetOptions struct {
	MonitorPorts      *bool
	EnableVulnScan    *bool
	EnableNuclei      *bool
	EnableCors        *bool
	EnableSubtakeover *bool
	VulnOnNewLive     *bool
	VulnOnWebChanged  *bool
	VulnMaxURLs       *int
	VulnCooldownMin   *int
}

// NewDatabase creates database connection.
func NewDatabase(dsn string) (*Database, error) {
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	if err := database.AutoMigrate(
		&Project{}, &ProjectScope{},
		&Asset{}, &AssetCandidate{}, &Port{}, &Vulnerability{}, &VulnEvent{},
		&MonitorRun{}, &AssetChange{}, &PortChange{}, &MonitorEvent{}, &MonitorSnapshot{}, &MonitorTarget{}, &MonitorTask{},
		&ScanJob{}, &ScanStage{}, &ScanArtifact{}, &JobLog{}, &AssetEdge{}, &AuditLog{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}
	if err := ensureProjectScopedSchema(database); err != nil {
		return nil, fmt.Errorf("failed to ensure project scoped schema: %v", err)
	}

	return &Database{DB: database}, nil
}

func ensureProjectScopedSchema(database *gorm.DB) error {
	return database.Transaction(func(tx *gorm.DB) error {
		// Serialize the project-scoped schema fixups across API/worker startup
		// processes to avoid concurrent DDL/DML deadlocks during bootstrap.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?, ?)", projectScopedSchemaLockClass, projectScopedSchemaLockObject).Error; err != nil {
			return err
		}

		backfillStatements := []string{
			"UPDATE assets SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE asset_candidates SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE ports SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE vulnerabilities SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE monitor_targets SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE monitor_targets SET interval_sec = 21600 WHERE interval_sec IS NULL OR interval_sec <= 0",
			"UPDATE monitor_targets SET monitor_ports = TRUE WHERE monitor_ports IS NULL",
			"UPDATE monitor_tasks SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE monitor_runs SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE monitor_events SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE monitor_snapshots SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE scan_jobs SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE scan_stages SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE scan_artifacts SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE job_logs SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE project_scopes SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE asset_changes SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE port_changes SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE asset_edges SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE vuln_events SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
			"UPDATE audit_logs SET project_id = 'default' WHERE project_id IS NULL OR BTRIM(project_id) = ''",
		}
		for _, stmt := range backfillStatements {
			if err := tx.Exec(stmt).Error; err != nil {
				return err
			}
		}

		// Drop old single-column unique constraints that block multi-project duplicates.
		dropStatements := []string{
			"ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_domain_key",
			"DROP INDEX IF EXISTS idx_assets_domain",
			"ALTER TABLE vulnerabilities DROP CONSTRAINT IF EXISTS vulnerabilities_fingerprint_key",
			"DROP INDEX IF EXISTS idx_vulnerabilities_fingerprint",
			"ALTER TABLE monitor_targets DROP CONSTRAINT IF EXISTS monitor_targets_root_domain_key",
			"DROP INDEX IF EXISTS idx_monitor_targets_root_domain",
		}
		for _, stmt := range dropStatements {
			if err := tx.Exec(stmt).Error; err != nil {
				return err
			}
		}

		createStatements := []string{
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_project_domain ON assets (project_id, domain)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_candidates_project_domain ON asset_candidates (project_id, domain)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_project_fingerprint ON vulnerabilities (project_id, fingerprint)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_target_project_root ON monitor_targets (project_id, root_domain)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_event_project_key ON monitor_events (project_id, event_key)",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_monitor_snapshot_project_root_run ON monitor_snapshots (project_id, root_domain, run_id)",
			"CREATE INDEX IF NOT EXISTS idx_job_logs_project_job_id ON job_logs (project_id, job_id, id)",
		}
		for _, stmt := range createStatements {
			if err := tx.Exec(stmt).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// SaveOrUpdateAsset saves or updates asset info.
func (d *Database) SaveOrUpdateAsset(data map[string]interface{}) error {
	domain, ok := data["domain"].(string)
	if !ok || domain == "" {
		return fmt.Errorf("domain is required")
	}
	projectID := strings.TrimSpace(getStringValue(data, "project_id"))
	if projectID == "" {
		projectID = "default"
	}
	rootDomain := strings.TrimSpace(getStringValue(data, "root_domain"))
	sourceJobID := strings.TrimSpace(getStringValue(data, "source_job_id"))
	sourceModule := strings.TrimSpace(getStringValue(data, "source_module"))

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
	result := d.DB.Where("project_id = ? AND domain = ?", projectID, domain).First(&existingAsset)
	now := time.Now()

	if result.Error == gorm.ErrRecordNotFound {
		asset := Asset{
			ProjectID:    projectID,
			RootDomain:   rootDomain,
			Domain:       domain,
			URL:          getStringValue(data, "url"),
			IP:           getStringValue(data, "ip"),
			StatusCode:   getIntValue(data, "status_code"),
			Title:        getStringValue(data, "title"),
			Technologies: techJSON,
			SourceJobID:  sourceJobID,
			SourceModule: sourceModule,
			FirstSeenAt:  now,
			LastSeen:     now,
		}
		if err := d.DB.Create(&asset).Error; err != nil {
			return fmt.Errorf("failed to create asset: %v", err)
		}
	} else if result.Error == nil {
		updates := map[string]interface{}{"last_seen": now}
		if rootDomain != "" {
			updates["root_domain"] = rootDomain
		}
		if sourceJobID != "" {
			updates["source_job_id"] = sourceJobID
		}
		if sourceModule != "" {
			updates["source_module"] = sourceModule
		}
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

// SaveOrUpdateAssetCandidate saves or updates candidate pool entries.
func (d *Database) SaveOrUpdateAssetCandidate(data map[string]interface{}) error {
	domain := strings.ToLower(strings.TrimSpace(getStringValue(data, "domain")))
	if domain == "" {
		return fmt.Errorf("domain is required")
	}

	projectID := strings.TrimSpace(getStringValue(data, "project_id"))
	if projectID == "" {
		projectID = "default"
	}
	rootDomain := strings.TrimSpace(getStringValue(data, "root_domain"))
	sourceJobID := strings.TrimSpace(getStringValue(data, "source_job_id"))
	sourceModule := strings.TrimSpace(getStringValue(data, "source_module"))

	lastIP := strings.TrimSpace(getStringValue(data, "last_ip"))
	if lastIP == "" {
		lastIP = strings.TrimSpace(getStringValue(data, "ip"))
	}
	lastURL := strings.TrimSpace(getStringValue(data, "last_url"))
	if lastURL == "" {
		lastURL = strings.TrimSpace(getStringValue(data, "url"))
	}
	lastStatusCode := getIntValue(data, "last_status_code")
	if lastStatusCode <= 0 {
		lastStatusCode = getIntValue(data, "status_code")
	}
	lastTitle := strings.TrimSpace(getStringValue(data, "last_title"))
	if lastTitle == "" {
		lastTitle = strings.TrimSpace(getStringValue(data, "title"))
	}

	verifyStatus := strings.ToLower(strings.TrimSpace(getStringValue(data, "verify_status")))
	verificationMethod := strings.TrimSpace(getStringValue(data, "verification_method"))
	if verifyStatus == "" {
		if v, ok := data["verified"]; ok {
			switch vv := v.(type) {
			case bool:
				if vv {
					verifyStatus = "verified"
				}
			case string:
				switch strings.ToLower(strings.TrimSpace(vv)) {
				case "1", "true", "yes", "on", "verified":
					verifyStatus = "verified"
				}
			}
		}
	}
	if verifyStatus != "verified" {
		verifyStatus = "pending"
	}

	now := time.Now()
	var existing AssetCandidate
	result := d.DB.Where("project_id = ? AND domain = ?", projectID, domain).First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		candidate := AssetCandidate{
			ProjectID:          projectID,
			RootDomain:         rootDomain,
			Domain:             domain,
			LastIP:             lastIP,
			LastURL:            lastURL,
			LastStatusCode:     lastStatusCode,
			LastTitle:          lastTitle,
			VerifyStatus:       verifyStatus,
			VerificationMethod: verificationMethod,
			SourceJobID:        sourceJobID,
			SourceModule:       sourceModule,
			FirstSeenAt:        now,
			LastSeen:           now,
		}
		if verifyStatus == "verified" {
			candidate.VerifiedAt = &now
		}
		if err := d.DB.Create(&candidate).Error; err != nil {
			return fmt.Errorf("failed to create asset candidate: %v", err)
		}
		return nil
	}
	if result.Error != nil {
		return fmt.Errorf("database query error: %v", result.Error)
	}

	updates := map[string]interface{}{
		"last_seen": now,
	}
	if rootDomain != "" {
		updates["root_domain"] = rootDomain
	}
	if sourceJobID != "" {
		updates["source_job_id"] = sourceJobID
	}
	if sourceModule != "" {
		updates["source_module"] = sourceModule
	}
	if lastIP != "" {
		updates["last_ip"] = lastIP
	}
	if lastURL != "" {
		updates["last_url"] = lastURL
	}
	if lastStatusCode > 0 {
		updates["last_status_code"] = lastStatusCode
	}
	if lastTitle != "" {
		updates["last_title"] = lastTitle
	}

	// Do not downgrade verified records back to pending.
	if verifyStatus == "verified" {
		updates["verify_status"] = "verified"
		if verificationMethod != "" {
			updates["verification_method"] = verificationMethod
		}
		if existing.VerifiedAt == nil {
			updates["verified_at"] = now
		}
	}

	if err := d.DB.Model(&existing).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update asset candidate: %v", err)
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
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(getStringValue(data, "domain")), "."))
	if domain == "" {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(getStringValue(data, "host")), "."))
	}
	protocol := defaultProtocol(getStringValue(data, "protocol"))
	projectID := strings.TrimSpace(getStringValue(data, "project_id"))
	if projectID == "" {
		projectID = "default"
	}
	rootDomain := strings.TrimSpace(getStringValue(data, "root_domain"))
	sourceJobID := strings.TrimSpace(getStringValue(data, "source_job_id"))
	sourceModule := strings.TrimSpace(getStringValue(data, "source_module"))

	if ip == "" || port == 0 {
		return fmt.Errorf("ip and port are required")
	}

	var asset Asset
	if domain != "" {
		result := d.DB.Where("project_id = ? AND domain = ?", projectID, domain).First(&asset)
		if result.Error == gorm.ErrRecordNotFound {
			asset = Asset{
				ProjectID:    projectID,
				RootDomain:   rootDomain,
				Domain:       domain,
				IP:           ip,
				SourceJobID:  sourceJobID,
				SourceModule: sourceModule,
				FirstSeenAt:  time.Now(),
				LastSeen:     time.Now(),
			}
			if err := d.DB.Create(&asset).Error; err != nil {
				return fmt.Errorf("failed to create asset: %v", err)
			}
		} else if result.Error != nil {
			return fmt.Errorf("database query error: %v", result.Error)
		}
	} else {
		result := d.DB.Where("project_id = ? AND ip = ?", projectID, ip).First(&asset)
		if result.Error == gorm.ErrRecordNotFound {
			asset = Asset{
				ProjectID:    projectID,
				RootDomain:   rootDomain,
				Domain:       ip,
				IP:           ip,
				SourceJobID:  sourceJobID,
				SourceModule: sourceModule,
				FirstSeenAt:  time.Now(),
				LastSeen:     time.Now(),
			}
			if err := d.DB.Create(&asset).Error; err != nil {
				return fmt.Errorf("failed to create asset: %v", err)
			}
		} else if result.Error != nil {
			return fmt.Errorf("database query error: %v", result.Error)
		}
	}

	var existingPort Port
	result := d.DB.Where("project_id = ? AND ip = ? AND port = ? AND protocol = ? AND domain = ?", projectID, ip, port, protocol, domain).First(&existingPort)
	// Backward-compat merge path:
	// old records might exist with empty domain from naabu "open_port",
	// then nmap "port_service" arrives with a domain and should enrich same row.
	if result.Error == gorm.ErrRecordNotFound && domain != "" {
		fallback := d.DB.Where("project_id = ? AND ip = ? AND port = ? AND protocol = ? AND COALESCE(domain, '') = ''", projectID, ip, port, protocol).First(&existingPort)
		if fallback.Error == nil {
			result = fallback
		}
	}
	now := time.Now()

	if result.Error == gorm.ErrRecordNotFound {
		portRecord := Port{
			ProjectID:    projectID,
			RootDomain:   rootDomain,
			AssetID:      asset.ID,
			Domain:       domain,
			IP:           ip,
			Port:         port,
			Protocol:     protocol,
			Service:      getStringValue(data, "service"),
			Version:      getStringValue(data, "version"),
			Banner:       getStringValue(data, "banner"),
			SourceJobID:  sourceJobID,
			SourceModule: sourceModule,
			FirstSeenAt:  now,
			LastSeen:     now,
		}
		if err := d.DB.Create(&portRecord).Error; err != nil {
			return fmt.Errorf("failed to create port: %v", err)
		}
	} else if result.Error == nil {
		updates := map[string]interface{}{"last_seen": now}
		if existingPort.AssetID != asset.ID {
			updates["asset_id"] = asset.ID
		}
		if domain != "" && strings.TrimSpace(existingPort.Domain) == "" {
			updates["domain"] = domain
		}
		if rootDomain != "" {
			updates["root_domain"] = rootDomain
		}
		if sourceJobID != "" {
			updates["source_job_id"] = sourceJobID
		}
		if sourceModule != "" {
			updates["source_module"] = sourceModule
		}
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
	projectID := strings.TrimSpace(getStringValue(data, "project_id"))
	if projectID == "" {
		projectID = "default"
	}
	sourceJobID := strings.TrimSpace(getStringValue(data, "source_job_id"))

	domain := getStringValue(data, "domain")
	host := getStringValue(data, "host")
	rootDomain := buildRootDomain(
		getStringValue(data, "root_domain"),
		domain,
		host,
		getStringValue(data, "url"),
		matchedAt,
	)
	fingerprint := getStringValue(data, "fingerprint")
	if fingerprint == "" {
		raw := projectID + "|" + templateID + "|" + matchedAt + "|" + host
		sum := sha1.Sum([]byte(raw))
		fingerprint = hex.EncodeToString(sum[:])
	}

	now := time.Now()

	var asset *Asset
	if domain != "" {
		var a Asset
		result := d.DB.Where("project_id = ? AND domain = ?", projectID, domain).First(&a)
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
	result := d.DB.Where("project_id = ? AND fingerprint = ?", projectID, fingerprint).First(&existing)

	if result.Error == gorm.ErrRecordNotFound {
		transitionAt := now
		record := Vulnerability{
			ProjectID:        projectID,
			RootDomain:       rootDomain,
			Domain:           domain,
			Host:             host,
			URL:              getStringValue(data, "url"),
			IP:               getStringValue(data, "ip"),
			TemplateID:       templateID,
			TemplateName:     getStringValue(data, "template_name"),
			Severity:         getStringValue(data, "severity"),
			CVE:              getStringValue(data, "cve"),
			MatcherName:      getStringValue(data, "matcher_name"),
			Description:      getStringValue(data, "description"),
			Reference:        getStringValue(data, "reference"),
			TemplateURL:      getStringValue(data, "template_url"),
			MatchedAt:        matchedAt,
			Fingerprint:      fingerprint,
			Status:           "open",
			SourceJobID:      sourceJobID,
			Raw:              rawJSON,
			FirstSeenAt:      now,
			LastSeen:         now,
			LastTransitionAt: &transitionAt,
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
		if rootDomain != "" {
			updates["root_domain"] = rootDomain
		}
		if sourceJobID != "" {
			updates["source_job_id"] = sourceJobID
		}
		if asset != nil {
			updates["asset_id"] = asset.ID
		}
		if existing.Status == "fixed" {
			transitionAt := now
			updates["status"] = "open"
			updates["reopen_count"] = existing.ReopenCount + 1
			updates["last_transition_at"] = &transitionAt
			updates["fixed_at"] = nil
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
func (d *Database) CreateMonitorRun(projectID, rootDomain string) (*MonitorRun, error) {
	if projectID == "" {
		projectID = "default"
	}
	run := &MonitorRun{
		ProjectID:  projectID,
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

// SaveMonitorSnapshot creates or updates one monitor snapshot for a run.
func (d *Database) SaveMonitorSnapshot(snapshot *MonitorSnapshot) error {
	if snapshot == nil {
		return fmt.Errorf("snapshot is nil")
	}
	if strings.TrimSpace(snapshot.ProjectID) == "" {
		snapshot.ProjectID = "default"
	}
	if strings.TrimSpace(snapshot.RootDomain) == "" {
		return fmt.Errorf("rootDomain is required")
	}
	if snapshot.RunID == 0 {
		return fmt.Errorf("runID is required")
	}
	return d.DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "project_id"},
			{Name: "root_domain"},
			{Name: "run_id"},
		},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"asset_count":      snapshot.AssetCount,
			"port_count":       snapshot.PortCount,
			"open_event_count": snapshot.OpenEventCount,
			"summary":          snapshot.Summary,
			"updated_at":       time.Now(),
		}),
	}).Create(snapshot).Error
}

// GetLiveAssetsByRootDomain returns live web assets by root domain.
func (d *Database) GetLiveAssetsByRootDomain(projectID, rootDomain string) ([]Asset, error) {
	var assets []Asset
	pattern := "%." + rootDomain
	if err := d.DB.
		Where("project_id = ? AND (domain = ? OR domain LIKE ?) AND url <> ''", projectID, rootDomain, pattern).
		Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// GetPortsByRootDomain returns ports by root domain.
func (d *Database) GetPortsByRootDomain(projectID, rootDomain string) ([]Port, error) {
	var ports []Port
	pattern := "%." + rootDomain
	if err := d.DB.
		Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
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
func (d *Database) GetOrCreateMonitorTarget(projectID, rootDomain string) (*MonitorTarget, error) {
	if projectID == "" {
		projectID = "default"
	}
	var target MonitorTarget
	result := d.DB.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).First(&target)
	if result.Error == gorm.ErrRecordNotFound {
		target = MonitorTarget{
			ProjectID:         projectID,
			RootDomain:        rootDomain,
			Enabled:           true,
			MonitorPorts:      true,
			EnableVulnScan:    false,
			EnableNuclei:      false,
			EnableCors:        false,
			EnableSubtakeover: false,
			VulnOnNewLive:     true,
			VulnOnWebChanged:  false,
			VulnMaxURLs:       defaultMonitorVulnMaxURLs,
			VulnCooldownMin:   defaultMonitorVulnCooldownMin,
			BaselineDone:      false,
		}
		if err := d.DB.Create(&target).Error; err != nil {
			return nil, err
		}
		return &target, nil
	}
	if result.Error != nil {
		return nil, result.Error
	}
	updates := monitorTargetDefaultUpdates(&target)
	if len(updates) > 0 {
		if err := d.DB.Model(&target).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	return &target, nil
}

// UpdateMonitorTarget updates baseline and last run time.
// Deprecated: prefer UpdateMonitorTargetAfterRun for versioned baselines.
func (d *Database) UpdateMonitorTarget(projectID, rootDomain string, baselineDone bool, lastRunAt time.Time) error {
	updates := map[string]interface{}{
		"baseline_done": baselineDone,
		"last_run_at":   lastRunAt,
	}
	return d.DB.Model(&MonitorTarget{}).Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Updates(updates).Error
}

// UpdateMonitorTargetAfterRun marks run completion and optionally establishes a new baseline version.
func (d *Database) UpdateMonitorTargetAfterRun(projectID, rootDomain string, lastRunAt time.Time, establishBaseline bool) error {
	updates := map[string]interface{}{
		"baseline_done": true,
		"last_run_at":   lastRunAt,
	}
	if establishBaseline {
		updates["baseline_at"] = lastRunAt
		updates["baseline_version"] = gorm.Expr("COALESCE(baseline_version, 0) + 1")
	}
	return d.DB.Model(&MonitorTarget{}).Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Updates(updates).Error
}

// ListMonitorTargets returns all monitor targets.
func (d *Database) ListMonitorTargets(projectID string) ([]MonitorTarget, error) {
	var targets []MonitorTarget
	query := d.DB.Order("root_domain asc")
	if projectID != "" {
		query = query.Where("project_id = ?", projectID)
	}
	if err := query.Find(&targets).Error; err != nil {
		return nil, err
	}
	return targets, nil
}

// StopMonitorTarget disables monitoring for the given root domain.
func (d *Database) StopMonitorTarget(projectID, rootDomain string) error {
	projectID = strings.TrimSpace(projectID)
	rootDomain = strings.TrimSpace(rootDomain)
	if projectID == "" {
		return fmt.Errorf("projectID is required")
	}
	if rootDomain == "" {
		return fmt.Errorf("rootDomain is required")
	}
	return d.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&MonitorTarget{}).
			Where("project_id = ? AND root_domain = ?", projectID, rootDomain).
			Update("enabled", false)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("monitor target not found: %s", rootDomain)
		}

		now := time.Now()
		if err := tx.Model(&MonitorTask{}).
			Where("project_id = ? AND root_domain = ? AND status IN ?", projectID, rootDomain, []string{"pending", "running"}).
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
func (d *Database) DeleteMonitorDataByRootDomain(projectID, rootDomain string) error {
	projectID = strings.TrimSpace(projectID)
	rootDomain = strings.TrimSpace(rootDomain)
	if projectID == "" {
		return fmt.Errorf("projectID is required")
	}
	if rootDomain == "" {
		return fmt.Errorf("rootDomain is required")
	}
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var taskIDs []uint
		if err := tx.Model(&MonitorTask{}).
			Where("project_id = ? AND root_domain = ?", projectID, rootDomain).
			Pluck("id", &taskIDs).Error; err != nil {
			return err
		}
		if len(taskIDs) > 0 {
			jobIDs := make([]string, 0, len(taskIDs))
			for _, id := range taskIDs {
				jobIDs = append(jobIDs, fmt.Sprintf("task-%d", id))
			}
			if err := tx.Where("project_id = ? AND job_id IN ?", projectID, jobIDs).Delete(&JobLog{}).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&PortChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&AssetChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorEvent{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorSnapshot{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorRun{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorTarget{}).Error; err != nil {
			return err
		}
		return nil
	})
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
		return defaultMonitorVulnCooldownMin
	}
	if n > maxMonitorVulnCooldownMin {
		return maxMonitorVulnCooldownMin
	}
	return n
}

func monitorTargetDefaultUpdates(target *MonitorTarget) map[string]interface{} {
	if target == nil {
		return nil
	}
	updates := make(map[string]interface{}, 2)
	if target.VulnMaxURLs <= 0 {
		updates["vuln_max_urls"] = defaultMonitorVulnMaxURLs
	}
	if target.VulnCooldownMin <= 0 {
		updates["vuln_cooldown_min"] = defaultMonitorVulnCooldownMin
	}
	return updates
}

func applyMonitorTargetOptionsToStruct(target *MonitorTarget, opts *MonitorTargetOptions) {
	if target == nil || opts == nil {
		return
	}
	if opts.MonitorPorts != nil {
		target.MonitorPorts = *opts.MonitorPorts
	}
	if opts.EnableVulnScan != nil {
		target.EnableVulnScan = *opts.EnableVulnScan
	}
	if opts.EnableNuclei != nil {
		target.EnableNuclei = *opts.EnableNuclei
	}
	if opts.EnableCors != nil {
		target.EnableCors = *opts.EnableCors
	}
	if opts.EnableSubtakeover != nil {
		target.EnableSubtakeover = *opts.EnableSubtakeover
	}
	if opts.VulnOnNewLive != nil {
		target.VulnOnNewLive = *opts.VulnOnNewLive
	}
	if opts.VulnOnWebChanged != nil {
		target.VulnOnWebChanged = *opts.VulnOnWebChanged
	}
	if opts.VulnMaxURLs != nil {
		target.VulnMaxURLs = clampMonitorVulnMaxURLs(*opts.VulnMaxURLs)
	}
	if opts.VulnCooldownMin != nil {
		target.VulnCooldownMin = clampMonitorVulnCooldownMin(*opts.VulnCooldownMin)
	}
}

func monitorTargetOptionUpdates(opts *MonitorTargetOptions) map[string]interface{} {
	if opts == nil {
		return nil
	}
	updates := make(map[string]interface{}, 9)
	if opts.MonitorPorts != nil {
		updates["monitor_ports"] = *opts.MonitorPorts
	}
	if opts.EnableVulnScan != nil {
		updates["enable_vuln_scan"] = *opts.EnableVulnScan
	}
	if opts.EnableNuclei != nil {
		updates["enable_nuclei"] = *opts.EnableNuclei
	}
	if opts.EnableCors != nil {
		updates["enable_cors"] = *opts.EnableCors
	}
	if opts.EnableSubtakeover != nil {
		updates["enable_subtakeover"] = *opts.EnableSubtakeover
	}
	if opts.VulnOnNewLive != nil {
		updates["vuln_on_new_live"] = *opts.VulnOnNewLive
	}
	if opts.VulnOnWebChanged != nil {
		updates["vuln_on_web_changed"] = *opts.VulnOnWebChanged
	}
	if opts.VulnMaxURLs != nil {
		updates["vuln_max_urls"] = clampMonitorVulnMaxURLs(*opts.VulnMaxURLs)
	}
	if opts.VulnCooldownMin != nil {
		updates["vuln_cooldown_min"] = clampMonitorVulnCooldownMin(*opts.VulnCooldownMin)
	}
	return updates
}

// EnableMonitorTarget enables monitor target and ensures one pending task exists.
// It returns the task ID of the pending/running monitor task for this target.
func (d *Database) EnableMonitorTarget(projectID, rootDomain string, intervalSec, maxAttempts int, opts *MonitorTargetOptions) (uint, error) {
	projectID = strings.TrimSpace(projectID)
	rootDomain = strings.TrimSpace(rootDomain)
	if projectID == "" {
		return 0, fmt.Errorf("projectID is required")
	}
	if rootDomain == "" {
		return 0, fmt.Errorf("rootDomain is required")
	}
	var ensuredTaskID uint
	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var target MonitorTarget
		effectiveInterval := intervalSec
		if effectiveInterval <= 0 {
			effectiveInterval = defaultMonitorIntervalSec
		}
		result := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).First(&target)
		if result.Error == gorm.ErrRecordNotFound {
			target = MonitorTarget{
				ProjectID:         projectID,
				RootDomain:        rootDomain,
				Enabled:           true,
				IntervalSec:       effectiveInterval,
				MonitorPorts:      true,
				EnableVulnScan:    false,
				EnableNuclei:      false,
				EnableCors:        false,
				EnableSubtakeover: false,
				VulnOnNewLive:     true,
				VulnOnWebChanged:  false,
				VulnMaxURLs:       defaultMonitorVulnMaxURLs,
				VulnCooldownMin:   defaultMonitorVulnCooldownMin,
				BaselineDone:      false,
			}
			applyMonitorTargetOptionsToStruct(&target, opts)
			if err := tx.Create(&target).Error; err != nil {
				return err
			}
		} else if result.Error != nil {
			return result.Error
		} else {
			if target.IntervalSec > 0 && intervalSec <= 0 {
				effectiveInterval = target.IntervalSec
			}
			updates := map[string]interface{}{
				"enabled":      true,
				"interval_sec": effectiveInterval,
			}
			for k, v := range monitorTargetDefaultUpdates(&target) {
				updates[k] = v
			}
			for k, v := range monitorTargetOptionUpdates(opts) {
				updates[k] = v
			}
			if err := tx.Model(&target).Updates(updates).Error; err != nil {
				return err
			}
			target.IntervalSec = effectiveInterval
		}
		if opts != nil && opts.MonitorPorts != nil && !*opts.MonitorPorts {
			if err := resolveOpenPortMonitorEventsTx(tx, projectID, rootDomain); err != nil {
				return err
			}
		}

		var task MonitorTask
		err := tx.Model(&MonitorTask{}).
			Where("project_id = ? AND root_domain = ? AND status IN ?", projectID, rootDomain, []string{"pending", "running"}).
			Order("run_at asc, id asc").
			First(&task).Error
		if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}
		if err == gorm.ErrRecordNotFound {
			task := MonitorTask{
				ProjectID:   projectID,
				RootDomain:  rootDomain,
				Status:      "pending",
				RunAt:       time.Now(),
				IntervalSec: effectiveInterval,
				MaxAttempts: maxAttempts,
				Attempt:     0,
			}
			if err := tx.Create(&task).Error; err != nil {
				return err
			}
			ensuredTaskID = task.ID
		} else {
			taskUpdates := map[string]interface{}{}
			if task.IntervalSec != effectiveInterval {
				taskUpdates["interval_sec"] = effectiveInterval
			}
			if maxAttempts > 0 && task.MaxAttempts != maxAttempts {
				taskUpdates["max_attempts"] = maxAttempts
			}
			if len(taskUpdates) > 0 {
				if err := tx.Model(&task).Updates(taskUpdates).Error; err != nil {
					return err
				}
			}
			ensuredTaskID = task.ID
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return ensuredTaskID, nil
}

// UpdateMonitorTargetOptions updates monitor target policy without changing
// scheduling state (enabled/disabled) or creating tasks.
func (d *Database) UpdateMonitorTargetOptions(projectID, rootDomain string, opts *MonitorTargetOptions) error {
	projectID = strings.TrimSpace(projectID)
	rootDomain = strings.TrimSpace(rootDomain)
	if projectID == "" {
		return fmt.Errorf("projectID is required")
	}
	if rootDomain == "" {
		return fmt.Errorf("rootDomain is required")
	}
	if opts == nil {
		return nil
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		var target MonitorTarget
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).First(&target).Error; err != nil {
			return err
		}

		updates := monitorTargetDefaultUpdates(&target)
		for k, v := range monitorTargetOptionUpdates(opts) {
			updates[k] = v
		}
		if len(updates) == 0 {
			return nil
		}
		if err := tx.Model(&target).Updates(updates).Error; err != nil {
			return err
		}
		if opts.MonitorPorts != nil && !*opts.MonitorPorts {
			if err := resolveOpenPortMonitorEventsTx(tx, projectID, rootDomain); err != nil {
				return err
			}
		}
		return nil
	})
}

func resolveOpenPortMonitorEventsTx(tx *gorm.DB, projectID, rootDomain string) error {
	now := time.Now()
	return tx.Model(&MonitorEvent{}).
		Where("project_id = ? AND root_domain = ? AND event_type = ? AND status = ?", projectID, rootDomain, "port_opened", "open").
		Updates(map[string]interface{}{
			"status":          "resolved",
			"resolved_at":     now,
			"last_changed_at": now,
		}).Error
}

func (d *Database) UpdateMonitorTargetLastVulnScan(projectID, rootDomain string, at time.Time) error {
	projectID = strings.TrimSpace(projectID)
	rootDomain = strings.TrimSpace(rootDomain)
	if projectID == "" || rootDomain == "" {
		return nil
	}
	return d.DB.Model(&MonitorTarget{}).
		Where("project_id = ? AND root_domain = ?", projectID, rootDomain).
		Update("last_vuln_scan_at", at).Error
}

// ArchiveProject marks project archived and stops related monitor scheduling.
func (d *Database) ArchiveProject(projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return fmt.Errorf("projectID is required")
	}
	return d.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Project{}).Where("id = ?", projectID).Update("archived", true).Error; err != nil {
			return err
		}
		if err := tx.Model(&MonitorTarget{}).Where("project_id = ?", projectID).Update("enabled", false).Error; err != nil {
			return err
		}
		now := time.Now()
		if err := tx.Model(&MonitorTask{}).
			Where("project_id = ? AND status IN ?", projectID, []string{"pending", "running"}).
			Updates(map[string]interface{}{
				"status":      "canceled",
				"finished_at": now,
			}).Error; err != nil {
			return err
		}
		return nil
	})
}

// DeleteProjectAndData permanently removes one project and all project-scoped data.
func (d *Database) DeleteProjectAndData(projectID string) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return fmt.Errorf("projectID is required")
	}
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var existing Project
		if err := tx.Where("id = ?", projectID).First(&existing).Error; err != nil {
			return err
		}

		// Delete child tables first, then project metadata.
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&VulnEvent{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&JobLog{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&ScanArtifact{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&ScanStage{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&ScanJob{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&PortChange{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&AssetChange{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&MonitorEvent{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&MonitorSnapshot{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&MonitorRun{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&MonitorTarget{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&AssetEdge{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&Port{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&AssetCandidate{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&Asset{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&ProjectScope{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("project_id = ?", projectID).Delete(&AuditLog{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("id = ?", projectID).Delete(&Project{}).Error; err != nil {
			return err
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
			Joins("JOIN monitor_targets mt ON mt.root_domain = monitor_tasks.root_domain AND mt.project_id = monitor_tasks.project_id AND mt.deleted_at IS NULL").
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
		if err := tx.Where("project_id = ? AND root_domain = ?", task.ProjectID, task.RootDomain).First(&target).Error; err == nil {
			if !target.Enabled {
				return nil
			}
		}

		next := MonitorTask{
			ProjectID:   task.ProjectID,
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
		if err := tx.Where("project_id = ? AND root_domain = ?", task.ProjectID, task.RootDomain).First(&target).Error; err == nil {
			if !target.Enabled {
				return nil
			}
		}

		next := MonitorTask{
			ProjectID:   task.ProjectID,
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
		Joins("JOIN monitor_targets mt ON mt.root_domain = monitor_tasks.root_domain AND mt.project_id = monitor_tasks.project_id AND mt.deleted_at IS NULL").
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
func (d *Database) HasRecentChangeRun(projectID, rootDomain string, excludeRunID uint, since time.Time) (bool, error) {
	if projectID == "" {
		projectID = "default"
	}
	query := d.DB.Model(&MonitorRun{}).
		Where("project_id = ? AND root_domain = ? AND status = ? AND finished_at IS NOT NULL AND finished_at >= ?", projectID, rootDomain, "success", since).
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
func (d *Database) GetPreviousPortCloseState(projectID, rootDomain string, currentRunID uint, ip string, port int) (string, error) {
	if projectID == "" {
		projectID = "default"
	}
	var prevRun MonitorRun
	q := d.DB.Where("project_id = ? AND root_domain = ? AND status = ?", projectID, rootDomain, "success")
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

// ListAssetDomains returns distinct domains from both verified and candidate pools.
func (d *Database) ListAssetDomains(projectID string) ([]string, error) {
	var verified []string
	query := d.DB.Model(&Asset{}).Distinct("domain").Where("domain <> ''")
	if strings.TrimSpace(projectID) != "" {
		query = query.Where("project_id = ?", strings.TrimSpace(projectID))
	}
	if err := query.Order("domain asc").Pluck("domain", &verified).Error; err != nil {
		return nil, err
	}
	var candidates []string
	cq := d.DB.Model(&AssetCandidate{}).Distinct("domain").Where("domain <> ''")
	if strings.TrimSpace(projectID) != "" {
		cq = cq.Where("project_id = ?", strings.TrimSpace(projectID))
	}
	if err := cq.Order("domain asc").Pluck("domain", &candidates).Error; err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(verified)+len(candidates))
	out := make([]string, 0, len(verified)+len(candidates))
	appendUnique := func(items []string) {
		for _, d := range items {
			d = strings.TrimSpace(d)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	appendUnique(verified)
	appendUnique(candidates)
	sort.Strings(out)
	return out, nil
}

// DeleteAllDataByRootDomain removes all related scan/monitor data for a root domain.
func (d *Database) DeleteAllDataByRootDomain(projectID, rootDomain string) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		projectID = "default"
	}
	pattern := "%." + rootDomain
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var monitorTaskIDs []uint
		if err := tx.Model(&MonitorTask{}).
			Where("project_id = ? AND root_domain = ?", projectID, rootDomain).
			Pluck("id", &monitorTaskIDs).Error; err != nil {
			return err
		}
		if len(monitorTaskIDs) > 0 {
			taskJobIDs := make([]string, 0, len(monitorTaskIDs))
			for _, id := range monitorTaskIDs {
				taskJobIDs = append(taskJobIDs, fmt.Sprintf("task-%d", id))
			}
			if err := tx.Where("project_id = ? AND job_id IN ?", projectID, taskJobIDs).Delete(&JobLog{}).Error; err != nil {
				return err
			}
		}

		var scanJobIDs []string
		if err := tx.Model(&ScanJob{}).
			Where("project_id = ? AND root_domain = ?", projectID, rootDomain).
			Pluck("job_id", &scanJobIDs).Error; err != nil {
			return err
		}
		if len(scanJobIDs) > 0 {
			if err := tx.Where("project_id = ? AND job_id IN ?", projectID, scanJobIDs).Delete(&ScanArtifact{}).Error; err != nil {
				return err
			}
			if err := tx.Where("project_id = ? AND job_id IN ?", projectID, scanJobIDs).Delete(&ScanStage{}).Error; err != nil {
				return err
			}
			if err := tx.Where("project_id = ? AND job_id IN ?", projectID, scanJobIDs).Delete(&JobLog{}).Error; err != nil {
				return err
			}
		}

		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		if err := tx.Where(
			"project_id = ? AND (root_domain = ? OR domain = ? OR domain LIKE ? OR host = ? OR host LIKE ?)",
			projectID, rootDomain, rootDomain, pattern, rootDomain, pattern,
		).
			Delete(&Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
			Delete(&Port{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
			Delete(&Asset{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND (domain = ? OR domain LIKE ?)", projectID, rootDomain, pattern).
			Delete(&AssetCandidate{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&PortChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&AssetChange{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorEvent{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorSnapshot{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorRun{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&MonitorTarget{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&AssetEdge{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND root_domain = ?", projectID, rootDomain).Delete(&ScanJob{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// ── ScanJob helpers ──

// CreateScanJob creates a new persistent scan job record.
func (d *Database) CreateScanJob(job *ScanJob) error {
	return d.DB.Create(job).Error
}

// UpdateScanJob updates scan job fields.
func (d *Database) UpdateScanJob(jobID string, updates map[string]interface{}) error {
	return d.DB.Model(&ScanJob{}).Where("job_id = ?", jobID).Updates(updates).Error
}

// CreateJobLog writes one structured runtime log for a job.
func (d *Database) CreateJobLog(projectID, jobID, level, message string) error {
	projectID = strings.TrimSpace(projectID)
	jobID = strings.TrimSpace(jobID)
	level = strings.ToLower(strings.TrimSpace(level))
	message = strings.TrimSpace(message)
	if projectID == "" {
		projectID = "default"
	}
	if jobID == "" || message == "" {
		return nil
	}
	if level == "" {
		level = "info"
	}
	return d.DB.Create(&JobLog{
		ProjectID: projectID,
		JobID:     jobID,
		Level:     level,
		Message:   message,
	}).Error
}

// ListJobLogs lists job logs in ascending ID order.
// - sinceID > 0: incremental fetch (id > sinceID)
// - beforeID > 0: history backfill page (id < beforeID), ascending
// - default: latest tail page
// The second return value indicates whether there are older rows before the first item.
func (d *Database) ListJobLogs(projectID, jobID string, sinceID, beforeID uint, limit int) ([]JobLog, bool, error) {
	projectID = strings.TrimSpace(projectID)
	jobID = strings.TrimSpace(jobID)
	if projectID == "" || jobID == "" {
		return []JobLog{}, false, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	base := d.DB.Model(&JobLog{}).
		Where("project_id = ? AND job_id = ?", projectID, jobID)

	if sinceID > 0 {
		var rows []JobLog
		if err := base.Where("id > ?", sinceID).Order("id asc").Limit(limit).Find(&rows).Error; err != nil {
			return nil, false, err
		}
		return rows, false, nil
	}

	if beforeID > 0 {
		var chunk []JobLog
		if err := base.Where("id < ?", beforeID).Order("id desc").Limit(limit).Find(&chunk).Error; err != nil {
			return nil, false, err
		}
		for i, j := 0, len(chunk)-1; i < j; i, j = i+1, j-1 {
			chunk[i], chunk[j] = chunk[j], chunk[i]
		}
		if len(chunk) == 0 {
			return chunk, false, nil
		}
		var older JobLog
		hasMoreBefore := base.Where("id < ?", chunk[0].ID).Order("id desc").Take(&older).Error == nil
		return chunk, hasMoreBefore, nil
	}

	var tail []JobLog
	if err := base.Order("id desc").Limit(limit).Find(&tail).Error; err != nil {
		return nil, false, err
	}
	for i, j := 0, len(tail)-1; i < j; i, j = i+1, j-1 {
		tail[i], tail[j] = tail[j], tail[i]
	}
	if len(tail) == 0 {
		return tail, false, nil
	}
	var older JobLog
	hasMoreBefore := base.Where("id < ?", tail[0].ID).Order("id desc").Take(&older).Error == nil
	return tail, hasMoreBefore, nil
}

// GetScanJob returns a scan job by job_id.
func (d *Database) GetScanJob(jobID string) (*ScanJob, error) {
	var job ScanJob
	if err := d.DB.Where("job_id = ?", jobID).First(&job).Error; err != nil {
		return nil, err
	}
	return &job, nil
}

// ListScanJobs returns scan jobs ordered by created_at desc.
func (d *Database) ListScanJobs(projectID, rootDomain string, limit int) ([]ScanJob, error) {
	if limit <= 0 {
		limit = 500
	}
	query := d.DB.Order("created_at desc").Limit(limit)
	if projectID != "" {
		query = query.Where("project_id = ?", projectID)
	}
	if rootDomain != "" {
		query = query.Where("root_domain = ?", rootDomain)
	}
	var jobs []ScanJob
	if err := query.Find(&jobs).Error; err != nil {
		return nil, err
	}
	return jobs, nil
}

// CancelScanJob marks a pending/running scan job as canceled.
func (d *Database) CancelScanJob(jobID string) error {
	now := time.Now()
	return d.DB.Model(&ScanJob{}).
		Where("job_id = ? AND status IN ?", jobID, []string{"pending", "running"}).
		Updates(map[string]interface{}{
			"status":      "canceled",
			"finished_at": now,
		}).Error
}

// DeleteScanJobHistory removes one finished/canceled scan job and its stage/artifact rows.
func (d *Database) DeleteScanJobHistory(projectID, jobID string) error {
	projectID = strings.TrimSpace(projectID)
	jobID = strings.TrimSpace(jobID)
	if projectID == "" || jobID == "" {
		return gorm.ErrRecordNotFound
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		var job ScanJob
		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).First(&job).Error; err != nil {
			return err
		}
		status := strings.ToLower(strings.TrimSpace(job.Status))
		if status == "running" || status == "pending" {
			return ErrJobActive
		}

		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).Delete(&ScanArtifact{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).Delete(&ScanStage{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).Delete(&JobLog{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).Delete(&ScanJob{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// DeleteMonitorTaskHistory removes one finished/canceled monitor task record.
func (d *Database) DeleteMonitorTaskHistory(projectID string, taskID uint) error {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" || taskID == 0 {
		return gorm.ErrRecordNotFound
	}

	return d.DB.Transaction(func(tx *gorm.DB) error {
		var task MonitorTask
		if err := tx.Where("project_id = ? AND id = ?", projectID, taskID).First(&task).Error; err != nil {
			return err
		}
		status := strings.ToLower(strings.TrimSpace(task.Status))
		if status == "running" || status == "pending" {
			return ErrMonitorTaskActive
		}
		jobID := fmt.Sprintf("task-%d", task.ID)
		if err := tx.Where("project_id = ? AND job_id = ?", projectID, jobID).Delete(&JobLog{}).Error; err != nil {
			return err
		}
		if err := tx.Where("project_id = ? AND id = ?", projectID, taskID).Delete(&MonitorTask{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// ClaimPendingScanJob atomically claims one pending scan job.
func (d *Database) ClaimPendingScanJob() (*ScanJob, error) {
	var claimed *ScanJob
	err := d.DB.Transaction(func(tx *gorm.DB) error {
		var job ScanJob
		now := time.Now()
		result := tx.Model(&ScanJob{}).
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("mode = ? AND status = ?", "scan", "pending").
			Order("created_at asc").
			First(&job)
		if result.Error == gorm.ErrRecordNotFound {
			return nil
		}
		if result.Error != nil {
			return result.Error
		}

		if err := tx.Model(&ScanJob{}).
			Where("id = ? AND status = ?", job.ID, "pending").
			Updates(map[string]interface{}{
				"status":     "running",
				"started_at": now,
			}).Error; err != nil {
			return err
		}
		job.Status = "running"
		job.StartedAt = &now
		claimed = &job
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

type RecoveredScanJob struct {
	ProjectID          string
	JobID              string
	RootDomain         string
	StartedAt          *time.Time
	JobUpdatedAt       time.Time
	CutoffAt           time.Time
	RecoveredAt        time.Time
	StaleAfter         time.Duration
	LastStage          string
	LastStageStatus    string
	LastStageUpdatedAt *time.Time
	LastStageError     string
	ErrorMessage       string
}

func formatTimeRFC3339OrUnknown(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "unknown"
	}
	return t.Format(time.RFC3339)
}

// RecoverStaleRunningScanJobsDetailed marks stale running scan jobs as failed
// and returns per-job recovery details for runtime logging.
func (d *Database) RecoverStaleRunningScanJobsDetailed(staleAfter time.Duration) ([]RecoveredScanJob, error) {
	if staleAfter <= 0 {
		staleAfter = 6 * time.Hour
	}
	recoveredAt := time.Now()
	cutoff := recoveredAt.Add(-staleAfter)

	var staleJobs []ScanJob
	if err := d.DB.Model(&ScanJob{}).
		Where("mode = ? AND status = ? AND started_at IS NOT NULL AND started_at <= ?", "scan", "running", cutoff).
		Order("started_at asc").
		Find(&staleJobs).Error; err != nil {
		return nil, err
	}
	if len(staleJobs) == 0 {
		return []RecoveredScanJob{}, nil
	}

	recovered := make([]RecoveredScanJob, 0, len(staleJobs))
	for i := range staleJobs {
		jobID := staleJobs[i].ID
		var detail *RecoveredScanJob
		if err := d.DB.Transaction(func(tx *gorm.DB) error {
			var job ScanJob
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", jobID).First(&job).Error; err != nil {
				if err == gorm.ErrRecordNotFound {
					return nil
				}
				return err
			}

			status := strings.ToLower(strings.TrimSpace(job.Status))
			if strings.ToLower(strings.TrimSpace(job.Mode)) != "scan" || status != "running" || job.StartedAt == nil || job.StartedAt.After(cutoff) {
				return nil
			}

			errMsg := fmt.Sprintf(
				"stale running scan job recovered by worker (started_at=%s, updated_at=%s, stale_after=%s, cutoff=%s, recovered_at=%s)",
				formatTimeRFC3339OrUnknown(job.StartedAt),
				job.UpdatedAt.Format(time.RFC3339),
				staleAfter.String(),
				cutoff.Format(time.RFC3339),
				recoveredAt.Format(time.RFC3339),
			)
			if err := tx.Model(&ScanJob{}).
				Where("id = ? AND status = ?", job.ID, "running").
				Updates(map[string]interface{}{
					"status":        "failed",
					"finished_at":   recoveredAt,
					"error_message": errMsg,
				}).Error; err != nil {
				return err
			}

			item := RecoveredScanJob{
				ProjectID:    job.ProjectID,
				JobID:        job.JobID,
				RootDomain:   job.RootDomain,
				StartedAt:    job.StartedAt,
				JobUpdatedAt: job.UpdatedAt,
				CutoffAt:     cutoff,
				RecoveredAt:  recoveredAt,
				StaleAfter:   staleAfter,
				ErrorMessage: errMsg,
			}

			var stage ScanStage
			if err := tx.Where("project_id = ? AND job_id = ?", job.ProjectID, job.JobID).Order("updated_at desc").Take(&stage).Error; err == nil {
				item.LastStage = strings.TrimSpace(stage.Stage)
				item.LastStageStatus = strings.TrimSpace(stage.Status)
				if !stage.UpdatedAt.IsZero() {
					t := stage.UpdatedAt
					item.LastStageUpdatedAt = &t
				}
				item.LastStageError = strings.TrimSpace(stage.Error)
			} else if err != gorm.ErrRecordNotFound {
				return err
			}

			detail = &item
			return nil
		}); err != nil {
			return recovered, err
		}
		if detail != nil {
			recovered = append(recovered, *detail)
		}
	}
	return recovered, nil
}

// RecoverStaleRunningScanJobs marks stale running scan jobs as failed.
func (d *Database) RecoverStaleRunningScanJobs(staleAfter time.Duration) (int, error) {
	recovered, err := d.RecoverStaleRunningScanJobsDetailed(staleAfter)
	if err != nil {
		return 0, err
	}
	return len(recovered), nil
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

func defaultProtocol(v string) string {
	p := strings.TrimSpace(strings.ToLower(v))
	if p == "" {
		return "tcp"
	}
	return p
}

func buildRootDomain(candidates ...string) string {
	for _, raw := range candidates {
		host := normalizeHost(raw)
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			continue
		}
		return extractRootDomain(host)
	}
	return ""
}

func normalizeHost(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}

	if parsed, err := url.Parse(v); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	}

	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	if idx := strings.Index(v, "/"); idx != -1 {
		v = v[:idx]
	}
	if idx := strings.Index(v, ":"); idx != -1 {
		v = v[:idx]
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

func extractRootDomain(host string) string {
	return common.EffectiveRootDomain(host)
}
