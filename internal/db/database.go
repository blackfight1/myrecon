package db

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Database 数据库连接管理
type Database struct {
	DB *gorm.DB
}

// NewDatabase 创建数据库连接
func NewDatabase(dsn string) (*Database, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// 自动迁移
	if err := db.AutoMigrate(&Asset{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}

	return &Database{DB: db}, nil
}

// SaveOrUpdateAsset 保存或更新资产信息
func (d *Database) SaveOrUpdateAsset(data map[string]interface{}) error {
	domain, ok := data["domain"].(string)
	if !ok || domain == "" {
		return fmt.Errorf("domain is required")
	}

	// 准备技术栈 JSON 数据
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

	// 查找现有记录
	var existingAsset Asset
	result := d.DB.Where("domain = ?", domain).First(&existingAsset)

	now := time.Now()

	if result.Error == gorm.ErrRecordNotFound {
		// 创建新记录
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
		// 更新现有记录
		updates := map[string]interface{}{
			"last_seen": now,
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
		if len(techJSON) > 2 { // 不是空数组 []
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

// GetAssetCount 获取资产总数
func (d *Database) GetAssetCount() (int64, error) {
	var count int64
	if err := d.DB.Model(&Asset{}).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetRecentAssets 获取最近添加的资产
func (d *Database) GetRecentAssets(since time.Time) ([]Asset, error) {
	var assets []Asset
	if err := d.DB.Where("created_at > ?", since).Find(&assets).Error; err != nil {
		return nil, err
	}
	return assets, nil
}

// 辅助函数
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
