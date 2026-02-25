package db

import (
	"database/sql/driver"
	"errors"
	"time"

	"gorm.io/gorm"
)

// JSONB 自定义 JSONB 类型
type JSONB []byte

// Value 实现 driver.Valuer 接口
func (j JSONB) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

// Scan 实现 sql.Scanner 接口
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

// Asset 资产模型
type Asset struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	Domain       string         `gorm:"uniqueIndex;not null" json:"domain"`
	URL          string         `json:"url"`
	IP           string         `json:"ip"`
	StatusCode   int            `json:"status_code"`
	Title        string         `json:"title"`
	Technologies JSONB          `gorm:"type:jsonb" json:"technologies"` // 存储技术栈数组
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName 指定表名
func (Asset) TableName() string {
	return "assets"
}
