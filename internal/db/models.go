package db

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// Asset 资产模型
type Asset struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	Domain       string         `gorm:"uniqueIndex;not null" json:"domain"`
	URL          string         `json:"url"`
	IP           string         `json:"ip"`
	StatusCode   int            `json:"status_code"`
	Title        string         `json:"title"`
	Technologies datatypes.JSON `json:"technologies"` // 存储技术栈数组
	LastSeen     time.Time      `json:"last_seen"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName 指定表名
func (Asset) TableName() string {
	return "assets"
}
