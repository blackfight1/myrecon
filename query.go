package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"hunter/internal/db"
)

func main() {
	// 连接数据库
	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
	database, err := db.NewDatabase(dsn)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}

	// 获取所有资产
	var assets []db.Asset
	if err := database.DB.Order("created_at DESC").Find(&assets).Error; err != nil {
		log.Fatalf("查询失败: %v", err)
	}

	fmt.Printf("📊 数据库中共有 %d 个资产\n\n", len(assets))

	if len(assets) == 0 {
		fmt.Println("暂无数据")
		return
	}

	// 显示资产列表
	fmt.Println("=" + "=================================================")
	fmt.Printf("%-5s %-30s %-6s %-30s\n", "ID", "域名", "状态码", "标题")
	fmt.Println("=" + "=================================================")

	for _, asset := range assets {
		title := asset.Title
		if len(title) > 28 {
			title = title[:28] + ".."
		}
		domain := asset.Domain
		if len(domain) > 28 {
			domain = domain[:28] + ".."
		}

		fmt.Printf("%-5d %-30s %-6d %-30s\n",
			asset.ID,
			domain,
			asset.StatusCode,
			title,
		)
	}

	fmt.Println("=" + "=================================================")

	// 如果提供了参数，显示详细信息
	if len(os.Args) > 1 {
		domain := os.Args[1]
		var asset db.Asset
		if err := database.DB.Where("domain = ?", domain).First(&asset).Error; err != nil {
			log.Fatalf("未找到域名: %s", domain)
		}

		fmt.Printf("\n🔍 详细信息: %s\n", domain)
		fmt.Println("--------------------------------------------------")
		fmt.Printf("URL:          %s\n", asset.URL)
		fmt.Printf("IP:           %s\n", asset.IP)
		fmt.Printf("状态码:       %d\n", asset.StatusCode)
		fmt.Printf("标题:         %s\n", asset.Title)

		// 解析技术栈
		var technologies []string
		if len(asset.Technologies) > 0 {
			json.Unmarshal(asset.Technologies, &technologies)
		}
		if len(technologies) > 0 {
			fmt.Printf("技术栈:       %v\n", technologies)
		}

		fmt.Printf("最后发现:     %s\n", asset.LastSeen.Format("2006-01-02 15:04:05"))
		fmt.Printf("创建时间:     %s\n", asset.CreatedAt.Format("2006-01-02 15:04:05"))
	}
}
