package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("使用方法: go run main.go <domain> [scanner]")
		fmt.Println("示例: go run main.go example.com")
		fmt.Println("      go run main.go example.com subfinder")
		fmt.Println("      go run main.go example.com samoscout")
		fmt.Println("      go run main.go example.com both")
		fmt.Println("")
		fmt.Println("scanner 选项:")
		fmt.Println("  subfinder  - 使用 Subfinder (默认)")
		fmt.Println("  samoscout  - 使用 Samoscout")
		fmt.Println("  both       - 同时使用两个工具")
		os.Exit(1)
	}

	domain := os.Args[1]
	scanner := "subfinder" // 默认使用 subfinder
	if len(os.Args) >= 3 {
		scanner = os.Args[2]
	}

	fmt.Printf("🎯 开始扫描目标: %s\n", domain)

	// 连接数据库
	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
	database, err := db.NewDatabase(dsn)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}

	// 记录扫描开始前的资产数量
	beforeCount, err := database.GetAssetCount()
	if err != nil {
		log.Fatalf("获取资产数量失败: %v", err)
	}

	scanStartTime := time.Now()

	// 创建流水线
	pipeline := engine.NewPipeline()

	// 根据选择添加子域名搜集插件
	switch scanner {
	case "subfinder":
		fmt.Println("📡 使用 Subfinder 进行子域名搜集")
		subfinderPlugin := plugins.NewSubfinderPlugin()
		pipeline.AddScanner(subfinderPlugin)
	case "samoscout":
		fmt.Println("📡 使用 Samoscout 进行子域名搜集")
		samoscoutPlugin := plugins.NewSamoscoutPlugin()
		pipeline.AddScanner(samoscoutPlugin)
	case "both":
		fmt.Println("📡 使用 Subfinder + Samoscout 进行子域名搜集")
		subfinderPlugin := plugins.NewSubfinderPlugin()
		samoscoutPlugin := plugins.NewSamoscoutPlugin()
		pipeline.AddScanner(subfinderPlugin)
		pipeline.AddScanner(samoscoutPlugin)
	default:
		log.Fatalf("未知的扫描器: %s (可选: subfinder, samoscout, both)", scanner)
	}

	// 添加 Httpx 插件
	httpxPlugin := plugins.NewHttpxPlugin()
	pipeline.AddScanner(httpxPlugin)

	fmt.Println("🚀 启动扫描流水线...")

	// 执行流水线
	results, err := pipeline.Execute([]string{domain})
	if err != nil {
		log.Fatalf("流水线执行失败: %v", err)
	}

	fmt.Println("💾 正在保存扫描结果到数据库...")

	// 保存结果到数据库
	savedCount := 0
	for _, result := range results {
		if result.Type == "web_service" {
			if data, ok := result.Data.(map[string]interface{}); ok {
				if err := database.SaveOrUpdateAsset(data); err != nil {
					fmt.Printf("保存资产失败: %v\n", err)
				} else {
					savedCount++
				}
			}
		}
	}

	// 获取扫描后的资产数量
	afterCount, err := database.GetAssetCount()
	if err != nil {
		log.Fatalf("获取资产数量失败: %v", err)
	}

	// 获取本次扫描新增的资产
	recentAssets, err := database.GetRecentAssets(scanStartTime)
	if err != nil {
		log.Printf("获取新增资产失败: %v", err)
	}

	// 打印扫描总结
	fmt.Println("\n==================================================")
	fmt.Println("📊 扫描完成总结")
	fmt.Println("==================================================")
	fmt.Printf("🎯 扫描目标: %s\n", domain)
	fmt.Printf("⏱️  扫描耗时: %v\n", time.Since(scanStartTime).Round(time.Second))
	fmt.Printf("📈 数据库资产总数: %d -> %d\n", beforeCount, afterCount)
	fmt.Printf("🆕 本次新增资产: %d 个\n", len(recentAssets))
	fmt.Printf("💾 成功保存记录: %d 个\n", savedCount)

	if len(recentAssets) > 0 {
		fmt.Println("\n🔍 新发现的资产:")
		for i, asset := range recentAssets {
			if i >= 10 { // 只显示前10个
				fmt.Printf("... 还有 %d 个资产\n", len(recentAssets)-10)
				break
			}
			fmt.Printf("  • %s [%d] %s\n", asset.URL, asset.StatusCode, asset.Title)
		}
	}

	fmt.Println("==================================================")
	fmt.Println("✅ 扫描任务完成!")
}
