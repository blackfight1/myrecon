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
		fmt.Println("使用方法: go run main.go <domain>")
		fmt.Println("示例: go run main.go example.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("🎯 开始扫描目标: %s\n", domain)

	// 连接数据库
	dsn := "host=localhost user=hunter password=hunter123 dbname=hunter port=5432 sslmode=disable"
	database, err := db.NewDatabase(dsn)
	if err != nil {
		log.Fatalf("数据库连接失败: %v", err)
	}

	// 记录扫描开始前的资产和端口数量
	beforeAssetCount, err := database.GetAssetCount()
	if err != nil {
		log.Fatalf("获取资产数量失败: %v", err)
	}
	beforePortCount, _ := database.GetPortCount()

	scanStartTime := time.Now()

	// 创建流水线
	pipeline := engine.NewPipeline()

	// 添加所有子域名搜集插件（并行执行）
	fmt.Println("📡 使用 Subfinder + Samoscout + Subdog 进行子域名搜集")
	subfinderPlugin := plugins.NewSubfinderPlugin()
	samoscoutPlugin := plugins.NewSamoscoutPlugin()
	subdogPlugin := plugins.NewSubdogPlugin()
	pipeline.AddDomainScanner(subfinderPlugin)
	pipeline.AddDomainScanner(samoscoutPlugin)
	pipeline.AddDomainScanner(subdogPlugin)

	// 设置 Httpx 插件（与端口扫描并行执行）
	fmt.Println("🌐 Httpx 测活 + Naabu/Nmap 端口扫描（并行执行）")
	httpxPlugin := plugins.NewHttpxPlugin()
	pipeline.SetHttpxScanner(httpxPlugin)

	// 添加端口扫描链（Naabu → Nmap，串行执行，与 Httpx 并行）
	naabuPlugin := plugins.NewNaabuPlugin()
	nmapPlugin := plugins.NewNmapPlugin()
	pipeline.AddPortScanner(naabuPlugin)
	pipeline.AddPortScanner(nmapPlugin)

	fmt.Println("🚀 启动扫描流水线...")

	// 执行流水线
	results, err := pipeline.Execute([]string{domain})
	if err != nil {
		log.Fatalf("流水线执行失败: %v", err)
	}

	fmt.Println("💾 正在保存扫描结果到数据库...")

	// 保存结果到数据库
	savedAssetCount := 0
	savedPortCount := 0
	for _, result := range results {
		switch result.Type {
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if err := database.SaveOrUpdateAsset(data); err != nil {
					fmt.Printf("保存资产失败: %v\n", err)
				} else {
					savedAssetCount++
				}
			}
		case "port_service":
			// 保存 Nmap 识别的端口服务信息
			if data, ok := result.Data.(map[string]interface{}); ok {
				if err := database.SaveOrUpdatePort(data); err != nil {
					fmt.Printf("保存端口失败: %v\n", err)
				} else {
					savedPortCount++
				}
			}
		case "open_port":
			// 保存 Naabu 发现的开放端口（如果 Nmap 未运行）
			if data, ok := result.Data.(map[string]interface{}); ok {
				// 检查是否已有对应的 port_service 结果
				if err := database.SaveOrUpdatePort(data); err != nil {
					fmt.Printf("保存端口失败: %v\n", err)
				}
			}
		}
	}

	// 获取扫描后的资产数量
	afterAssetCount, err := database.GetAssetCount()
	if err != nil {
		log.Fatalf("获取资产数量失败: %v", err)
	}

	// 获取扫描后的端口数量
	afterPortCount, _ := database.GetPortCount()

	// 获取本次扫描新增的资产
	recentAssets, err := database.GetRecentAssets(scanStartTime)
	if err != nil {
		log.Printf("获取新增资产失败: %v", err)
	}

	// 获取本次扫描新增的端口
	recentPorts, err := database.GetRecentPorts(scanStartTime)
	if err != nil {
		log.Printf("获取新增端口失败: %v", err)
	}

	// 打印扫描总结
	fmt.Println("\n==================================================")
	fmt.Println("📊 扫描完成总结")
	fmt.Println("==================================================")
	fmt.Printf("🎯 扫描目标: %s\n", domain)
	fmt.Printf("⏱️  扫描耗时: %v\n", time.Since(scanStartTime).Round(time.Second))
	fmt.Printf("📈 数据库资产总数: %d -> %d\n", beforeAssetCount, afterAssetCount)
	fmt.Printf("🔌 数据库端口总数: %d -> %d\n", beforePortCount, afterPortCount)
	fmt.Printf("🆕 本次新增资产: %d 个\n", len(recentAssets))
	fmt.Printf("🆕 本次新增端口: %d 个\n", len(recentPorts))
	fmt.Printf("💾 成功保存资产: %d 个\n", savedAssetCount)
	fmt.Printf("💾 成功保存端口: %d 个\n", savedPortCount)

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

	if len(recentPorts) > 0 {
		fmt.Println("\n🔌 新发现的端口:")
		for i, port := range recentPorts {
			if i >= 10 { // 只显示前10个
				fmt.Printf("... 还有 %d 个端口\n", len(recentPorts)-10)
				break
			}
			serviceInfo := port.Service
			if port.Version != "" {
				serviceInfo += " " + port.Version
			}
			fmt.Printf("  • %s:%d [%s] %s\n", port.IP, port.Port, port.Protocol, serviceInfo)
		}
	}

	fmt.Println("==================================================")
	fmt.Println("✅ 扫描任务完成!")
}
