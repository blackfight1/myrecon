package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"hunter/internal/db"
	"hunter/internal/engine"
	"hunter/internal/plugins"
)

func main() {
	// 命令行参数
	domain := flag.String("d", "", "单个目标域名")
	domainList := flag.String("dL", "", "包含域名列表的文件路径")
	subsOnly := flag.Bool("subs", false, "仅执行子域名收集（不进行测活和端口扫描）")
	flag.Parse()

	// 验证参数
	if *domain == "" && *domainList == "" {
		fmt.Println("使用方法:")
		fmt.Println("  单个域名:   go run main.go -d example.com")
		fmt.Println("  批量域名:   go run main.go -dL domains.txt")
		fmt.Println("  仅子域名:   go run main.go -d example.com -subs")
		fmt.Println("  批量+仅子域名: go run main.go -dL domains.txt -subs")
		os.Exit(1)
	}

	// 获取目标域名列表
	var domains []string
	if *domainList != "" {
		// 从文件读取域名列表
		file, err := os.Open(*domainList)
		if err != nil {
			log.Fatalf("无法打开域名列表文件: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			d := strings.TrimSpace(scanner.Text())
			if d != "" && !strings.HasPrefix(d, "#") {
				domains = append(domains, d)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("读取域名列表文件失败: %v", err)
		}

		if len(domains) == 0 {
			log.Fatalf("域名列表文件为空")
		}
		fmt.Printf("🎯 批量扫描模式: 共 %d 个目标域名\n", len(domains))
	} else {
		domains = []string{*domain}
		fmt.Printf("🎯 开始扫描目标: %s\n", *domain)
	}

	if *subsOnly {
		fmt.Println("📋 模式: 仅子域名收集")
	}

	// 判断是否为批量模式
	isBatchMode := *domainList != ""

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
	fmt.Println("📡 使用 Subfinder + Samoscout + Subdog + Shosubgo 进行子域名搜集")
	subfinderPlugin := plugins.NewSubfinderPlugin(isBatchMode)
	samoscoutPlugin := plugins.NewSamoscoutPlugin(isBatchMode)
	subdogPlugin := plugins.NewSubdogPlugin(isBatchMode)
	shosubgoPlugin := plugins.NewShosubgoPlugin()
	pipeline.AddDomainScanner(subfinderPlugin)
	pipeline.AddDomainScanner(samoscoutPlugin)
	pipeline.AddDomainScanner(subdogPlugin)
	pipeline.AddDomainScanner(shosubgoPlugin)

	// 如果不是仅子域名模式，添加测活和端口扫描
	if !*subsOnly {
		fmt.Println("🌐 Httpx 测活 + Naabu/Nmap 端口扫描（并行执行）")
		httpxPlugin := plugins.NewHttpxPlugin()
		pipeline.SetHttpxScanner(httpxPlugin)

		naabuPlugin := plugins.NewNaabuPlugin()
		nmapPlugin := plugins.NewNmapPlugin()
		pipeline.AddPortScanner(naabuPlugin)
		pipeline.AddPortScanner(nmapPlugin)
	}

	fmt.Println("🚀 启动扫描流水线...")

	// 执行流水线
	results, err := pipeline.Execute(domains)
	if err != nil {
		log.Fatalf("流水线执行失败: %v", err)
	}

	fmt.Println("💾 正在保存扫描结果到数据库...")

	// 保存结果到数据库
	savedAssetCount := 0
	savedPortCount := 0
	savedDomainCount := 0
	for _, result := range results {
		switch result.Type {
		case "domain":
			// 仅子域名模式下保存子域名
			if *subsOnly {
				if subdomain, ok := result.Data.(string); ok {
					// 保存子域名为资产
					data := map[string]interface{}{
						"domain": subdomain,
					}
					if err := database.SaveOrUpdateAsset(data); err != nil {
						// 忽略重复错误
					} else {
						savedDomainCount++
					}
				}
			}
		case "web_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if err := database.SaveOrUpdateAsset(data); err != nil {
					fmt.Printf("保存资产失败: %v\n", err)
				} else {
					savedAssetCount++
				}
			}
		case "port_service":
			if data, ok := result.Data.(map[string]interface{}); ok {
				if err := database.SaveOrUpdatePort(data); err != nil {
					fmt.Printf("保存端口失败: %v\n", err)
				} else {
					savedPortCount++
				}
			}
		case "open_port":
			if data, ok := result.Data.(map[string]interface{}); ok {
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
	if isBatchMode {
		fmt.Printf("🎯 扫描目标: %d 个域名\n", len(domains))
	} else {
		fmt.Printf("🎯 扫描目标: %s\n", domains[0])
	}
	fmt.Printf("⏱️  扫描耗时: %v\n", time.Since(scanStartTime).Round(time.Second))
	fmt.Printf("📈 数据库资产总数: %d -> %d\n", beforeAssetCount, afterAssetCount)
	if !*subsOnly {
		fmt.Printf("🔌 数据库端口总数: %d -> %d\n", beforePortCount, afterPortCount)
	}
	fmt.Printf("🆕 本次新增资产: %d 个\n", len(recentAssets))
	if !*subsOnly {
		fmt.Printf("🆕 本次新增端口: %d 个\n", len(recentPorts))
	}
	if *subsOnly {
		fmt.Printf("💾 成功保存子域名: %d 个\n", savedDomainCount)
	} else {
		fmt.Printf("💾 成功保存资产: %d 个\n", savedAssetCount)
		fmt.Printf("💾 成功保存端口: %d 个\n", savedPortCount)
	}

	if len(recentAssets) > 0 {
		fmt.Println("\n🔍 新发现的资产:")
		for i, asset := range recentAssets {
			if i >= 10 {
				fmt.Printf("... 还有 %d 个资产\n", len(recentAssets)-10)
				break
			}
			if asset.URL != "" {
				fmt.Printf("  • %s [%d] %s\n", asset.URL, asset.StatusCode, asset.Title)
			} else {
				fmt.Printf("  • %s\n", asset.Domain)
			}
		}
	}

	if !*subsOnly && len(recentPorts) > 0 {
		fmt.Println("\n🔌 新发现的端口:")
		for i, port := range recentPorts {
			if i >= 10 {
				fmt.Printf("... 还有 %d 个端口\n", len(recentPorts)-10)
				break
			}
			serviceInfo := port.Service
			if port.Version != "" {
				serviceInfo += " " + port.Version
			}
			host := port.Domain
			if host == "" {
				host = port.IP
			}
			fmt.Printf("  • %s:%d (%s) [%s] %s\n", host, port.Port, port.IP, port.Protocol, serviceInfo)
		}
	}

	fmt.Println("==================================================")
	fmt.Println("✅ 扫描任务完成!")
}
