# Hunter - 资产搜集引擎

Hunter 是一个模块化的资产搜集引擎，采用流水线架构设计，支持插件化扩展。

## 🏗️ 架构设计

- **插件化设计**: 每个扫描工具都是独立的插件，易于扩展
- **流水线模式**: 支持将一个工具的输出作为下一个工具的输入
- **数据库存储**: 使用 PostgreSQL + GORM 进行数据持久化
- **批量扫描**: 支持单域名和批量域名扫描
- **灵活模式**: 支持仅子域名收集或完整扫描流程

## 📁 项目结构

```
hunter/
├── internal/
│   ├── engine/          # 流水线核心逻辑
│   │   └── scanner.go   # Scanner 接口和 Pipeline 实现
│   ├── plugins/         # 扫描工具插件
│   │   ├── subfinder.go # Subfinder 域名搜集插件
│   │   ├── samoscout.go # Samoscout 域名搜集插件
│   │   ├── subdog.go    # Subdog 域名搜集插件
│   │   ├── shosubgo.go  # Shosubgo 域名搜集插件（Shodan）
│   │   ├── httpx.go     # Httpx 存活检测插件
│   │   ├── naabu.go     # Naabu 端口扫描插件
│   │   ├── nmap.go      # Nmap 服务识别插件
│   │   └── utils.go     # 辅助函数
│   └── db/              # 数据库相关
│       ├── models.go    # 数据模型
│       └── database.go  # 数据库操作
├── main.go              # 主程序入口
├── go.mod               # Go 模块文件
├── docker-compose.yml   # PostgreSQL 容器配置
└── README.md            # 项目说明
```

## 🚀 快速开始

### 1. 环境准备

确保已安装以下工具：
- Go 1.21+
- Docker & Docker Compose
- subfinder、samoscout、subdog、shosubgo（子域名收集）
- httpx（存活检测）
- naabu、nmap（端口扫描）

安装扫描工具：
```bash
# 子域名收集工具
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/samogod/samoscout@latest
go install -v github.com/rix4uni/SubDog@latest
go install -v github.com/incogbyte/shosubgo@latest

# 存活检测
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 端口扫描
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
# nmap 需要系统安装

```

### 2. 配置环境变量

```bash
# Shosubgo 需要 Shodan API Key
export SHODAN_API_KEY="your_shodan_api_key"
```

### 3. 启动数据库

```bash
docker-compose up -d
```

### 4. 运行扫描

```bash
# 单个域名完整扫描（子域名 + 测活 + 端口扫描）
go run main.go -d example.com

# 批量域名完整扫描
go run main.go -dL domains.txt

# 仅子域名收集（不进行测活和端口扫描）
go run main.go -d example.com -subs

# 批量域名仅子域名收集
go run main.go -dL domains.txt -subs
```

## 📋 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-d` | 单个目标域名 | `-d example.com` |
| `-dL` | 域名列表文件 | `-dL domains.txt` |
| `-subs` | 仅子域名收集模式 | `-subs` |
| `-no-screenshot` | 禁用截图功能 | `-no-screenshot` |
| `-screenshot-dir` | 截图存储目录 | `-screenshot-dir ./shots` |
| `-report` | 启动截图查看服务 | `-report example.com` |
| `-report-host` | 截图服务监听地址 | `-report-host 0.0.0.0` |
| `-report-port` | 截图服务监听端口 | `-report-port 7070` |
| `-list-screenshots` | 列出所有有截图的域名 | `-list-screenshots` |

**domains.txt 格式：**
```
example.com
test.com
# 注释行会被忽略
another.com
```

## 🔧 扫描流程

### 第一阶段：子域名收集（并行执行）

| 工具 | 说明 | 批量支持 |
|------|------|----------|
| Subfinder | ProjectDiscovery 子域名枚举 | ✅ `-dL` |
| Samoscout | 多源子域名收集 | ✅ `-dL` |
| Subdog | 子域名收集 | ✅ stdin |
| Shosubgo | 从 Shodan 查找子域名 | ❌ 逐个处理 |

### 第二阶段：存活检测 + 端口扫描（并行执行）

| 工具 | 说明 |
|------|------|
| Httpx | HTTP 存活检测、状态码、标题、技术栈 |
| Naabu | 快速端口扫描 |
| Nmap | 服务版本识别 |

### 第三阶段：Web 截图

| 工具 | 说明 |
|------|------|
| Gowitness | 对存活 Web 服务进行截图，按域名分类存储 |

## 📊 输出示例

```
╔══════════════════════════════════════════════════════════════╗
║                      📊 扫描完成总结                          ║
╠══════════════════════════════════════════════════════════════╣
║  🎯 扫描目标: 3 个域名                                        ║
║  ⏱️  扫描耗时: 2m30s                                          ║
╠══════════════════════════════════════════════════════════════╣
║                      📋 各域名统计                            ║
╠══════════════════════════════════════════════════════════════╣
║  example.com              子域名:125   Web:45    端口:89     ║
║  test.com                 子域名:67    Web:23    端口:34     ║
║  another.com              子域名:89    Web:31    端口:56     ║
╠══════════════════════════════════════════════════════════════╣
║                      📈 汇总统计                              ║
╠══════════════════════════════════════════════════════════════╣
║  📊 发现子域名总数: 281                                       ║
║  🌐 存活 Web 服务: 99                                         ║
║  🔌 开放端口总数: 179                                         ║
║  📈 数据库资产: 100 -> 381                                    ║
║  📈 数据库端口: 50 -> 229                                     ║
╠══════════════════════════════════════════════════════════════╣
║  💾 成功保存资产: 281                                         ║
║  💾 成功保存端口: 179                                         ║
╚══════════════════════════════════════════════════════════════╝

✅ 扫描任务完成!
```

## 🗄️ 数据库操作

### 连接数据库

```bash
# 使用 psql 连接
docker exec -it hunter-postgres psql -U hunter -d hunter

# 或者使用任意 PostgreSQL 客户端
# Host: localhost
# Port: 5432
# User: hunter
# Password: hunter123
# Database: hunter
```

### 常用查询

```sql
-- 查看所有资产
SELECT domain, url, status_code, title FROM assets;

-- 查看所有端口
SELECT domain, ip, port, service, version FROM ports;

-- 按域名统计子域名数量
SELECT 
    SUBSTRING(domain FROM '([^.]+\.[^.]+)$') as root_domain,
    COUNT(*) as subdomain_count 
FROM assets 
GROUP BY root_domain;

-- 查看特定服务的端口
SELECT domain, ip, port, service, version 
FROM ports 
WHERE service LIKE '%ssh%' OR service LIKE '%mysql%';
```

### 清理数据

```sql
-- 删除所有资产数据
DELETE FROM assets;

-- 删除所有端口数据
DELETE FROM ports;

-- 删除特定域名的数据
DELETE FROM assets WHERE domain LIKE '%example.com';
DELETE FROM ports WHERE domain LIKE '%example.com';

-- 重置自增 ID（可选）
ALTER SEQUENCE assets_id_seq RESTART WITH 1;
ALTER SEQUENCE ports_id_seq RESTART WITH 1;

-- 完全清空并重置表
TRUNCATE TABLE assets RESTART IDENTITY CASCADE;
TRUNCATE TABLE ports RESTART IDENTITY CASCADE;
```

### 一键清空所有数据

```bash
# 在终端执行
docker exec -it hunter-postgres psql -U hunter -d hunter -c "TRUNCATE TABLE assets, ports RESTART IDENTITY CASCADE;"
```

## 📸 截图功能

Hunter 集成了 Gowitness 进行 Web 截图，截图按根域名分类存储：

```
screenshots/
├── google.com/
│   ├── gowitness.sqlite3
│   └── screenshots/
└── tesla.com/
    ├── gowitness.sqlite3
    └── screenshots/
```

### 截图相关命令

```bash
# 扫描时自动截图（默认开启）
go run main.go -d example.com

# 禁用截图
go run main.go -d example.com -no-screenshot

# 列出所有有截图的域名
go run main.go -list-screenshots

# 启动截图查看服务
go run main.go -report example.com

# 指定端口启动
go run main.go -report example.com -report-port 8080
```

### 安装 Gowitness

```bash
go install github.com/sensepost/gowitness@latest
```

## 🔌 扩展插件

要添加新的扫描工具，只需：

1. 在 `internal/plugins/` 目录创建新插件文件
2. 实现 `Scanner` 接口
3. 在 `main.go` 中添加到流水线

```go
type Scanner interface {
    Name() string
    Execute(input []string) ([]Result, error)
}
```

## 🛠️ 技术特性

- **错误处理**: 优雅处理工具缺失和执行错误
- **批量扫描**: 支持单域名和批量域名扫描
- **灵活模式**: 支持仅子域名收集或完整扫描
- **实时进度**: 扫描过程中实时显示进度
- **数据去重**: 自动去重和更新重复记录
- **并发执行**: 子域名收集工具并行执行
- **美化输出**: 清晰的表格化统计输出
