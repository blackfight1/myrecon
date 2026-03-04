# Hunter - 资产侦查与漏洞发现引擎

Hunter 是一个模块化的后端工具，面向 bug bounty 侦查流程，支持：

- 子域名收集（多工具并行）
- 存活探测与端口扫描
- Web 截图
- Nuclei（CVE 优先）漏洞扫描
- PostgreSQL 持久化

## 功能概览

- `subs`：子域名收集（`subfinder` / `samoscout` / `subdog` / `shosubgo`）
- `ports`：`httpx` + `naabu` + `nmap`
- `witness`：`gowitness` 截图
- `nuclei`：可选漏洞扫描（默认按 `cve` 标签，`medium,high,critical`）
- `notify`：可选钉钉通知（recon 开始/结束）
- `monitor`：定时监控单个域名，跟踪新存活子域/Web变化/端口变化

## 项目结构

```text
myrecon/
├── main.go
├── internal/
│   ├── engine/
│   │   └── scanner.go
│   ├── plugins/
│   │   ├── subfinder.go
│   │   ├── samoscout.go
│   │   ├── subdog.go
│   │   ├── shosubgo.go
│   │   ├── httpx.go
│   │   ├── naabu.go
│   │   ├── nmap.go
│   │   ├── gowitness.go
│   │   ├── nuclei.go
│   │   └── utils.go
│   └── db/
│       ├── models.go
│       └── database.go
├── docker-compose.yml
└── README.md
```

## 环境准备

### 1) 基础依赖

- Go 1.21+
- Docker / Docker Compose
- PostgreSQL（可通过 docker-compose 启动）

### 2) 安装扫描工具

```bash
# 子域名收集
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/samogod/samoscout@latest
go install -v github.com/rix4uni/SubDog@latest
go install -v github.com/incogbyte/shosubgo@latest

# 存活探测
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# 端口扫描
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
# nmap 需要系统安装

# 截图
go install github.com/sensepost/gowitness@latest

# 漏洞扫描
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### 3) 环境变量

```bash
# Shodan 子域名插件需要
export SHODAN_API_KEY=your_key

# 钉钉通知（开启 -notify 时需要）
export DINGTALK_WEBHOOK=https://oapi.dingtalk.com/robot/send?access_token=xxxx

# 如果机器人开启“加签”，还需要配置
export DINGTALK_SECRET=SECxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Windows PowerShell:

```powershell
$env:SHODAN_API_KEY="your_key"
```

## 启动数据库

```bash
docker-compose up -d
```

默认连接：

- host: `localhost`
- port: `5432`
- db: `hunter`
- user: `hunter`
- password: `hunter123`

## 使用方法

### 完整扫描（推荐）

```bash
go run main.go -mode scan -d example.com
```

### 完整扫描 + Nuclei

```bash
go run main.go -mode scan -d example.com -nuclei
```

### 完整扫描 + 钉钉通知

```bash
go run main.go -mode scan -d example.com -notify
```

### 监控模式（第一阶段）

```bash
go run main.go -mode monitor -d example.com -monitor-interval 6h -notify
```

说明：监控模式会循环执行 `subs+ports`，并检测：

- 新存活子域（含标题、状态码、技术栈）
- Web 指纹变化（状态码/标题/技术栈）
- 端口新增/关闭/服务版本变化

监控基线策略：

- 第一次监控运行仅建立基线（`baseline_done=true`），只发送开始/结束通知
- 从第二次运行开始，才发送变化通知

### 批量扫描

```bash
go run main.go -dL domains.txt -nuclei
```

### 仅运行指定模块

```bash
# 仅子域名收集
go run main.go -m subs -d example.com

# 仅端口链（输入是子域名列表）
go run main.go -m ports -i subdomains.txt -nuclei

# 仅截图（输入是 URL 列表）
go run main.go -m witness -i urls.txt
```

### 管道输入

```bash
cat subdomains.txt | go run main.go -m ports -nuclei
cat urls.txt | go run main.go -m witness
```

## 命令行参数

| 参数 | 说明 |
|---|---|
| `-mode` | 运行模式：`scan` 或 `monitor`（默认 `scan`） |
| `-d` | 单个目标域名 |
| `-dL` | 域名列表文件 |
| `-i` | 输入文件（ports/witness 模块） |
| `-m` | 模块选择：`subs,ports,witness` |
| `--dry-run` | 只运行，不写数据库 |
| `-screenshot-dir` | 截图目录（默认 `screenshots`） |
| `-nuclei` | 启用 Nuclei 漏洞扫描 |
| `-notify` | 启用钉钉开始/结束通知（读取 `DINGTALK_WEBHOOK`） |
| `-monitor-interval` | 监控间隔（默认 `6h`） |
| `-report` | 启动 gowitness 报告服务 |
| `-report-host` | 报告服务监听地址 |
| `-report-port` | 报告服务端口 |
| `-list-screenshots` | 列出已有截图域名 |

## 扫描流程

```text
输入目标(-d/-dL/-i)
      |
      v
模块选择(subs/ports/witness)
      |
      v
[subs] 子域名收集(并行多工具) -> 去重
      |
      v
[ports] httpx存活 + naabu->nmap
      |
      +--> [可选] nuclei (CVE优先)
      |
      +--> [可选] gowitness 截图
      |
      v
写入 PostgreSQL + 输出统计摘要
```

## 数据库表

自动迁移会创建以下表：

- `assets`：资产信息（域名、URL、状态码、标题、技术栈等）
- `ports`：端口与服务信息
- `vulnerabilities`：Nuclei 漏洞结果（模板、严重度、CVE、匹配目标、指纹等）
- `monitor_runs`：每次监控运行记录（状态、耗时、变化统计）
- `asset_changes`：子域/Web变化明细
- `port_changes`：端口变化明细
- `monitor_targets`：监控目标状态（是否已完成基线）

## 常用查询

```sql
-- 资产
SELECT domain, url, status_code, title, last_seen FROM assets ORDER BY updated_at DESC LIMIT 50;

-- 端口
SELECT domain, ip, port, service, version, last_seen FROM ports ORDER BY updated_at DESC LIMIT 50;

-- 漏洞
SELECT domain, template_id, severity, cve, matched_at, last_seen
FROM vulnerabilities
ORDER BY updated_at DESC
LIMIT 50;
```

## 截图查看

```bash
# 列出可查看域名
go run main.go -list-screenshots

# 启动指定域名的截图服务
go run main.go -report example.com

# 自定义地址端口
go run main.go -report example.com -report-host 0.0.0.0 -report-port 8080
```

## 注意事项

- 仅对授权范围目标执行扫描。
- `shosubgo` 依赖 `SHODAN_API_KEY`。
- `nuclei` 结果属于候选，建议人工复现后再提交报告。
- 首次运行 `nuclei` 前建议执行 `nuclei -update-templates`。
- 钉钉机器人如开启加签，必须同时配置 `DINGTALK_SECRET`。

## 后续维护约定

后续如果功能或参数有变更，请同步更新本 README，至少包含：

- 新增/变更参数
- 流程图或执行顺序变化
- 数据库表结构变化
- 最小可运行示例命令
