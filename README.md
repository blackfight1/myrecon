# Hunter / MyRecon

轻量化资产侦查与漏洞发现平台，面向日常资产盘点、持续监控和漏洞候选收集。

当前版本已经采用 **API 进程与 Worker 执行进程分离** 的模式：

- API (`-mode web`)：只负责接收请求、查询数据、写入任务队列
- Worker (`-mode worker`)：只负责消费任务并执行扫描

> 如果只启动 API 不启动 Worker，`scan_jobs` 会一直停在 `pending`，这是预期行为。

## 核心能力

- 子域名收集：`subfinder` / `chaos` / `findomain` / `bbot` / `shosubgo`
- 可选主动扩展：`bbot_active`（独立模块）/ `dictgen + dnsx`
- Web 存活探测：`httpx`
- 端口与服务识别：`naabu + nmap`（`service/version/banner`）
- Web 截图：`gowitness`
- 漏洞候选：`nuclei` + `cors`（高危 CORS）+ `subjack`（子域名接管）
- 资产、端口、漏洞、任务、监控结果统一落地 PostgreSQL
- 前端控制台（React + Vite）

## 架构说明

```text
Frontend (Vite/Nginx)
        |
        v
API Server (go run . -mode web)
        |
        +--> PostgreSQL (assets/ports/vulns/jobs/...)
        |
        +--> scan_jobs / monitor_tasks (任务队列)
                              |
                              v
                     Worker (go run . -mode worker)
                              |
                              v
             调用外部扫描工具并回写 PostgreSQL
```

## 目录结构

```text
myrecon/
├── main.go
├── monitor.go
├── internal/
│   ├── api/
│   ├── db/
│   ├── engine/
│   └── plugins/
├── frontend/
├── docker-compose.yml
└── README.md
```

## 环境要求

- Go `1.21+`
- PostgreSQL `15+`（推荐直接用 `docker-compose.yml`）
- Node.js `20+`（仅前端开发需要）
- Docker / Docker Compose（可选，但推荐）

## 安装第三方扫描工具

以下工具由后端在运行时直接调用（`PATH` 中必须可见）。

### 1) 子域名收集工具

```bash
# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# chaos
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# findomain（常见方式：cargo）
cargo install findomain
# 或使用官方 release 二进制

# bbot（推荐 pipx）
pipx install bbot

# shosubgo
go install -v github.com/incogbyte/shosubgo@latest
```

### 2) 主动子域名扩展（可选）

```bash
# dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### 3) Web / 端口 / 漏洞 / 截图工具

```bash
# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# naabu
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# nmap（系统包管理器安装）
# Ubuntu/Debian: sudo apt-get install -y nmap
# macOS: brew install nmap

# gowitness
go install github.com/sensepost/gowitness@latest

# nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# subjack（子域名接管）
go install -v github.com/haccer/subjack@latest
```

### 4) 安装自检

Linux/macOS:

```bash
for t in subfinder chaos findomain bbot shosubgo dnsx httpx naabu nmap gowitness nuclei subjack; do
  command -v "$t" >/dev/null 2>&1 && echo "[OK] $t" || echo "[MISS] $t"
done
```

PowerShell:

```powershell
$tools = "subfinder","chaos","findomain","bbot","shosubgo","dnsx","httpx","naabu","nmap","gowitness","nuclei","subjack"
foreach ($t in $tools) {
  if (Get-Command $t -ErrorAction SilentlyContinue) { "[OK] $t" } else { "[MISS] $t" }
}
```

## 环境变量

```bash
# shosubgo 依赖（使用 Shodan 数据时必需）
SHODAN_API_KEY=your_key

# chaos 依赖（任选其一）
CHAOS_KEY=your_key
# 或：
PDCP_API_KEY=your_key

# DingTalk 通知（开启 -notify 时）
DINGTALK_WEBHOOK=https://oapi.dingtalk.com/robot/send?access_token=xxxx
DINGTALK_SECRET=SECxxxxxxxxxxxxxxxx

# CORS（可选）
# 默认仅允许 http://localhost:5173 和 http://127.0.0.1:5173
# 允许所有跨域（开发临时用，不推荐生产）：
CORS_ALLOWED_ORIGINS=*
# 指定多个来源：
# CORS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173

# Nuclei 降噪（可选）
# 默认会排除 info/unknown 严重级别
NUCLEI_EXCLUDE_SEVERITIES=info,unknown
# 可额外排除标签（逗号分隔），例如：
# NUCLEI_EXCLUDE_TAGS=tech,panel
# 排除协议模板类型（默认 ssl,dns）
# NUCLEI_EXCLUDE_PROTOCOL_TYPES=ssl,dns
# 排除模板 ID（逗号分隔，设置为空可禁用默认排除）
# NUCLEI_EXCLUDE_TEMPLATE_IDS=https-to-http-redirect,form-detection

# 高危 CORS 扫描（可选）
# 是否启用 CORS 扫描器（默认 true）
# CORS_SCAN_ENABLED=true
# 仅保留高风险规则（默认 true）
# CORS_HIGH_RISK_ONLY=true
# 单次任务最多检测多少个 live URL（默认 200）
# CORS_MAX_TARGETS=200
# HTTP 请求超时（毫秒，默认 7000）
# CORS_TIMEOUT_MS=7000
# 攻击者域名占位（默认 evil-cors.invalid）
# CORS_ATTACKER_HOST=evil-cors.invalid
# User-Agent（可选）
# CORS_USER_AGENT=myrecon-cors/1.0
# 当任务使用默认模块且启用 nuclei 时，是否自动附带 cors（默认 true）
# CORS_WITH_NUCLEI=true

# 子域名接管扫描（subjack，可选）
# 是否启用插件（默认 true）
# SUBTAKEOVER_SCAN_ENABLED=true
# 单次任务最多检测 host 数（默认 3000）
# SUBTAKEOVER_MAX_TARGETS=3000
# 并发（默认 20）
# SUBTAKEOVER_CONCURRENCY=20
# 每个请求超时秒数（默认 10）
# SUBTAKEOVER_TIMEOUT_SEC=10
# 无协议输入是否默认强制 https（默认 true）
# SUBTAKEOVER_FORCE_HTTPS=true
# 对每个目标发送请求验证（对应 subjack -a，默认 true）
# SUBTAKEOVER_CHECK_ALL=true
# Manual 模式（对应 subjack -m，默认 false）
# SUBTAKEOVER_MANUAL=false
# 可选扩展检查（默认 false）
# SUBTAKEOVER_CHECK_NS=false
# SUBTAKEOVER_CHECK_AR=false
# SUBTAKEOVER_CHECK_AXFR=false
# SUBTAKEOVER_CHECK_MAIL=false
# 自定义解析器列表文件（对应 subjack -r）
# SUBTAKEOVER_RESOLVER_LIST=/path/to/resolvers.txt
# 风险级别（默认 high）
# SUBTAKEOVER_SEVERITY=high
# 排除指定平台（逗号分隔，按 service 名过滤）
# SUBTAKEOVER_EXCLUDE_ENGINES=github,vercel
```

PowerShell 示例：

```powershell
$env:SHODAN_API_KEY="your_key"
$env:DINGTALK_WEBHOOK="https://oapi.dingtalk.com/robot/send?access_token=xxxx"
$env:DINGTALK_SECRET="SECxxxx"
$env:CORS_ALLOWED_ORIGINS="http://localhost:5173"
```

## 启动方式（推荐）

### 1) 启动 PostgreSQL

```bash
docker compose up -d postgres
```

默认连接（与当前代码一致）：

- host: `localhost`
- port: `5432`
- db: `hunter`
- user: `hunter`
- password: `hunter123`

### 2) 启动 API（Web）

```bash
go run . -mode web -web-addr 0.0.0.0:8080
```

### 3) 启动 Worker（任务执行）

```bash
go run . -mode worker
```

## 前端启动

### 本地开发

```bash
cd frontend
npm install
npm run dev
```

默认会代理 `/api` 到 `http://127.0.0.1:8080`。

若 API 不在该地址，可指定：

```bash
cd frontend
VITE_API_TARGET=http://127.0.0.1:8080 npm run dev
```

### Docker 启动前端

```bash
docker compose up -d frontend
```

注意：`frontend/nginx.conf` 当前会把 `/api` 代理到 `http://host.docker.internal:8080`，
因此 API 需要运行在宿主机 `8080` 端口。

## CLI 快速用法

### 扫描模式

```bash
# 完整扫描
go run . -mode scan -d example.com

# 完整扫描 + nuclei
go run . -mode scan -d example.com -nuclei

# 完整扫描 + nuclei + 高危 CORS（显式模块）
go run . -mode scan -m subs,httpx,ports,nuclei,cors -d example.com

# 完整扫描 + 主动子域名扩展
go run . -mode scan -d example.com -active-subs -dict-size 1500

# 仅子域名
go run . -mode scan -m subs -d example.com

# 仅端口链（输入子域名列表）
go run . -mode scan -m ports -i subdomains.txt -nuclei

# 仅截图（输入 URL 列表）
go run . -mode scan -m witness -i urls.txt
```

### 监控模式

```bash
# 开启监控
go run . -mode monitor -d example.com -monitor-interval 6h

# 列出监控目标
go run . -mode monitor -monitor-list

# 停止监控
go run . -mode monitor -monitor-stop example.com

# 删除监控数据
go run . -mode monitor -monitor-delete example.com
```

### Scan 数据管理

```bash
# 列出 scan 资产域名
go run . -mode scan -scan-list-domains

# 删除某根域名的全部数据
go run . -mode scan -scan-delete-domain example.com
```

## 常用参数

| 参数 | 说明 |
|---|---|
| `-mode` | `scan` / `monitor` / `web` / `worker` |
| `-web-addr` | API 监听地址（仅 `web` 模式） |
| `-project` | 项目 ID（CLI 扫描/监控隔离） |
| `-d` | 单个根域名 |
| `-dL` | 根域名文件 |
| `-i` | 输入文件（ports/witness） |
| `-m` | 模块：`subs,httpx,ports,witness,nuclei,cors,subtakeover,dnsx_bruteforce,bbot_active` |
| `-dry-run` | 只执行不入库 |
| `-nuclei` | 启用 nuclei |
| `-active-subs` | 启用主动子域名扩展 |
| `-dict-size` | 主动扩展字典大小上限 |
| `-dns-resolvers` | dnsx resolvers 文件 |
| `-notify` | 扫描任务结束通知（`scan` 模式） |
| `-monitor-interval` | 监控周期 |

## 通知行为说明

- `scan` 模式：任务结束后发送摘要通知（成功/失败/取消），受任务级 `notify` 和全局 `DINGTALK_WEBHOOK` 控制。
- `monitor` 模式：仅在检测到变更时发送通知，且有降噪冷却；目前由全局 `DINGTALK_WEBHOOK` 控制。
- `monitor` 通知内容包含：新资产 URL/标题/技术栈、端口变化（OPEN/CLOSED/CHANGED）摘要。

## 端口指纹显示说明

- 端口页与资产详情页会展示 `service/version`，端口页额外展示 `banner`。
- 后端会对 `naabu` 与 `nmap` 的端口结果做统一归一，尽量避免“同一端口分裂为两行（有指纹/无指纹）”。

## 关键 API（前端主要使用）

- `GET /api/projects`
- `DELETE /api/projects?id=<project_id>[&purge_data=1]`（`purge_data=1` 时彻底删除项目及其数据）
- `GET /api/dashboard/summary`
- `GET/POST /api/jobs`
- `POST /api/jobs/cancel`
- `GET /api/assets`
- `GET /api/ports`
- `GET /api/vulns`
- `GET /api/monitor/targets`
- `GET /api/monitor/runs`
- `GET /api/monitor/changes`
- `GET /api/screenshots/domains`
- `GET /api/screenshots/:rootDomain`

## 故障排查

### 1) 作业一直 `pending`

- 检查是否已启动 `go run . -mode worker`。

### 2) 前端报 CORS 403

- 检查 `CORS_ALLOWED_ORIGINS` 是否包含你的前端地址。
- 开发期可临时设置 `CORS_ALLOWED_ORIGINS=*`。

### 3) 扫描时报某工具 not found in PATH

- 说明对应二进制未安装或 PATH 未生效。
- 重新安装后重启终端/进程。

### 4) `shosubgo` 报错 `SHODAN_API_KEY` 未设置

- 设置 `SHODAN_API_KEY` 后再执行包含 shosubgo 的扫描。

### 5) 前端 Docker 能开但无数据

- `frontend` 容器默认代理到宿主机 `8080`，确认 API 正在该端口运行。

## 合规与安全

- 仅对授权范围内目标执行扫描。
- 漏洞结果是候选项，提交前请人工复现。

