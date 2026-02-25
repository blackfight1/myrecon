# Hunter - 资产搜集引擎

Hunter 是一个模块化的资产搜集引擎，采用流水线架构设计，支持插件化扩展。

## 🏗️ 架构设计

- **插件化设计**: 每个扫描工具都是独立的插件，易于扩展
- **流水线模式**: 支持将一个工具的输出作为下一个工具的输入
- **数据库存储**: 使用 PostgreSQL + GORM 进行数据持久化
- **实时反馈**: 扫描过程中实时显示进度和结果

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
│   │   └── httpx.go     # Httpx 存活检测插件
│   └── db/              # 数据库相关
│       ├── models.go    # 数据模型
│       └── database.go  # 数据库操作
├── main.go              # 主程序入口
├── query.go             # 数据库查询工具
├── go.mod               # Go 模块文件
├── docker-compose.yml   # PostgreSQL 容器配置
└── README.md            # 项目说明
```

## 🚀 快速开始

### 1. 环境准备

确保已安装以下工具：
- Go 1.21+
- Docker & Docker Compose
- subfinder
- samoscout
- subdog
- httpx

安装扫描工具：
```bash
# 安装 subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 安装 samoscout
go install -v github.com/samogod/samoscout@latest

# 安装 subdog
go install -v github.com/rix4uni/SubDog@latest

# 安装 httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

注意：如果某个工具未安装，程序会自动跳过该工具并继续执行。

### 2. 启动数据库

```bash
docker-compose up -d
```

### 3. 安装依赖

```bash
go mod tidy
```

### 4. 运行扫描

```bash
# 默认使用所有子域名搜集工具（Subfinder + Samoscout + Subdog）
go run main.go example.com
```

注意：如果某个工具未安装，会显示警告并自动跳过，不影响其他工具的执行。

## 🔧 核心功能

### Scanner 接口

所有扫描插件都实现统一的 Scanner 接口：

```go
type Scanner interface {
    Name() string
    Execute(input []string) ([]Result, error)
}
```

### 流水线执行

**第一阶段：并行子域名搜集**（自动去重）

1. **Subfinder 插件**: 搜集子域名
   - 调用 `subfinder -d domain.com -json`
   - 提取 JSON 中的 `host` 字段

2. **Samoscout 插件**: 搜集子域名
   - 调用 `samoscout -d domain.com -silent -json`
   - 过滤日志行，提取有效 JSON 中的 `host` 字段

3. **Subdog 插件**: 搜集子域名
   - 调用 `echo domain.com | subdog --silent`
   - 解析纯文本输出，每行一个域名
   - 自动去重

**第二阶段：存活检测**

4. **Httpx 插件**: 对所有发现的域名进行存活检测
   - 接收合并后的域名列表
   - 调用 `httpx -json -sc -title -td`
   - 实时解析 JSONL 输出

### 数据存储

Asset 模型包含以下字段：
- `domain`: 域名（唯一键）
- `url`: 完整 URL
- `ip`: IP 地址
- `status_code`: HTTP 状态码
- `title`: 页面标题
- `technologies`: 技术栈（JSONB 数组）
- `last_seen`: 最后发现时间

## 🔌 扩展插件

要添加新的扫描工具（如 Naabu、Nuclei），只需：

1. 在 `internal/plugins/` 目录创建新插件文件
2. 实现 `Scanner` 接口
3. 在 `main.go` 中添加到流水线

示例插件结构：
```go
type NewPlugin struct{}

func (n *NewPlugin) Name() string {
    return "NewTool"
}

func (n *NewPlugin) Execute(input []string) ([]engine.Result, error) {
    // 实现扫描逻辑
    return results, nil
}
```

## 📊 输出示例

```
🎯 开始扫描目标: example.com
📡 使用 Subfinder + Samoscout + Subdog 进行子域名搜集
🚀 启动扫描流水线...
[Subfinder] 正在搜集域名: example.com
[Subfinder] 发现 25 个域名
[Samoscout] 正在搜集域名: example.com
[Samoscout] 发现 32 个域名
[Subdog] 正在搜集域名: example.com
[Subdog] 发现 18 个域名
[Httpx] 正在对 62 个域名进行测活...（已自动去重）
[Httpx] 已发现 10 个存活服务
[Httpx] 测活完成，发现 20 个存活服务
💾 正在保存扫描结果到数据库...

==================================================
📊 扫描完成总结
==================================================
🎯 扫描目标: example.com
⏱️  扫描耗时: 45s
📈 数据库资产总数: 100 -> 115
🆕 本次新增资产: 15 个
💾 成功保存记录: 15 个

🔍 新发现的资产:
  • https://api.example.com [200] API Gateway
  • https://admin.example.com [200] Admin Panel
  ...
==================================================
✅ 扫描任务完成!
```

## 🛠️ 技术特性

- **错误处理**: 优雅处理工具缺失和执行错误，未安装的工具会自动跳过
- **实时进度**: 扫描过程中实时显示进度
- **数据去重**: 以域名为唯一键，自动更新重复记录
- **并发安全**: 支持并发扫描和数据库操作
- **可扩展性**: 插件化架构，易于添加新工具
- **智能跳过**: 如果某个工具未安装，自动跳过并继续使用其他工具