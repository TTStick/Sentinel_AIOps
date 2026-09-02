# 参考文档

**核心架构**: 客户端 → 中心服务端 → 大模型（Agent 采集 + 多租户中心化分析 + 可插拔 LLM 按任务复杂度路由决策）

---

## 0. 技术栈（分组）

| 分类 | 具体技术 |
| --- | --- |
| **操作系统** | Linux（Ubuntu / Debian / CentOS）；开发环境 Windows + WSL2 |
| **开发工具** | Uvicorn、Systemd、venv、Git |
| **编程语言** | Python、JavaScript (ES6+)、HTML5、CSS3、SQL |
| **数据库** | SQLite（标准库 sqlite3，WAL 模式、线程局部连接） |
| **开发框架 / 库** | FastAPI、Starlette、Jinja2、Pydantic、paramiko、cryptography（Fernet / PBKDF2）、requests、psutil、Chart.js、xterm.js |
| **人工智能** | 大语言模型（LLM）应用集成、模型路由（快速 / 强力双档）、Prompt 工程、JSON 结构化输出、AIOps（根因分析 · 自适应异常检测 · 容量预测 · 命令风险研判 · 会话摘要 · ChatOps · AI 调查）；接入 Ollama、DeepSeek、通义千问 Qwen、硅基流动 SiliconFlow、OpenAI 兼容接口 |

> 前端为**零构建**的原生 HTML/CSS/JS（Jinja2 服务端渲染 + 轮询），未使用 Tailwind / 打包器；界面采用「暖纸 Warm Paper」风格（思源宋体标题 + 陶土色强调）。

---

## 1. 部署指南

系统分为 **被监控端 (Agent)** 与 **中心服务端 (Server)** 两部分。

### A. 环境准备

- **操作系统**: Linux（Ubuntu / CentOS / Debian）
- **Python**: 3.10+（推荐 3.11 / 3.12）
- **AI 依赖（可选）**: 默认内置离线规则引擎即可运行；如需本地模型，安装 [Ollama](https://ollama.com/) 并 `ollama pull`（如 `qwen2.5:7b`）。在线模型（DeepSeek / Qwen / 硅基流动等）无需本地依赖，登录后在网页「模型设置」里配置即可。

### B. 服务端 (Server) 部署

1. **安装依赖**：

   ```bash
   pip install -r requirements.txt
   # 即：fastapi uvicorn[standard] jinja2 python-multipart paramiko requests websockets
   #（cryptography 由 paramiko 自动带入，用于凭据/Key 加密）
   ```

2. **启动服务**：

   ```bash
   # 在 sentinel-ai 根目录下
   ./run.sh
   # 或手动指定端口：
   python -m uvicorn server.app:app --app-dir src --host 0.0.0.0 --port 8000
   ```

   - 默认监听端口 **8000**（可用 `SENTINEL_PORT` 或 `--port` 修改）。
   - 默认超级管理员 **admin / admin123**，**首次登录强制改密**。
   - 默认 LLM = `mock`（离线规则引擎），可在网页「模型设置」中切换真实模型。

3. **配置 AI 模型（网页，推荐）**：

   以管理员登录 → 左侧 **「模型设置」** → 选供应商（自动填好接口地址）→ 填 Key 与模型名 → 「测试连接」→ 保存。无需改任何代码或环境变量（详见 §4 第四阶段）。

### C. 客户端 (Agent) 部署

1. **配置 Server 地址**（通过环境变量，无需改源码）：

   ```bash
   export AIZ_SERVER_URL="http://192.168.1.100:8000/api/report"
   export AIZ_AGENT_TOKEN="sk-secure-token-123456"   # 与服务端一致
   export AIZ_INTERVAL=10                              # 采集上报间隔（秒）
   ```

2. **一键安装（推荐）**：

   ```bash
   cd agent
   chmod +x install.sh
   sudo ./install.sh
   ```

   *脚本会安装依赖（`psutil`, `requests`），并注册为 Systemd 服务 `aiz-agent`。*

3. **验证状态**：

   ```bash
   systemctl status aiz-agent
   journalctl -u aiz-agent -f
   ```

---

## 2. 项目结构

```
aiz-ops-platform/
├── src/
│   ├── server/                     # 服务端（FastAPI + SQLite + Jinja）
│   └── agent/                      # 主机采集 Agent
├── document/                       # 说明文档
├── test/                           # 测试脚本
├── agent/                          # [客户端] 部署在每台被监控主机
│   ├── main.py                     # 采集 + 正则预处理 + 上报调度
│   ├── install.sh                  # 自动化部署脚本
│   └── service/
│       └── aiz-agent.service       # Systemd 服务描述文件
├── server/                         # [服务端] 中心控制节点
│   ├── app.py                      # FastAPI 入口（装配路由 / 启动初始化 / 后台预测）
│   ├── config.py                   # 配置中心（环境变量可覆盖）
│   ├── database.py                 # SQLite 建表与连接（WAL、线程局部）
│   ├── models.py                   # 数据访问层 + settings_kv 配置存取
│   ├── auth.py                     # 会话鉴权 / RBAC 权限判定
│   ├── security.py                 # 口令哈希(PBKDF2) + 凭据加密(Fernet)
│   ├── analysis.py                 # EWMA 自适应基线 + z-score 异常 + 综合负载/健康度 + 容量预测
│   ├── cmd_guard.py                # WebSSH 命令风险护栏（safe/caution/dangerous）
│   ├── webssh.py                   # paramiko SSH 通道
│   ├── audit.py                    # 审计记录 + AI 摘要增强
│   ├── llm_engine.py               # 可插拔 LLM + 任务路由（OpenAI 兼容 / Ollama / mock 兜底）
│   ├── llm_config.py               # 模型路由配置中心（供应商预设 / 加密 Key / 档位解析）
│   ├── routes/                     # 各业务 API 路由（report/auth/hosts/admin/audit/dashboard/ai/ssh/settings/pages）
│   ├── templates/                  # 多页面前端（dashboard/hosts/host_detail/webssh/audit/investigations/chatops/admin/me/settings/login）
│   └── static/                     # app.css（暖纸主题）+ app.js（轮询/图表/组件）
├── requirements.txt
├── run.sh
└── README.md
```

---

## 3. 权限模型（多租户 RBAC）

- **超级管理员（superadmin）**：管理用户、主机分配、模型设置，可见全部数据。
- **普通用户**：仅能看到/操作被授权的主机；主机授权分 `view`（只读）/ `operate`（可运维）/ `admin`（可再分配）三级。
- 会话基于签名 Cookie（`sid`），口令以 PBKDF2 加盐哈希；SSH 凭据与模型 API Key 均以 Fernet 加密落库。所有写操作进审计。

---

## 4. 技术实现

数据从采集、正则分析、上报到可视化与 AI 决策的全链路流程。

### 第一阶段：全栈数据采集

Agent 每 **10 秒**（`AIZ_INTERVAL` 可调）执行一次 `collect()`，采集：

1. **硬资源指标**（`psutil`）：CPU 使用率、物理内存、Swap、根分区磁盘、网络进出流量字节数。
2. **内核与系统级深层检测**：
   - **I/O Wait**：`cpu_times_percent().iowait`，**> 25%** 标记磁盘瓶颈。
   - **僵尸进程**：遍历 `process_iter()`，状态为 `Z` 的进程 **> 5** 标记进程泄露风险。
   - 进程总数 / 运行数 / 僵尸数一并上报。

### 第二阶段：日志分析与正则预处理

为避免上传垃圾日志，Agent 本地先做**正则预过滤**（`re.IGNORECASE`）。

**A. SSH 爆破审计**：读取 SSH 服务最近日志，正则统计 `Failed password` 次数，**> 5** 生成异常「SSH 暴力破解」。

**B. 应用 / 系统故障指纹库**：

| 故障类型 | 正则表达式 | 异常描述 |
| --- | --- | --- |
| 服务拒绝连接 | `connection refused` | 连接被拒绝（服务可能已宕） |
| 网络超时 | `connection timed out` | 网络连接超时 |
| 数据库慢查询 | `slow query` | 数据库慢查询 |
| 数据库死锁 | `deadlock` | 数据库死锁 |
| 内存溢出 | `out of memory｜oom-kill` | OOM 内存耗尽 |
| 段错误 | `segfault` | 进程段错误 |
| 磁盘错误 | `i/o error｜read-only file system` | 磁盘 I/O 错误 |

> 命中任意一条则该次上报 `is_danger=True`，并附带相关日志片段（仅在有异常时携带日志正文）。

### 第三阶段：传输

**协议** HTTP，**格式** JSON，发往 `http://{server}:8000/api/report`。

- **Header**：`Authorization: Bearer <AIZ_AGENT_TOKEN>`（服务端按令牌定位主机）。
- **Payload**：

  ```json
  {
    "hostname": "db-server-01",
    "metrics": { "cpu": 15.5, "memory_pct": 62.0, "swap_pct": 80.0,
                 "disk_pct": 91.0, "iowait": 30.2, "proc_zombie": 7, "...": "..." },
    "anomalies": ["IO Wait 偏高，磁盘可能瓶颈", "SSH 暴力破解"],
    "logs": "Jan 19 10:00:01 sshd[123]: Failed password for root...",
    "is_danger": true
  }
  ```

### 第四阶段：服务端处理与 AI 介入

`server/routes/report.py` + `server/analysis.py`

1. **自适应异常检测**：每个指标维护 **EWMA 均值/方差**，用 **z-score** 判定「相对该主机历史」的异常（叠加固定阈值规则、Agent 上报异常与日志特征），自适应不同主机的基线。

2. **综合负载计算**（加权）：

   ```
   Score = CPU*0.34 + MEM*0.26 + SWAP*0.15 + DISK*0.10 + IOWait*0.15
   ```

3. **健康度评分**：从 100 起，对 CPU/内存/磁盘/Swap/IOWait 超过 70 的部分按权重扣分，得到 0–100 健康度。

4. **风险分级**：
   - **Normal**：无异常且健康度良好。
   - **Warning**：存在 `warning` 级异常或健康度 < 70。
   - **Critical**：存在 `critical` 级异常或健康度 < 40。

5. **AI 异步决策（The Brain）**：当 `is_danger=True` 或风险为 `Critical`，经 FastAPI `BackgroundTasks` **异步非阻塞**调用大模型（**强力档**），把 `Metrics + Anomalies + Raw Logs` 填入 Prompt，要求返回 JSON 的**根因分析 + 解决方案**，结果落库并进审计。任何模型失败自动降级到离线规则引擎。

6. **容量预测**：对磁盘等指标做线性回归，估算每日增速与「触顶剩余时间」，后台定时刷新。

> **模型路由（网页「模型设置」）**：AI 任务分两档——
> **快速档**（会话摘要 / 命令解释 / 命令风险注释 / ChatOps / SSH 建议）与
> **强力档**（根因分析 / AI 调查计划与结论 / 修复建议）。
> 路由方式可选 `智能路由（按复杂度）`、`始终强力`、`始终快速`、`离线规则`。
> 供应商内置 **DeepSeek、通义千问 Qwen（百炼兼容）、硅基流动 SiliconFlow、本地 Ollama、OpenAI 兼容网关** 预设，统一走 OpenAI 兼容 `/chat/completions`；API Key 以 Fernet 加密存储、前端只显示「已配置」、保存/测试均进审计（不记录 Key）。

### 第五阶段：交互式运维与可视化

多页面 Jinja 应用 + 原生 JS 轮询（暖纸主题，Chart.js / xterm.js）：

1. **总览大屏 (`dashboard`)**：Chart.js 渲染 Normal/Warning/Critical 机器比例与异常趋势；AI 分析简报流。
2. **主机列表与详情 (`hosts` / `host_detail`)**：综合负载条与状态徽章按 `risk_level` 变色（绿/黄/红）；详情页展示四维指标、自适应异常、容量预测与 AI 处理建议，右侧原始日志回放辅助人工复核。
3. **WebSSH (`webssh`)**：基于 paramiko 的浏览器终端（xterm.js），命令经**风险护栏**(safe/caution/dangerous)研判，内置 **AI 命令建议**，会话结束生成 **AI 摘要**，全程命令落审计。
4. **AI 调查 (`investigations`)**：AI 调查员提议只读诊断计划 → **人工批准** → 执行 → 给出根因与修复建议（修复需二次人工确认），形成「AI 提方案、人把关」的闭环。
5. **ChatOps (`chatops`)**：自然语言查询平台数据，由模型据检索到的结构化证据作答。
6. **审计回溯 (`audit`)**：每条操作可追溯，附 AI 一句话摘要与解释。
7. **管理与设置 (`admin` / `settings` / `me`)**：用户与主机分配、模型路由配置、个人改密。

---

> **说明**：`mock` 离线规则引擎为规则化输出，仅供离线演示与兜底；要获得高质量根因分析与建议，请在「模型设置」接入真实大模型。所有 AI 调用失败都会自动降级回 `mock`，绝不阻塞运维主流程。
