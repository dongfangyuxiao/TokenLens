# 春静企业代码安全平台 — 产品技术文档

**版本**：v2.2
**更新日期**：2026-03-27
**仓库地址**：https://github.com/dongfangyuxiao/SpringStillness

---

## 目录

1. [产品概述](#1-产品概述)
2. [整体架构](#2-整体架构)
3. [目录结构](#3-目录结构)
4. [核心模块详解](#4-核心模块详解)
5. [数据库设计](#5-数据库设计)
6. [REST API 参考](#6-rest-api-参考)
7. [扫描引擎工作流](#7-扫描引擎工作流)
8. [LLM 集成设计](#8-llm-集成设计)
9. [代码平台客户端](#9-代码平台客户端)
10. [通知与告警](#10-通知与告警)
11. [安全机制](#11-安全机制)
12. [部署与运维](#12-部署与运维)
13. [环境变量](#13-环境变量)
14. [依赖说明](#14-依赖说明)
15. [版本变更记录](#15-版本变更记录)
16. [2026-03-26 本次更新](#16-2026-03-26-本次更新)
17. [2026-03-27 本次更新](#17-2026-03-27-本次更新)

---

## 1. 产品概述

春静企业代码安全平台是面向企业研发团队的**自动化代码安全审计系统**，通过接入大语言模型（LLM）并整合 Semgrep 静态分析与 OpenSCA 软件成分分析，对多个代码托管平台的每次提交进行安全审计，实时发现注入漏洞、认证缺陷、供应链投毒等高危风险，并通过多渠道即时告警。

**核心设计原则**

- **轻量单体**：后端单进程，数据库为 SQLite，无外部中间件依赖，一条命令启动
- **无框架前端**：单 HTML 文件，原生 JS，零构建步骤
- **Prompt 驱动审计**：在 LLM Prompt 层面即区分扫描类型，LLM 从分析阶段就针对性工作
- **渐进降级**：无 LLM 配置时自动使用 Semgrep + OpenSCA，保证基础扫描能力

---

## 2. 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│                         浏览器                                │
│              static/index.html（单文件 SPA）                   │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTP REST API (Bearer Token)
┌────────────────────────────▼─────────────────────────────────┐
│                      FastAPI 应用层 (app.py)                   │
│                                                              │
│  ┌─────────────────┐   ┌─────────────────┐                   │
│  │  APScheduler    │   │  REST 路由层     │                   │
│  │  (Cron 任务)    │   │  /api/*         │                   │
│  └────────┬────────┘   └────────┬────────┘                   │
│           │                     │                            │
│           └──────────┬──────────┘                            │
│                      ▼                                       │
│              scanner.py（扫描协调器）                          │
│    ┌──────────────────────────────────────┐                  │
│    │           analyzer.py               │                  │
│    │  ┌─────────┐ ┌────────┐ ┌────────┐  │                  │
│    │  │   LLM   │ │Semgrep │ │OpenSCA │  │                  │
│    │  │(多提供商)│ │静态分析│ │成分分析│  │                  │
│    │  └─────────┘ └────────┘ └────────┘  │                  │
│    └──────────────────────────────────────┘                  │
│                                                              │
│              database.py（SQLite 数据访问层）                  │
│                      audit.db                                │
└──────────────────────────────────────────────────────────────┘
         │ API / Webhook
┌────────▼──────────────────────────────────────────────────┐
│       代码平台（GitHub / GitLab / Bitbucket / Gitee / ...）  │
└───────────────────────────────────────────────────────────┘
         │ 告警推送
┌────────▼──────────────────────────────────────────────────┐
│       通知渠道（钉钉 / 飞书 / 企业微信 / Slack / 邮件）       │
└───────────────────────────────────────────────────────────┘
```

---

## 3. 目录结构

```
SpringStillness/
├── app.py                  # FastAPI 应用入口，路由定义，定时调度
├── scanner.py              # 扫描协调器，拉取提交 → 分析 → 存储 → 通知
├── analyzer.py             # LLM / Semgrep / OpenSCA 分析引擎
├── database.py             # SQLite 数据访问层，DDL 与所有 CRUD
├── license_manager.py      # 产品授权签发 / 校验工具
├── repo_sync.py            # 全量扫描代码快照同步 + 跨仓库关键词检索
├── reporter.py             # 报告生成（Markdown / JSON / HTML）
├── sbom.py                 # 依赖清单解析（SCA 组件提取）
├── notifier.py             # 多渠道通知发送
├── syslog_sender.py        # Syslog UDP/TCP 转发
├── default_prompts.py      # 内置安全审计 Prompt 模板
├── requirements.txt        # Python 依赖
├── audit.db                # SQLite 数据库文件（运行时生成）
├── static/
│   └── index.html          # 前端单文件 SPA
├── reports/                # 生成的报告文件（运行时生成）
├── synced_repos/           # 全量扫描同步下来的仓库代码快照（运行时生成）
├── clients/
│   ├── github.py           # GitHub API 客户端
│   ├── gitlab.py           # GitLab API 客户端（含腾讯工蜂 / 阿里 Codeup）
│   ├── bitbucket.py        # Bitbucket API 客户端
│   ├── gitee.py            # Gitee API 客户端
│   ├── semgrep_scanner.py  # Semgrep 调用封装
│   └── opensca_scanner.py  # OpenSCA 调用封装
└── docs/
    ├── technical-document.md   # 本文档
    └── user-manual.md          # 产品使用手册
```

---

## 4. 核心模块详解

### 4.1 app.py — 应用入口

**职责**：FastAPI 应用初始化、鉴权中间件、REST 路由定义、APScheduler 定时任务管理。

**启动流程**：
1. `db.init_db()` — 初始化 SQLite 表结构，自动 ALTER TABLE 补全新列（向后兼容）
2. `db.mark_interrupted_scans()` — 将上次未正常结束的扫描（`running`/`paused`）标记为 `interrupted`
3. `syslog.reload()` — 加载 Syslog 配置
4. `_reschedule()` — 从数据库读取计划任务并注册到 APScheduler
5. `scheduler.start()` — 启动后台调度线程

**鉴权机制**：
- 登录接口返回随机 Bearer Token，存储在内存 `_sessions` 字典
- 所有 `/api/*` 接口通过 `require_auth` 依赖校验 Token
- 连续登录失败 5 次锁定 10 分钟

**计划任务**：
- 每个 `scan_schedules` 记录对应一个 APScheduler Cron Job
- 支持小时、天、周三种粒度，可绑定独立 `llm_profile_id`
- 服务重启后通过 `_reschedule()` 自动恢复

---

### 4.2 scanner.py — 扫描协调器

**职责**：按扫描类型拉取代码变更、去重、调用分析引擎、持久化结果、触发通知。

**扫描类型**：

| 类型 | 说明 | 分析目标 |
|------|------|---------|
| `poison` | 增量投毒扫描 | 所有分支，专注供应链攻击、恶意代码注入 |
| `incremental_audit` | 增量安全审计 | 近期提交变更，严重/高危漏洞 |
| `full_audit` | 全量安全审计 | main/master 主分支完整历史 |

**关键函数**：

```python
run_scan(base_url, scan_type, stop_event, pause_event, manual, llm_profile_id)
```

- `stop_event`：线程事件，置位时扫描中断
- `pause_event`：线程事件，清除时扫描暂停，直到再次置位
- `llm_profile_id`：指定使用哪个 LLM 配置，`None` 时使用系统默认

**文件去重逻辑（`_dedup_files_by_repo`）**：

同一仓库多次提交中对同一文件的多次变更，只保留最新提交的 patch，避免重复分析。API 按时间倒序返回提交（最新在前），遍历时首次出现即为最新版本。

**扫描控制**：
- 支持暂停 / 继续 / 停止，通过 `threading.Event` 实现
- 每处理一个提交前调用 `_check(stop_event, pause_event)` 检查状态

---

### 4.3 analyzer.py — 分析引擎

**职责**：构建 LLM 调用函数，对代码 patch 进行安全分析，整合 Semgrep / OpenSCA 静态扫描结果。

**LLM 提供商构建（`build_llm_caller`）**：
- Anthropic Claude：使用 `anthropic` SDK
- OpenAI 及兼容提供商（OpenAI / DeepSeek / 阿里通义 / 智谱 GLM 等）：使用 `openai` SDK，通过 `base_url` 区分
- 自动识别并抛出 `LLMQuotaExhausted` 异常（HTTP 402、429+quota、billing 相关错误信息）

**Prompt 路由**：
- `_find_prompt(filename, prompts)` 按文件扩展名匹配最合适的 Prompt 模板
- 找不到匹配模板时返回 `None`，跳过该文件

**并发分析（`analyze_commit`）**：
- 使用 `ThreadPoolExecutor` 并发分析同一提交内的多个文件
- `max_workers` 默认 4，可通过系统配置调整
- 每个文件返回 `(findings, summary)` 元组

**漏洞去重（指纹机制）**：
- 对每条漏洞生成 `fingerprint = hash(repo + file + title + description[:100])`
- 扫描时跳过已在白名单中的指纹

---

### 4.4 database.py — 数据访问层

**职责**：所有 SQLite 读写操作，DDL 定义，自动迁移。

**连接管理**：使用 `contextmanager` 包装的 `get_conn()`，自动提交/回滚。

**自动迁移**：`init_db()` 在每次启动时执行，使用 `PRAGMA table_info` 检查列是否存在，缺失则 `ALTER TABLE ADD COLUMN`，确保新版本数据库字段向后兼容。

---

### 4.5 reporter.py — 报告生成

生成三种格式报告：
- **Markdown**：适合 Webhook 消息正文
- **JSON**：适合系统间集成
- **HTML**：适合邮件发送（内联样式）

---

### 4.6 notifier.py — 通知发送

支持渠道：钉钉（签名验证）、飞书、企业微信、Slack、邮件（SMTP + SSL）。
所有渠道统一通过 `notify_all(scan_id, findings)` 触发，失败不影响主流程。

---

### 4.7 syslog_sender.py — Syslog 转发

支持 UDP / TCP 协议，将登录事件、扫描启动、漏洞发现等关键日志实时转发至外部 Syslog 服务器，便于接入 SIEM 系统。

`facility` 支持单值与多值（逗号分隔），多值模式会为每个 facility 创建独立 handler 并并行发送。

---

## 5. 数据库设计

数据库文件：`audit.db`（SQLite 3）

### 5.1 主要表结构

#### `admin_users` — 管理员账户
| 字段 | 类型 | 说明 |
|------|------|------|
| username | TEXT PK | 管理员用户名 |
| password_hash | TEXT | PBKDF2 哈希值 |
| salt | TEXT | 密码盐值 |

#### `accounts` — 代码平台账户
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| platform | TEXT | github / gitlab / bitbucket / gitee / tgit / codeup |
| name | TEXT | 显示名称 |
| token | TEXT | API Token |
| url | TEXT | 自定义平台地址 |
| owner | TEXT | 组织、群组、工作区或用户名 |
| created_at | TEXT | 创建时间 |

#### `channels` — 通知渠道
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| name | TEXT | 渠道名称 |
| type | TEXT | dingtalk / feishu / wecom / slack / email |
| config | TEXT | JSON 配置 |
| enabled | INTEGER | 是否启用（0/1） |
| created_at | TEXT | 创建时间 |

#### `llm_profiles` — LLM 配置档案
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| name | TEXT | 配置名称 |
| provider | TEXT | openai / anthropic / deepseek / ollama 等 |
| model | TEXT | 模型名称 |
| api_key | TEXT | API 密钥 |
| base_url | TEXT | 自定义接口地址 |

#### `scans` — 扫描记录
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| started_at | TEXT | 开始时间 |
| finished_at | TEXT | 结束时间 |
| status | TEXT | running / done / error / stopped / paused / interrupted |
| scan_type | TEXT | poison / incremental_audit / full_audit |
| total_commits | INTEGER | 本次分析的提交/聚合仓库数 |
| total_findings | INTEGER | 漏洞总数 |
| critical_count | INTEGER | 严重漏洞数 |
| high_count | INTEGER | 高危漏洞数 |
| medium_count | INTEGER | 中危漏洞数 |
| low_count | INTEGER | 低危漏洞数 |
| report_path | TEXT | HTML 报告路径 |
| error_msg | TEXT | 异常信息 |
| llm_profile_id | INTEGER | 使用的 LLM 配置（NULL = 系统默认） |

#### `repo_sync_status` — 代码快照同步状态
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| source | TEXT | 平台来源 |
| repo | TEXT | 仓库路径 |
| branch | TEXT | 同步分支（main/master） |
| commit_sha | TEXT | 对应提交 |
| local_path | TEXT | 本地同步路径 |
| file_count | INTEGER | 同步文件数 |
| last_scan_id | INTEGER | 最后一次同步所属扫描 |
| synced_at | TEXT | 同步时间 |

#### `component_inventory` — 软件成分清单
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| source | TEXT | 平台来源 |
| repo | TEXT | 仓库路径 |
| ecosystem | TEXT | 生态（pypi/npm/maven 等） |
| component | TEXT | 组件名 |
| version | TEXT | 版本或版本约束 |
| manifest_file | TEXT | 依赖清单文件路径 |
| raw_spec | TEXT | 原始依赖声明 |
| last_scan_id | INTEGER | 最后一次更新所属扫描 |
| updated_at | TEXT | 更新时间 |

#### `findings` — 漏洞记录
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| scan_id | INTEGER FK | 所属扫描 |
| repo | TEXT | 仓库名 |
| commit_sha | TEXT | 提交 SHA |
| commit_url | TEXT | 提交链接 |
| author | TEXT | 提交作者 |
| committed_at | TEXT | 提交时间 |
| severity | TEXT | critical / high / medium / low |
| type | TEXT | 漏洞类型 |
| title | TEXT | 漏洞标题 |
| filename | TEXT | 文件路径 |
| line | TEXT | 行号 |
| description | TEXT | 漏洞描述 |
| recommendation | TEXT | 修复建议 |
| status | TEXT | new / fixing / fixed / wont_fix |
| fingerprint | TEXT | 去重指纹 |
| is_cross_file | INTEGER | 是否跨文件漏洞 |
| cross_files | TEXT | 关联文件列表（JSON） |

#### `scan_repos` / `scan_logs` / `repo_owners`
| 表名 | 说明 |
|------|------|
| `scan_repos` | 每次扫描按仓库汇总的严重级别统计 |
| `scan_logs` | 扫描执行日志，供前端日志弹窗查看 |
| `repo_owners` | 仓库负责人映射，漏洞详情中展示责任人信息 |

#### `scan_schedules` — 计划任务
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| type | TEXT | poison / incremental_audit / full_audit |
| hour | INTEGER | 小时（-1 = 每小时） |
| minute | INTEGER | 分钟 |
| weekday | INTEGER | 星期几（0-6，NULL = 每天） |
| enabled | INTEGER | 是否启用 |
| label | TEXT | 显示标签 |
| llm_profile_id | INTEGER | 绑定的 LLM 配置 |

#### `finding_whitelist` — 漏洞白名单
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| repo | TEXT | 仓库名（空 = 通配） |
| filename | TEXT | 文件路径（空 = 通配） |
| title | TEXT | 漏洞标题（空 = 通配） |
| reason | TEXT | 加入白名单原因 |
| created_by | TEXT | 操作人 |
| created_at | TEXT | 创建时间 |

#### `app_config` / `llm_config` / `syslog_config`
| 表 | 说明 |
|----|------|
| `app_config` | 系统参数，如 `max_diff_chars`、`scan_include_config_files`、`opensca_token`、`semgrep_token`、`license_key`、`license_enforce_enabled` |
| `llm_config` | 系统默认 LLM 配置（`provider/model/api_key/base_url`） |
| `syslog_config` | Syslog 主机、端口、协议、facility（支持多值）和 app_name |

#### `prompts` — Prompt 模板
| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER PK | 自增主键 |
| name | TEXT | 模板名称 |
| category | TEXT | frontend / backend / contract / custom |
| extensions | TEXT | 匹配扩展名 |
| content | TEXT | Prompt 正文 |
| is_default | INTEGER | 是否内置模板 |
| enabled | INTEGER | 是否启用 |
| created_at | TEXT | 创建时间 |

---

## 6. REST API 参考

所有接口（登录除外）需在请求头携带：
```
Authorization: Bearer <token>
```

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/login` | 登录，返回 token |
| POST | `/api/logout` | 登出 |
| GET | `/api/me` | 获取当前用户信息 |

### 代码平台账户

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/accounts` | 获取账户列表 |
| POST | `/api/accounts` | 添加账户 |
| DELETE | `/api/accounts/{id}` | 删除账户 |
| POST | `/api/accounts/test` | 测试连通性 |

### LLM 配置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/llm-profiles` | 获取 LLM 配置列表 |
| POST | `/api/llm-profiles` | 添加 LLM 配置 |
| PUT | `/api/llm-profiles/{id}` | 更新 LLM 配置 |
| DELETE | `/api/llm-profiles/{id}` | 删除 LLM 配置 |
| POST | `/api/llm-profiles/{id}/test` | 测试 LLM 连通性 |
| GET | `/api/llm-config` | 获取系统默认 LLM 配置 |
| POST | `/api/llm-config` | 设置系统默认 LLM 配置 |

### 扫描控制

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/scan/trigger` | 手动触发扫描 |
| POST | `/api/scan/stop` | 停止当前扫描 |
| POST | `/api/scan/pause` | 暂停当前扫描 |
| POST | `/api/scan/resume` | 继续扫描 |
| GET | `/api/status` | 获取当前扫描状态与计划摘要（含实时 `progress` 百分比） |
| GET | `/api/scans` | 获取扫描历史列表 |
| DELETE | `/api/scans/{id}` | 删除扫描记录 |
| POST | `/api/scans/{id}/rerun` | 重新执行某次扫描 |
| GET | `/api/scans/{id}/findings` | 获取某次扫描的漏洞列表 |
| GET | `/api/scans/{id}/logs` | 获取某次扫描的执行日志 |
| GET | `/api/scans/{id}/export?format=json|markdown|docx` | 导出扫描结果 |

### SCA 与应急排查

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/repo-sync-status` | 查看全量扫描代码快照同步状态 |
| GET | `/api/components` | 查询组件清单（支持关键词/仓库/来源过滤） |
| GET | `/api/components/summary` | 组件聚合统计 |
| POST | `/api/emergency/dependency-check` | 应急依赖排查（模糊/精确） |
| POST | `/api/emergency/code-search` | 全代码库关键词检索（如 `swagger.html`） |

### 漏洞管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/findings/{id}` | 获取漏洞详情 |
| PATCH | `/api/findings/{id}/status` | 更新漏洞状态 |

### 计划任务

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/scan-schedules` | 获取计划列表 |
| POST | `/api/scan-schedules` | 添加计划 |
| PATCH | `/api/scan-schedules/{id}` | 启停计划 |
| DELETE | `/api/scan-schedules/{id}` | 删除计划 |

### 即时检测

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/analyze/instant` | 提交代码片段审计 |
| POST | `/api/analyze/instant-upload` | 上传文件 / ZIP 审计 |

### 通知渠道

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/channels` | 获取渠道列表 |
| POST | `/api/channels` | 添加渠道 |
| PUT | `/api/channels/{id}` | 更新渠道 |
| DELETE | `/api/channels/{id}` | 删除渠道 |
| POST | `/api/channels/{id}/test` | 发送测试消息 |

### 系统配置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/settings` | 获取系统配置 |
| POST | `/api/settings` | 更新系统配置 |
| GET | `/api/license-status` | 获取产品授权状态 |
| POST | `/api/license-config` | 保存授权码与授权拦截开关 |
| GET | `/api/license/machine-file` | 下载当前实例机器码文件（JSON） |
| POST | `/api/license/upload-file` | 上传授权文件并应用 |
| POST | `/api/license/generate-file` | 按机器码生成授权文件并下载 |
| GET | `/api/admin-users` | 用户列表 |
| POST | `/api/admin-users` | 创建用户 |
| PATCH | `/api/admin-users/{username}/password` | 修改密码 |
| DELETE | `/api/admin-users/{username}` | 删除用户 |
| GET | `/api/syslog-config` | 获取 Syslog 配置 |
| POST | `/api/syslog-config` | 保存 Syslog 配置 |
| POST | `/api/syslog-test` | 测试 Syslog 连通性 |

---

## 7. 扫描引擎工作流

```
触发扫描（定时 / 手动）
        │
        ▼
create_scan() → 写入 scans 表，status='running'
        │
        ▼
按已启用的代码账户依次拉取变更
  ├── GitHub: /repos/{owner}/{repo}/commits → /commits/{sha}
  ├── GitLab: /projects/{id}/repository/commits
  ├── Bitbucket: /repositories/{workspace}/{repo}/commits
  └── Gitee: /repos/{owner}/{repo}/commits
        │
        ▼
_dedup_files_by_repo()  — 同仓库多提交文件去重
        │
        ▼
对每个提交（去重后）调用 analyze_commit()
  ├── 过滤二进制/非代码文件
  ├── ThreadPoolExecutor 并发分析每个文件
  │    ├── [有LLM] 构建 Prompt → 调用 LLM API → 解析 JSON 响应
  │    ├── [有Semgrep] 调用 semgrep_scan(patch)
  │    └── [有OpenSCA] 调用 opensca_scan(patch)
  └── 合并去重漏洞列表
        │
        ▼
白名单过滤（指纹匹配）
        │
        ▼
save_findings() → 写入 findings 表
        │
        ▼
update_scan_status(scan_id, 'done')
        │
        ▼
notify_all() → 发送告警通知
        │
        ▼
syslog.send_event('scan_completed', ...)
```

---

## 8. LLM 集成设计

### 8.1 提供商支持矩阵

| 提供商 | SDK | base_url 示例 |
|--------|-----|---------------|
| OpenAI | openai | `https://api.openai.com/v1` |
| Anthropic Claude | anthropic | — |
| DeepSeek | openai compat | `https://api.deepseek.com/v1` |
| 阿里通义千问 | openai compat | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| 智谱 GLM | openai compat | `https://open.bigmodel.cn/api/paas/v4` |
| 月之暗面 Kimi | openai compat | `https://api.moonshot.cn/v1` |
| 字节豆包 | openai compat | `https://ark.cn-beijing.volces.com/api/v3` |
| Ollama（本地） | openai compat | `http://localhost:11434/v1` |
| 自定义 | openai compat | 任意 |

### 8.2 额度耗尽处理

`LLMQuotaExhausted` 异常在以下条件触发：
- HTTP 状态码 402
- HTTP 状态码 429 且 error.code 包含 "quota"
- 错误信息包含：`insufficient_quota` / `exceeded your current quota` / `credit balance` / `billing` / `payment`

触发后扫描任务自动切换为 `paused`，等待人工恢复，避免持续无效调用消耗配额。

### 8.3 Prompt 设计

内置三类 Prompt（`default_prompts.py`），在 LLM 分析阶段即明确任务：
- **投毒检测 Prompt**：专注后门、恶意依赖、异常外联
- **增量审计 Prompt**：专注 RCE、SQL 注入、认证绕过、SSRF 等高影响漏洞
- **全量审计 Prompt**：全覆盖 OWASP Top 10 及供应链风险

返回格式要求 LLM 输出结构化 JSON：
```json
{
  "findings": [
    {
      "title": "漏洞标题",
      "severity": "critical|high|medium|low",
      "description": "详细描述",
      "recommendation": "修复建议",
      "file": "文件路径",
      "line": 42
    }
  ]
}
```

---

## 9. 代码平台客户端

所有客户端统一返回格式：
```python
[{
    "repo": str,          # 仓库名
    "source": str,        # 平台标识
    "commit_sha": str,
    "commit_url": str,
    "author": str,
    "message": str,
    "files": [{"filename": str, "patch": str}]
}]
```

### 请求频率限制处理
- 遇到 HTTP 429 自动等待 `Retry-After` 秒（或默认 60s）后重试
- 遇到 HTTP 401/403 记录错误并跳过该账户
- 网络超时默认 30s

---

## 10. 通知与告警

### 消息格式

所有渠道推送包含：
- 扫描类型与时间
- 各严重级别漏洞计数（critical / high / medium / low）
- Top 5 高危漏洞摘要（仓库 + 文件 + 标题）
- 平台跳转链接（`BASE_URL`）

### 钉钉签名

钉钉机器人开启安全签名时，使用 `timestamp + "\n" + secret` 的 HMAC-SHA256 签名，附加在 Webhook URL query 参数中。

---

## 11. 安全机制

| 机制 | 实现 |
|------|------|
| 身份认证 | Bearer Token（随机 32 字节十六进制），内存存储 |
| 登录防爆破 | 5 次失败锁定 10 分钟 |
| 密码强度 | 最低 8 位，含大小写字母及数字 |
| 密码存储 | bcrypt 哈希（不存储明文） |
| API 访问控制 | 所有 `/api/*` 接口强制 Bearer Token 校验 |
| Syslog 审计 | 关键操作实时转发至外部日志系统 |
| SQL 注入防护 | 全部使用参数化查询，无字符串拼接 SQL |

> **注意**：Token 存储于服务进程内存，重启后所有会话失效，用户需重新登录。如需持久化会话，建议在反向代理层（Nginx）配置 HTTPS 并调整 Token 存储策略。

---

## 12. 部署与运维

### 12.1 最小化部署

```bash
git clone https://github.com/dongfangyuxiao/SpringStillness.git
cd SpringStillness
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 12.2 生产部署建议

**使用 systemd 管理进程**：
```ini
[Unit]
Description=春静代码安全平台
After=network.target

[Service]
WorkingDirectory=/opt/SpringStillness
ExecStart=/usr/bin/uvicorn app:app --host 0.0.0.0 --port 8000 --workers 1
Restart=on-failure
RestartSec=5
Environment=BASE_URL=https://your-domain.com

[Install]
WantedBy=multi-user.target
```

**Nginx 反向代理**：
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # SSE 日志流需要禁用缓冲
        proxy_buffering off;
    }
}
```

### 12.3 Semgrep 安装（可选）

```bash
pip install semgrep
# 或
brew install semgrep
```

安装后系统自动检测并启用 Semgrep 静态分析。

### 12.4 数据备份

数据库为单文件 `audit.db`，直接复制即可备份：
```bash
cp audit.db audit.db.bak.$(date +%Y%m%d)
```

---

## 13. 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `BASE_URL` | 通知消息中的平台跳转地址 | `http://localhost:8000` |
| `LICENSE_SECRET` | 授权签名密钥，签发与校验必须一致 | `springstillness-dev-license-secret` |
| `PRODUCT_INSTANCE_ID` | 手工指定实例 ID；未设置时自动根据主机信息生成 | 自动生成 |

---

## 14. 依赖说明

| 包 | 版本 | 用途 |
|----|------|------|
| fastapi | 0.110.0 | Web 框架 |
| uvicorn[standard] | 0.27.0 | ASGI 服务器 |
| openai | ≥1.55.0 | OpenAI 及兼容提供商 SDK |
| anthropic | ≥0.40.0 | Anthropic Claude SDK |
| requests | 2.31.0 | 代码平台 API 请求 |
| apscheduler | 3.10.4 | 定时任务调度 |
| jinja2 | 3.1.4 | 报告模板渲染 |
| python-multipart | 0.0.9 | 文件上传支持 |

---

## 15. 版本变更记录

### v2.1（2026-03-26）

**新增**
- 产品授权模块 `license_manager.py`，支持 HMAC-SHA256 授权码签发与校验
- 系统设置新增授权码录入、授权文件上传、机器码文件下载、实例 ID 展示、授权状态查看与授权校验开关
- 新增 `/api/license-status`、`/api/license-config`、`/api/license/machine-file`、`/api/license/upload-file`、`/api/license/generate-file` 授权接口
- 新增授权临期提醒、界面授权水印，以及基于 `features` 的能力控制

**说明**
- 当前版本默认不启用授权拦截，仅提供配置和联调能力
- 当后续手动开启授权校验后，扫描触发、重新扫描与即时分析接口会执行授权状态检查
- 若授权载荷未声明 `features`，则视为全功能授权；声明后将仅放行列出的能力

### v2.0（2026-03-26）

**新增**
- 多 LLM 配置档案（`llm_profiles` 表），每个计划任务可绑定独立 LLM
- 计划任务 `llm_profile_id` 字段支持
- 服务启动时自动修复异常中断的扫描记录（`mark_interrupted_scans`）
- 多提交同一文件去重逻辑（`_dedup_files_by_repo`）
- LLM 额度耗尽精准识别（`LLMQuotaExhausted` 异常）
- `findings` 表新增跨文件漏洞字段（`is_cross_file` / `cross_files`）
- 深色科技安全控制台主题与响应式布局优化

**优化**
- 计划任务调度器重构，消除冗余函数，支持动态 LLM 绑定
- 代码平台客户端请求健壮性增强（429 重试、错误隔离）
- 管理员删除与报告导出边界行为修复

---

## 16. 2026-03-26 本次更新

本次更新覆盖了授权能力、稳定性修复、前端视觉重构和文档对齐：

- 新增产品授权模块，支持 HMAC-SHA256 授权码签发、实例 ID 绑定、后台录入与状态校验
- 新增授权临期提醒、顶部授权状态胶囊、右下角授权水印，以及按 `features` 控制功能点
- 默认不启用授权拦截，授权联调可先上线配置，再按需开启校验

- 修复服务启动时误删指定管理员账户的硬编码逻辑
- 修复管理员删除接口的错误返回不准确问题
- 修复无漏洞扫描记录无法导出报告的问题
- 前端单文件 SPA 升级为深色科技安全控制台风格，并补齐移动端自适应布局
- 恢复 Light / Dark 双主题切换，并补齐代码库配置、扫描历史、漏洞统计、提示词、账户管理、系统设置等页面的浅色样式
- 继续收紧视觉体系，压低粉色/绿色倾向，增强登录页冷色氛围、左侧导航和概览页的控制台层次
- 技术文档、使用手册、README 与更新日志同步校正数据库表名、API 路径、系统设置项和当前实现说明

## 17. 2026-03-27 本次更新

- LLM 配置统一为新版字段：`provider/model/api_key/base_url`
- 已移除旧版 `deepseek_api_key` / `anthropic_api_key` 的前后端展示与保存逻辑
- AI 配置支持本地模型与云端模型统一多模型管理
- 投毒检测、增量审计、全量审计均支持手动触发和计划任务绑定独立 `llm_profile_id`
- 修复扫描记录创建时未写入 `llm_profile_id` 的问题
- 新增全量扫描代码快照同步（`synced_repos/`）与同步状态表（`repo_sync_status`）
- 新增软件成分清单表（`component_inventory`）与组件查询接口
- 新增应急排查接口：恶意依赖检测与全代码库关键词检索

### v1.0（初始版本）

- 基础 LLM 审计引擎（OpenAI / Anthropic）
- GitHub / GitLab / Bitbucket / Gitee 四平台支持
- 三类扫描模式（投毒 / 增量审计 / 全量审计）
- APScheduler 定时调度
- 多渠道通知（钉钉 / 飞书 / 企业微信 / Slack / 邮件）
- Syslog 转发
- 漏洞白名单与状态管理
- 即时检测（代码粘贴 / ZIP 上传）
