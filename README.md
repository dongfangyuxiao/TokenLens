# 探云令 TokenLens

## 项目简介

探云令 TokenLens是一款面向企业研发团队的**自动化代码安全审计平台**。通过接入大语言模型（LLM），结合 Semgrep 静态分析与 OpenSCA 软件成分分析，对代码仓库的每一次提交进行安全审计，实时发现注入、认证绕过、供应链投毒等高危风险，并通过钉钉、飞书、企业微信、邮件等渠道即时告警。

## 最近更新

### 2026-03-30

- 新增多模型交叉审计链：手动触发、计划任务、历史重跑均支持同时绑定多个 `llm_profile_ids`
- 交叉审计展示改为 `审计模型 / 检查模型 / 验证模型` 三段式配置，可分别选择一个或多个模型
- `analyzer.py` 支持多模型逐文件复核与跨文件复核，并按共识策略合并结果
- 多模型非单模型策略下，系统会把共识确认过的结果自动沉淀为 adaptive skills，并在后续同类语言/任务扫描中注入 prompt
- 扫描配置新增“根据审计结果优化对应 skills”开关，开启后会基于三段式联合校验结果自动优化已有 skills
- AI 配置新增勾选项“启用多模型联合校验后自动优化 skills”，只有勾选该选项的模型参与联合校验时才会触发 skills 自动调整
- 内置提示词扩展为多语言专项 skills，新增 `Java / PHP / Python / Go / Node.js / C# / Ruby / Rust / C/C++`
- 参考 DVWA 官方模块目录补齐能力项，对齐 `authbypass / bac / cryptography / csp / open_redirect / weak_id / api` 等场景
- 扫描计划页和手动触发弹窗已支持多模型链与复核策略配置
- 扫描记录与计划任务表结构新增 `llm_profile_ids`、`llm_consensus_mode`，兼容旧版 `llm_profile_id`

### 2026-03-27

- 即时分析（粘贴/上传）支持选择 AI 模型；上传接口鉴权已修复，避免会话误判失效
- 扫描执行改为仓库级流式处理（拉一个仓库扫一个），并在扫描中实时刷新漏洞数据
- 扫描状态新增进度百分比展示（顶部状态栏与概览同步显示）
- 扫描历史支持运行中/暂停中查看“实时漏洞”并自动刷新
- 代码库配置新增仓库列表区块；全量审计后自动清理已失效仓库
- 应急排查（SCA/关键字检索）结果改为分页展示，并支持每页 20/50/100 切换
- 系统设置新增“配置文件检测”开关（默认关闭）；关闭时配置文件不送检
- Syslog Facility 支持多选，并改为“应用日志/系统服务/认证授权”等可读说明

### 2026-03-26

- AI 配置统一为新版字段（`provider/model/api_key/base_url`），已移除旧版 `deepseek_api_key` / `anthropic_api_key` 前后端显示与保存逻辑
- 支持本地模型（Ollama）与云端模型统一配置为多模型列表，并在扫描时按任务选择
- 投毒检测、增量审计、全量审计均支持手动触发和计划任务绑定独立模型（`llm_profile_id`）
- 全量审计新增主分支快照同步：每次 full audit 会将各仓库 `main/master` 同步到本地 `synced_repos/`
- 新增软件成分分析（SCA）组件清单入库，支持按组件/仓库/来源查询
- 新增应急排查能力：支持恶意依赖全仓检测、支持全代码库关键词模糊检索（如 `swagger.html`）
- 新增产品授权能力，支持机器码展示、授权文件签发、导入与状态校验
- 新增授权临期提醒、顶部授权状态胶囊、右下角授权水印和按功能点控制能力
- 修复启动时误删指定管理员账户的硬编码逻辑
- 修复管理员删除接口错误提示不准确的问题
- 修复无漏洞扫描记录无法导出报告的问题
- 前端 UI 升级为深色科技安全控制台风格，并增强平板 / 手机布局
- 恢复 Light / Dark 双主题切换，补齐主要页面在 Light 模式下的表格、面板和输入区样式
- 进一步压低登录页粉色和主界面绿色倾向，强化左侧栏与概览页的冷色发光控制台视觉
- 同步完善技术文档、使用手册和更新日志，校正文档中与当前实现不一致的接口和表结构描述

## 核心功能

**多模式智能审计**
- **增量扫描**：监控所有分支的新增与修改文件，专注供应链投毒和恶意代码注入检测
- **增量审计**：对最近提交的变更文件进行 LLM 深度审计，只上报严重与高危风险，降低噪音
- **全量审计**：定期扫描 main/master 主分支完整历史提交，覆盖所有漏洞级别，建立安全基线

**任务针对性扫描**
每类任务在 Prompt 层面即明确扫描目标：增量扫描专注投毒/供应链攻击，增量审计只检测 RCE、SQL 注入、认证绕过等高影响漏洞，全量审计全覆盖所有风险类别，LLM 从分析阶段就针对性工作，而非扫完再裁剪。

**灵活的计划调度**
支持按**小时、天、周**配置三类审计计划，多个时间点可叠加，后端基于 APScheduler 实现 Cron 精准调度，重启自动恢复。

**多平台代码源接入**
| 平台 | 支持方式 |
|------|---------|
| GitHub | Token + Organization |
| GitLab / 腾讯工蜂 / 阿里云效 Codeup | Token + 自定义域名 |
| Bitbucket | App Password |
| Gitee | Token |

**多 LLM 提供商支持**
| 类型 | 支持 |
|------|------|
| 国际 | OpenAI、Anthropic Claude、Google Gemini、DeepSeek |
| 国内 | 阿里通义千问、智谱 GLM、月之暗面 Kimi、字节豆包、百度文心、MiniMax |
| 本地私有化 | Ollama（Llama3、Qwen2.5、DeepSeek-Coder 等） |
| 自定义 | 任意 OpenAI 兼容接口 |

无 LLM 配置时自动降级为 Semgrep + OpenSCA 静态扫描。

**多模型交叉审计**
- 支持在投毒检测、增量审计、全量审计中分别配置 `审计模型`、`检查模型`、`验证模型`
- 每个角色都可以选择一个或多个模型
- 典型组合：`DeepSeek` 审计，`GPT` 检查，`Claude` 验证
- 结果保留规则为分阶段去噪：审计先发现，检查再过滤，验证做最终确认
- 开启“根据审计结果优化对应 skills”后，系统会用保留下来的结果增强已有 skills，并把被后续阶段否决的弱信号沉淀为抑制噪音的负向经验

**即时告警与通知**
- 钉钉（支持签名验证）
- 飞书 / 企业微信
- Slack
- 邮件（SMTP，支持 SSL）

**白名单与误报管理**
对已确认误报的漏洞加入白名单，后续扫描自动过滤，支持按仓库 + 文件 + 漏洞标题精确匹配。

**漏洞生命周期管理**
每条漏洞支持状态流转：新增 → 修复中 → 已修复 / 暂不处理，审计历史全程可查。

**Syslog 实时同步**
登录、扫描、漏洞发现等关键事件实时转发至外部 Syslog 服务器（支持 UDP / TCP），便于接入 SIEM。

**自定义 Prompt**
内置 Frontend、Backend、Smart Contract，以及 Java、PHP、Python、Go、Node.js、C#、Ruby、Rust、C/C++ 等语言专项提示词，支持按文件扩展名匹配，可在 Web 界面自由编辑或新增。

## DVWA 基准对照

参考 DVWA 官方仓库 `vulnerabilities/` 目录，当前公开模块至少包括：

- `api`
- `authbypass`
- `bac`
- `brute`
- `captcha`
- `cryptography`
- `csp`
- `csrf`
- `exec`
- `fi`
- `javascript`
- `open_redirect`
- `sqli`
- `sqli_blind`
- `upload`
- `weak_id`
- `xss_d`
- `xss_r`
- `xss_s`

基于这组基准，本项目本次调整了默认 skills / prompts：

- 后端提示词补齐 `open redirect`、`weak identifier`、API/BAC 相关检查点
- 前端提示词继续覆盖 `csp`、`javascript`、`open redirect`、`xss_*`
- PHP 专项提示词补齐 `fi`、`upload`、`exec`、`open redirect`
- Java 专项提示词补齐 `authbypass`、`bac`、`cryptography`、`xxe`、`deserialization`

如果要验证“DVWA 是否都能审出来”，建议把 DVWA 仓库本身接入平台后跑一次 `full_audit`，再按模块做召回率核对。当前仓库内没有 DVWA 扫描结果，因此这里完成的是能力对照，不是样本实测召回。

## 技术架构

```
┌─────────────────────────────────────────────┐
│                   Web UI                    │
│        (单文件 HTML + 原生 JavaScript)        │
└──────────────────┬──────────────────────────┘
                   │ REST API
┌──────────────────▼──────────────────────────┐
│              FastAPI 后端                    │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│   │ Scheduler │  │ Scanner  │  │ Notifier │  │
│   │APScheduler│  │          │  │          │  │
│   └──────────┘  └────┬─────┘  └──────────┘  │
│                      │                       │
│   ┌───────────────────▼──────────────────┐   │
│   │             Analyzer                 │   │
│   │  LLM (多提供商) + Semgrep + OpenSCA  │   │
│   └──────────────────────────────────────┘   │
│                                              │
│   ┌──────────────────────────────────────┐   │
│   │          SQLite (audit.db)           │   │
│   └──────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
         │ Webhook / API
┌────────▼────────────────────────────────────┐
│  GitHub / GitLab / Bitbucket / Gitee / ...  │
└─────────────────────────────────────────────┘
```

**技术栈**
- 后端：Python 3.10+、FastAPI、APScheduler、OpenAI SDK、Anthropic SDK
- 前端：纯原生 HTML/CSS/JavaScript，无框架依赖，单文件部署
- 数据库：SQLite（单文件，无需额外安装）
- 静态扫描：Semgrep、OpenSCA

## 快速部署

**环境要求**
- Python 3.10+
- pip

**安装与启动**

```bash
git clone <repo-url>
cd code-audit
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000
```

浏览器访问 `http://localhost:8000`，默认账号密码：`admin / admin123`（首次登录后请立即修改）。

**Docker 部署**

```bash
docker compose up -d --build
```

启动后访问 `http://localhost:8000`。  
持久化数据默认在宿主机 `./data` 目录（数据库、报告、同步仓库快照）。
镜像构建默认不会打包本机 `.env`、数据库、报告文件和同步快照目录。

## 源码保护与防泄漏

- 仓库内置 `pre-commit` 密钥拦截配置：`.pre-commit-config.yaml`
- 提供基础安全策略：`SECURITY.md`
- 提供交付与防抄袭建议：`docs/delivery-and-ip-protection.md`

启用提交前拦截：

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

**环境变量**

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `BASE_URL` | 报告链接前缀，用于通知消息中的跳转地址 | `http://localhost:8000` |
| `LICENSE_PRIVATE_KEY_PATH` | 授权管理系统私钥路径，仅授权系统需要 | 空 |
| `LICENSE_PUBLIC_KEY_PATH` | 代码审计系统公钥路径，仅审计系统需要 | 空 |
| `LICENSE_PRIVATE_KEY` | 授权管理系统私钥 PEM 内容，可替代文件路径 | 空 |
| `LICENSE_PUBLIC_KEY` | 代码审计系统公钥 PEM 内容，可替代文件路径 | 空 |
| `PRODUCT_INSTANCE_ID` | 手工指定当前机器码；不设置时自动按主机信息生成 | 自动生成 |
| `DB_PATH` | SQLite 数据库文件路径 | `audit.db` |
| `REPORTS_DIR` | 报告目录（`/reports` 静态映射来源） | `reports` |
| `SYNC_ROOT` | 全量快照同步目录 | `synced_repos` |
| `REPORTS_REQUIRE_AUTH` | 是否要求登录后访问报告（`1` 开启） | `1` |
| `SESSION_TTL_MINUTES` | 会话绝对有效期（分钟） | `720` |
| `SESSION_IDLE_MINUTES` | 会话空闲超时（分钟） | `120` |

## 产品授权

当前版本已内置基于 **机器码 + 授权文件** 的授权机制，且**授权校验强制开启，不可由客户修改**。
未导入有效授权文件时，所有扫描功能（投毒检测、增量审计、全量审计、即时分析）将被拒绝访问，仅允许登录和系统设置操作。
代码审计系统仅保留客户侧授权动作：查看机器码、下载机器码文件、导入授权文件（`license.json`）。
授权签发与授权台账已拆分为独立内部系统，不包含在当前客户交付仓库中。

### 生产部署示例

仓库已提供可直接改造的部署样例：

- `deploy/systemd/tokenlens-audit.service`
- `deploy/nginx/tokenlens.conf`

推荐部署步骤：

1. 将项目放到 `/opt/tokenlens`
2. 按实际域名修改 `deploy/nginx/tokenlens.conf`
3. 先生成 Ed25519 公私钥
4. 将公钥放到客户侧代码审计系统
5. 按实际路径和环境变量修改 `systemd` service 文件
6. 启动代码审计系统

```bash
mkdir -p /opt/tokenlens/keys
python3 license_manager.py generate-keypair \
  --private-key-out /opt/tokenlens/keys/license_private.pem \
  --public-key-out /opt/tokenlens/keys/license_public.pem
```

其中：

- `license_private.pem` 只放在公司内部授权管理系统
- `license_public.pem` 放到客户侧代码审计系统
- 私钥不要下发到代码审计系统

```bash
sudo cp deploy/systemd/tokenlens-audit.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tokenlens-audit
```

7. 加载 Nginx 配置

```bash
sudo cp deploy/nginx/tokenlens.conf /etc/nginx/conf.d/
sudo nginx -t
sudo systemctl reload nginx
```

### 生成授权文件

先在目标部署机器的 **系统设置 → 产品授权** 下载机器码文件，或复制机器码，然后在公司内部授权系统或签发环境执行：

```bash
python3 license_manager.py generate-file \
  --customer 'Acme Corp' \
  --expires-at '2027-12-31T23:59:59Z' \
  --machine-code '目标机器码' \
  --feature poison_scan \
  --feature incremental_audit \
  --feature full_audit \
  --feature instant_analysis \
  --output ./license_acme.json
```

将生成的 `license_acme.json` 在系统设置中上传即可生效。

可重复追加 `--feature` 写入功能点，例如 `--feature full_audit --feature instant_analysis`。  
若不传 `--feature`，则默认表示授权不限制功能点。

### 校验授权文件

```bash
export LICENSE_PUBLIC_KEY_PATH=./keys/license_public.pem

python3 license_manager.py verify-file \
  --license-file ./license_acme.json \
  --machine-code '粘贴系统设置页里的机器码'
```

推荐功能点：
- `poison_scan`
- `incremental_audit`
- `full_audit`
- `instant_analysis`

## 使用指南

### 1. 配置代码平台账户

进入 **代码平台** 页面，添加 GitHub / GitLab 等账户的 Token，填写 Owner（组织或用户名）。平台将自动拉取该账户下所有可访问仓库的提交记录。

### 2. 配置 LLM

进入 **AI 配置** 页面，选择 LLM 提供商并填入 API Key 和 Model。若不配置，系统自动使用 Semgrep + OpenSCA 进行静态扫描。

### 3. 配置审计计划

进入 **系统设置** 页面，为三类计划分别添加执行时间点：

| 计划 | 适用场景 | 推荐频率 |
|------|---------|---------|
| 增量扫描 | 实时监控投毒与供应链攻击 | 每小时 |
| 增量审计 | 工作日提交后审计高危漏洞 | 每天（下班后） |
| 全量审计 | 定期主分支完整安全基线 | 每周 |

### 4. 配置告警通知

进入 **通知渠道** 页面，添加钉钉机器人 Webhook、飞书 Bot、企业微信群机器人或邮件 SMTP 配置，支持发送测试消息验证连通性。

### 5. 查看审计结果

- **扫描历史**：查看每次扫描的漏洞汇总，点击「查看漏洞」进入详情
- **漏洞详情**：按严重程度、状态筛选，支持翻页浏览，每条漏洞可标记处理状态
- **漏洞统计**：按天/周/月查看各仓库漏洞趋势图

### 6. 即时审计

在 **即时检测** 页面可粘贴代码片段或上传文件（支持 ZIP），立即触发一次 LLM 审计，无需等待定时任务。

## 漏洞检测范围

**前端**
XSS、原型链污染、敏感数据泄露、不安全存储、CSP 配置缺失、CORS 错误配置、postMessage 未校验来源、开放重定向、点击劫持、供应链投毒

**后端**
SQL / NoSQL / 命令注入、XXE、认证与授权缺陷（JWT、IDOR、OAuth2）、批量赋值、敏感信息泄露、弱加密、SSRF、文件路径穿越、不安全反序列化、CSRF、业务逻辑漏洞、速率限制缺失

**依赖与供应链**
恶意代码注入、后门植入、typosquatting、混淆代码、异常外联请求、数据外泄逻辑（通过 OpenSCA 检测已知 CVE）

## 免责声明

本工具仅供**已获授权**的安全研究、代码审计及内部安全建设使用。使用者须自行承担因未经授权使用而产生的一切法律责任，请严格遵守所在地网络安全相关法律法规。
