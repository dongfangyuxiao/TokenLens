# TokenLens 代码安全审计平台 · 部署手册

> 版本：2026-03
> 适用：TokenLens 正式发布版（Cython 编译保护包）

---

## 目录

1. [系统要求](#1-系统要求)
2. [快速部署（一键脚本）](#2-快速部署一键脚本)
3. [手动部署步骤](#3-手动部署步骤)
4. [Nginx 反向代理配置](#4-nginx-反向代理配置)
5. [systemd 服务管理](#5-systemd-服务管理)
6. [授权文件配置](#6-授权文件配置)
7. [环境变量参考表](#7-环境变量参考表)
8. [目录结构说明](#8-目录结构说明)
9. [数据备份与迁移](#9-数据备份与迁移)
10. [常见问题排查](#10-常见问题排查)
11. [代码保护说明（开发者内部）](#11-代码保护说明开发者内部)

---

## 1. 系统要求

### 操作系统

| 系统 | 版本 | 备注 |
|------|------|------|
| Ubuntu | 20.04 / 22.04 / 24.04 LTS | 推荐 |
| Debian | 11 / 12 | 支持 |
| CentOS / Rocky Linux | 7 / 8 / 9 | 支持 |
| 其他 Linux | — | 需自行确认 Python 3.10+ 可用 |

不支持 Windows Server（可使用 Docker 方式部署）。

### Python

- 最低要求：**Python 3.10**
- 推荐版本：**Python 3.11 或 3.12**
- 核心模块已通过 Cython 编译为 `.so` 二进制文件，无需额外安装编译工具

### 硬件资源

| 资源 | 最低配置 | 推荐配置 |
|------|----------|----------|
| CPU | 2 核 | 4 核+ |
| 内存 | 2 GB | 8 GB+ |
| 磁盘 | 20 GB | 100 GB+（扫描报告会占用空间） |
| 网络 | 可访问目标代码仓库（GitLab/GitHub） | — |

### 网络要求

- 服务默认监听 `127.0.0.1:8000`，通过 Nginx 对外暴露
- 如需同步 Git 仓库，服务器需能访问对应 Git 服务（SSH 22 端口或 HTTPS 443 端口）
- 授权文件为本地文件，不需要联网验证

---

## 2. 快速部署（一键脚本）

适合全新服务器的快速安装。

### 前提条件

- root 权限或 sudo 权限
- 已将部署包解压到服务器（例如 `/tmp/tokenlens/`）

### 执行部署

```bash
# 1. 解压部署包
tar -xzf tokenlens-YYYYMMDD.tar.gz -C /tmp/

# 2. 进入解压目录
cd /tmp/tokenlens

# 3. 运行一键部署脚本
sudo bash deploy/deploy.sh
```

脚本会自动完成：

- 检查 Python 版本
- 安装系统依赖（python3-venv、git、curl）
- 创建 `tokenlens` 系统用户
- 将文件部署到 `/opt/tokenlens/`
- 创建 Python 虚拟环境并安装所有依赖
- 注册并启动 `tokenlens-audit` systemd 服务

部署完成后，服务在 `http://<服务器IP>:8000` 可访问（内网直接访问，不经过 Nginx）。

**注意**：部署完成后需上传授权文件才能正常使用，参见[第 6 节](#6-授权文件配置)。

---

## 3. 手动部署步骤

如果需要自定义安装路径或对部署过程有更多控制，可按以下步骤手动部署。

### 步骤 1：创建系统用户

```bash
useradd -r -s /bin/false -d /opt/tokenlens tokenlens
```

### 步骤 2：部署文件

```bash
# 创建安装目录
mkdir -p /opt/tokenlens

# 将解压后的文件复制到安装目录（跳过 venv 和数据库）
rsync -a --exclude='venv/' --exclude='*.db' --exclude='data/' \
    /tmp/tokenlens/ /opt/tokenlens/

# 创建数据目录
mkdir -p /opt/tokenlens/data/reports
mkdir -p /opt/tokenlens/data/synced_repos

# 设置权限
chown -R tokenlens:tokenlens /opt/tokenlens
chmod 750 /opt/tokenlens
chmod 700 /opt/tokenlens/keys
```

### 步骤 3：创建 Python 虚拟环境

```bash
# 使用 Python 3.11（或 3.10/3.12）
python3.11 -m venv /opt/tokenlens/venv

# 安装依赖
/opt/tokenlens/venv/bin/pip install --upgrade pip
/opt/tokenlens/venv/bin/pip install -r /opt/tokenlens/requirements.txt
```

### 步骤 4：配置环境变量（可选）

如需覆盖默认配置，可在 `/opt/tokenlens/.env` 中设置，或直接在 systemd 服务文件中添加 `Environment=` 行。

### 步骤 5：配置 systemd 服务

```bash
# 复制服务文件
cp /opt/tokenlens/deploy/systemd/tokenlens-audit.service \
    /etc/systemd/system/

# 根据实际情况修改服务文件中的 BASE_URL
nano /etc/systemd/system/tokenlens-audit.service

# 启用并启动服务
systemctl daemon-reload
systemctl enable tokenlens-audit
systemctl start tokenlens-audit

# 验证服务状态
systemctl status tokenlens-audit
```

### 步骤 6：验证服务

```bash
# 检查服务是否正常响应
curl http://127.0.0.1:8000/api/status
```

返回 JSON 响应即表示服务正常。

---

## 4. Nginx 反向代理配置

### 安装 Nginx

```bash
# Ubuntu/Debian
apt-get install -y nginx

# CentOS/Rocky
yum install -y nginx
```

### 配置虚拟主机（HTTP）

将部署包中的 `deploy/nginx/tokenlens.conf` 复制到 Nginx 配置目录：

```bash
cp /opt/tokenlens/deploy/nginx/tokenlens.conf \
    /etc/nginx/sites-available/tokenlens.conf

# 启用配置
ln -s /etc/nginx/sites-available/tokenlens.conf \
    /etc/nginx/sites-enabled/

# 修改 server_name 为实际域名
nano /etc/nginx/sites-available/tokenlens.conf

# 测试配置语法
nginx -t

# 重载 Nginx
systemctl reload nginx
```

### 配置 HTTPS（使用 Let's Encrypt）

```bash
# 安装 certbot
apt-get install -y certbot python3-certbot-nginx

# 申请证书并自动配置 Nginx
certbot --nginx -d audit.example.com

# certbot 会自动修改 Nginx 配置，添加 SSL 和 HTTP→HTTPS 重定向
```

### 配置 HTTPS（使用自签名或企业证书）

手动在 Nginx 配置中添加 SSL：

```nginx
server {
    listen 443 ssl;
    server_name audit.example.com;

    ssl_certificate     /etc/ssl/tokenlens/cert.pem;
    ssl_certificate_key /etc/ssl/tokenlens/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    client_max_body_size 200m;

    location / {
        proxy_pass http://tokenlens_audit;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}

server {
    listen 80;
    server_name audit.example.com;
    return 301 https://$host$request_uri;
}
```

配置完 HTTPS 后，需要同步更新 systemd 服务中的 `BASE_URL` 环境变量：

```bash
# 编辑服务文件
systemctl edit tokenlens-audit

# 在 [Service] 下添加（会覆盖原来的值）：
# Environment=BASE_URL=https://audit.example.com

systemctl daemon-reload
systemctl restart tokenlens-audit
```

---

## 5. systemd 服务管理

### 常用命令

```bash
# 查看服务状态
systemctl status tokenlens-audit

# 启动 / 停止 / 重启
systemctl start tokenlens-audit
systemctl stop tokenlens-audit
systemctl restart tokenlens-audit

# 开机自启 / 禁用自启
systemctl enable tokenlens-audit
systemctl disable tokenlens-audit

# 查看最近 100 行日志
journalctl -u tokenlens-audit -n 100

# 实时跟踪日志
journalctl -u tokenlens-audit -f

# 查看今天的日志
journalctl -u tokenlens-audit --since today
```

### 修改服务配置

推荐使用 `systemctl edit` 追加配置（不直接修改原文件，升级时不会被覆盖）：

```bash
systemctl edit tokenlens-audit
```

在打开的编辑器中写入（示例）：

```ini
[Service]
Environment=BASE_URL=https://audit.mycompany.com
Environment=SESSION_TTL_MINUTES=1440
```

保存后执行：

```bash
systemctl daemon-reload
systemctl restart tokenlens-audit
```

---

## 6. 授权文件配置

### 授权机制概述

TokenLens 采用离线授权方式，授权文件（`license.json`）由供应商签发，服务器无需联网验证。授权文件中包含：

- 被授权方信息（公司名称、联系人）
- 授权有效期
- 功能限制（扫描并发数、最大项目数等）
- 供应商数字签名（Ed25519）

### 从授权管理台获取授权文件

1. 联系 TokenLens 供应商，提供以下信息：
   - 公司名称
   - 所需授权有效期
   - 所需功能配置（扫描并发数等）
2. 供应商通过授权管理台生成并发送 `license.json` 文件

### 上传授权文件

**方式一：通过 Web 界面上传（推荐）**

1. 访问 TokenLens Web 界面，使用管理员账号登录
2. 进入 **系统设置 → 授权管理**
3. 点击"上传授权文件"，选择 `license.json`
4. 上传成功后页面显示授权信息（有效期、授权方等）

**方式二：直接放置文件**

```bash
# 将授权文件复制到安装目录
cp license.json /opt/tokenlens/license.json
chown tokenlens:tokenlens /opt/tokenlens/license.json
chmod 640 /opt/tokenlens/license.json

# 重启服务使其生效
systemctl restart tokenlens-audit
```

### 无授权时的行为

| 场景 | 行为 |
|------|------|
| 未上传授权文件 | 系统启动，但登录后显示"未授权"提示，核心审计功能被禁用 |
| 授权已过期 | 可查看历史数据，无法发起新的扫描任务 |
| 授权文件被篡改 | 系统拒绝加载，显示签名验证失败错误 |
| 授权超出并发限制 | 超出部分的扫描任务进入等待队列 |

### 授权续期

授权到期前，联系供应商获取新的 `license.json`，按上传流程重新上传即可，无需重启服务（热加载）。

---

## 7. 环境变量参考表

所有环境变量均可在 systemd 服务文件或 Docker Compose 的 `environment` 块中设置。

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `BASE_URL` | `http://localhost:8000` | 服务的对外访问地址，影响报告中的链接生成 |
| `DB_PATH` | `/opt/tokenlens/data/audit.db` | SQLite 数据库文件路径 |
| `REPORTS_DIR` | `/opt/tokenlens/data/reports` | 扫描报告存储目录 |
| `SYNC_ROOT` | `/opt/tokenlens/data/synced_repos` | Git 仓库同步缓存目录 |
| `LICENSE_PUBLIC_KEY_PATH` | `/opt/tokenlens/keys/license_public.pem` | 授权验证公钥路径（勿删除） |
| `REPORTS_REQUIRE_AUTH` | `1` | 是否要求登录才能访问报告（`1`=是，`0`=否） |
| `SESSION_TTL_MINUTES` | `720` | 登录会话最大存活时间（分钟），超时强制重新登录 |
| `SESSION_IDLE_MINUTES` | `120` | 会话空闲超时时间（分钟），空闲超时后需重新登录 |

**说明：**

- `BASE_URL` 建议在配置 Nginx+SSL 后更新为 `https://` 地址，否则报告分享链接会是 HTTP
- `SESSION_TTL_MINUTES` 和 `SESSION_IDLE_MINUTES` 可根据企业安全策略调整，高安全场景建议分别设为 `480` 和 `60`

---

## 8. 目录结构说明

部署后 `/opt/tokenlens/` 的目录结构：

```
/opt/tokenlens/
├── app*.so                 # 主应用（Cython 编译二进制）
├── database*.so            # 数据库层（Cython 编译二进制）
├── license_manager*.so     # 授权管理（Cython 编译二进制）
├── scanner*.so             # 扫描引擎（Cython 编译二进制）
├── reporter*.so            # 报告生成（Cython 编译二进制）
├── notifier*.so            # 通知模块（Cython 编译二进制）
├── syslog_sender*.so       # Syslog 推送（Cython 编译二进制）
├── repo_sync*.so           # 仓库同步（Cython 编译二进制）
├── default_prompts*.so     # 默认提示词（Cython 编译二进制）
├── requirements.txt        # Python 依赖列表
├── VERSION                 # 版本号文件
├── static/                 # 前端静态文件
│   └── index.html
├── deploy/                 # 部署配置
│   ├── deploy.sh           # 一键部署脚本
│   ├── nginx/
│   │   └── tokenlens.conf  # Nginx 配置模板
│   └── systemd/
│       └── tokenlens-audit.service  # systemd 服务文件模板
├── keys/
│   └── license_public.pem  # 授权验证公钥（勿删除）
├── venv/                   # Python 虚拟环境（部署时创建）
├── license.json            # 授权文件（上传后出现）
└── data/                   # 运行时数据（需持久化备份）
    ├── audit.db            # SQLite 主数据库
    ├── reports/            # 扫描报告文件
    └── synced_repos/       # Git 仓库缓存
```

**重要说明：**

- `*.so` 文件是 Cython 编译的二进制模块，**不得删除**，否则服务无法启动
- `keys/license_public.pem` 是授权验证公钥，**不得删除或修改**
- `data/` 目录包含所有运行数据，**需要定期备份**

---

## 9. 数据备份与迁移

### 需要备份的内容

| 内容 | 路径 | 重要性 |
|------|------|--------|
| 数据库 | `/opt/tokenlens/data/audit.db` | 极高（所有项目、扫描记录、用户数据） |
| 扫描报告 | `/opt/tokenlens/data/reports/` | 高（历史报告文件） |
| 授权文件 | `/opt/tokenlens/license.json` | 高（丢失需重新向供应商申请） |

不需要备份：`venv/`（可重新安装）、`synced_repos/`（可重新同步）

### 自动备份脚本

```bash
#!/bin/bash
# /etc/cron.daily/tokenlens-backup
BACKUP_DIR="/backup/tokenlens"
DATE=$(date +%Y%m%d)

mkdir -p "$BACKUP_DIR"

# 备份数据库（热备份，SQLite 支持在运行时复制）
cp /opt/tokenlens/data/audit.db "$BACKUP_DIR/audit-${DATE}.db"

# 备份报告（增量）
rsync -a /opt/tokenlens/data/reports/ "$BACKUP_DIR/reports/"

# 保留最近 30 天的数据库备份
find "$BACKUP_DIR" -name "audit-*.db" -mtime +30 -delete

echo "TokenLens 备份完成：$BACKUP_DIR"
```

```bash
# 设置每日自动备份
chmod +x /etc/cron.daily/tokenlens-backup
```

### 迁移到新服务器

```bash
# ── 在旧服务器上 ──
# 1. 停止服务
systemctl stop tokenlens-audit

# 2. 打包数据
tar -czf tokenlens-data-$(date +%Y%m%d).tar.gz \
    /opt/tokenlens/data/ \
    /opt/tokenlens/license.json

# 3. 传输到新服务器
scp tokenlens-data-*.tar.gz user@new-server:/tmp/

# ── 在新服务器上 ──
# 4. 完成正常部署流程（参见第 2 节）
# 5. 停止服务，恢复数据
systemctl stop tokenlens-audit
tar -xzf /tmp/tokenlens-data-*.tar.gz -C /
chown -R tokenlens:tokenlens /opt/tokenlens/data /opt/tokenlens/license.json
systemctl start tokenlens-audit
```

---

## 10. 常见问题排查

### 服务启动失败

**症状：** `systemctl status tokenlens-audit` 显示 `failed`

**排查步骤：**

```bash
# 查看详细错误日志
journalctl -u tokenlens-audit -n 50 --no-pager

# 常见原因 1：Python 路径错误
ls /opt/tokenlens/venv/bin/uvicorn

# 常见原因 2：端口被占用
ss -tlnp | grep 8000

# 常见原因 3：目录权限问题
ls -la /opt/tokenlens/
stat /opt/tokenlens/data/
```

### 403 / 401 错误

- 检查授权文件是否已上传且有效
- 检查 `SESSION_TTL_MINUTES` 是否过小导致频繁过期
- 检查 `REPORTS_REQUIRE_AUTH` 设置

### Git 仓库同步失败

```bash
# 测试 SSH 连接（如果使用 SSH 方式）
sudo -u tokenlens ssh -T git@your-gitlab.example.com

# 检查 SSH 密钥是否配置
ls -la /opt/tokenlens/.ssh/

# 配置 SSH 密钥（需要在 GitLab/GitHub 添加对应公钥）
sudo -u tokenlens ssh-keygen -t ed25519 -C "tokenlens@your-server"
cat /opt/tokenlens/.ssh/id_ed25519.pub
```

### 扫描报告无法访问

```bash
# 检查报告目录权限
ls -la /opt/tokenlens/data/reports/

# 检查 REPORTS_DIR 环境变量
systemctl show tokenlens-audit | grep REPORTS_DIR
```

### Nginx 502 Bad Gateway

- 确认 `tokenlens-audit` 服务正在运行：`systemctl is-active tokenlens-audit`
- 确认 upstream 地址正确（`127.0.0.1:8000`）
- 检查 Nginx 错误日志：`tail -f /var/log/nginx/error.log`

### 授权验证失败

```bash
# 检查公钥文件是否存在
ls -la /opt/tokenlens/keys/license_public.pem

# 检查授权文件格式
python3 -c "import json; json.load(open('/opt/tokenlens/license.json')); print('JSON格式正确')"

# 检查 LICENSE_PUBLIC_KEY_PATH 环境变量
systemctl show tokenlens-audit | grep LICENSE_PUBLIC_KEY
```

### 磁盘空间不足

```bash
# 查看各目录占用
du -sh /opt/tokenlens/data/reports/
du -sh /opt/tokenlens/data/synced_repos/
du -sh /opt/tokenlens/data/audit.db

# 清理旧的 Git 缓存（不影响数据库中的记录）
rm -rf /opt/tokenlens/data/synced_repos/*
# 注意：清理后下次扫描时会重新克隆，耗时较长
```

---

## 11. 代码保护说明（开发者内部）

> 本节为内部文档，不对客户分发。

### 保护方案

TokenLens 使用 **Cython** 将核心 Python 文件编译为 `.so` 二进制模块进行源码保护，防止客户直接阅读业务逻辑代码。编译后的 `.so` 文件为本机二进制，无法反推出原始 Python 源码。

编译保护的文件包括：`app.py`、`database.py`、`license_manager.py`、`scanner.py`、`reporter.py`、`notifier.py`、`syslog_sender.py`、`repo_sync.py`、`default_prompts.py`

静态资源（`static/`）、`clients/` 目录和配置文件**不编译**，直接原样打包。

### 构建部署包

使用项目根目录的 `build_package.sh` 脚本：

```bash
# 在有源码的机器上，切换到项目根目录
cd /path/to/TokenLens

# 构建当天日期版本包（输出：tokenlens-20260331.tar.gz）
bash build_package.sh

# 构建指定版本号
bash build_package.sh 1.2.0
```

**构建依赖：**

- `python3`、`python3-venv`、`gcc`（系统包）
- `Cython`、`setuptools`（脚本会在临时虚拟环境中自动准备）

**构建流程：**

1. 检查 `python3`、`python3-venv` 和 `gcc` 是否可用，必要时创建临时虚拟环境准备 Cython
2. 将核心 `.py` 文件复制到临时目录，生成 `setup.py`
3. 执行 `python3 setup.py build_ext --inplace`，通过 Cython 编译为 `.so` 二进制
4. 将 `.so` 文件（不含源码 `.py`）复制到部署包
5. 原样复制 `clients/`、`static/`、`requirements.txt`、`deploy/` 等运行所需文件
6. 复制 `keys/license_public.pem`（**不复制私钥**）
7. 写入 `VERSION` 文件，打包为 `tokenlens-<版本号>.tar.gz`

**注意事项：**

- 构建前确保本地 `keys/license_public.pem` 是最新的公钥
- `keys/license_private.pem`（私钥）绝对不能打入包中，`build_package.sh` 只复制公钥
- `.so` 文件与 CPU 架构和 Python 版本绑定，**必须在与目标客户相同架构的机器上构建**（x86_64 Linux），避免跨平台运行失败
- 客户服务器需安装与构建时版本一致的 Python（如 Python 3.11）

### 交付流程

1. 运行 `build_package.sh <版本号>` 生成 `.tar.gz` 包
2. 将包传输给客户（邮件、文件共享等）
3. 客户解压后运行 `bash deploy/deploy.sh`
4. 客户登录后在系统设置中上传 `license.json` 授权文件
5. 授权生效，系统可正常使用
