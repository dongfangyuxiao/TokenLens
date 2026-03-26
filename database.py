import sqlite3
import json
import hashlib
import os
import binascii
from datetime import datetime, date, timedelta
from default_prompts import FRONTEND_PROMPT, BACKEND_PROMPT, CONTRACT_PROMPT

DB_PATH = 'audit.db'


def _hash_password(password: str, salt: str = None):
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode()
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return binascii.hexlify(dk).decode(), salt

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS admin_users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS accounts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            platform   TEXT NOT NULL,
            name       TEXT NOT NULL,
            token      TEXT NOT NULL,
            url        TEXT DEFAULT '',
            owner      TEXT DEFAULT '',
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS channels (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL,
            config     TEXT NOT NULL,
            enabled    INTEGER DEFAULT 1,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS llm_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS prompts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL UNIQUE,
            category   TEXT NOT NULL DEFAULT 'custom',
            extensions TEXT NOT NULL DEFAULT '',
            content    TEXT NOT NULL,
            is_default INTEGER DEFAULT 0,
            enabled    INTEGER DEFAULT 1,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scans (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at     TEXT,
            finished_at    TEXT,
            status         TEXT DEFAULT 'running',
            scan_type      TEXT DEFAULT 'incremental',
            total_commits  INTEGER DEFAULT 0,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count     INTEGER DEFAULT 0,
            medium_count   INTEGER DEFAULT 0,
            low_count      INTEGER DEFAULT 0,
            report_path    TEXT DEFAULT '',
            error_msg      TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS syslog_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_repos (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            repo           TEXT NOT NULL,
            source         TEXT DEFAULT '',
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count     INTEGER DEFAULT 0,
            medium_count   INTEGER DEFAULT 0,
            low_count      INTEGER DEFAULT 0,
            scanned_at     TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id        INTEGER NOT NULL,
            repo           TEXT DEFAULT '',
            commit_sha     TEXT DEFAULT '',
            commit_url     TEXT DEFAULT '',
            author         TEXT DEFAULT '',
            committed_at   TEXT DEFAULT '',
            severity       TEXT DEFAULT 'low',
            type           TEXT DEFAULT 'vulnerability',
            title          TEXT DEFAULT '',
            filename       TEXT DEFAULT '',
            line           TEXT DEFAULT '',
            description    TEXT DEFAULT '',
            recommendation TEXT DEFAULT '',
            status         TEXT DEFAULT 'new'
        );
        CREATE TABLE IF NOT EXISTS scan_logs (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER NOT NULL,
            level     TEXT DEFAULT 'info',
            message   TEXT DEFAULT '',
            logged_at TEXT
        );
        CREATE TABLE IF NOT EXISTS repo_owners (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            repo               TEXT NOT NULL,
            source             TEXT DEFAULT '',
            responsible_person TEXT DEFAULT '',
            contact            TEXT DEFAULT '',
            created_at         TEXT
        );
        CREATE TABLE IF NOT EXISTS finding_whitelist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            repo        TEXT DEFAULT '',
            filename    TEXT DEFAULT '',
            title       TEXT DEFAULT '',
            reason      TEXT DEFAULT '',
            created_by  TEXT DEFAULT '',
            created_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            type    TEXT    NOT NULL DEFAULT 'poison',
            hour    INTEGER NOT NULL DEFAULT -1,
            minute  INTEGER NOT NULL DEFAULT 0,
            weekday INTEGER DEFAULT NULL,
            enabled INTEGER DEFAULT 1,
            label   TEXT    DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS llm_profiles (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            name      TEXT NOT NULL,
            provider  TEXT NOT NULL DEFAULT '',
            model     TEXT DEFAULT '',
            api_key   TEXT DEFAULT '',
            base_url  TEXT DEFAULT ''
        );
        """)
        # Syslog 默认配置
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('enabled','0')")
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('host','')")
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('port','514')")
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('protocol','udp')")
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('facility','local0')")
        conn.execute("INSERT OR IGNORE INTO syslog_config VALUES ('app_name','code-audit')")
        # 索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id  ON scan_logs(scan_id)")
        # 默认管理员账户
        conn.execute("DELETE FROM admin_users WHERE username='light'")
        row = conn.execute("SELECT username FROM admin_users WHERE username='admin'").fetchone()
        if not row:
            pwd_hash, salt = _hash_password('admin123')
            conn.execute("INSERT INTO admin_users VALUES ('admin',?,?)", (pwd_hash, salt))
        # 默认配置
        conn.execute("INSERT OR IGNORE INTO app_config VALUES ('scan_interval_hours','1')")
        conn.execute("INSERT OR IGNORE INTO app_config VALUES ('max_diff_chars','12000')")
        conn.execute("INSERT OR IGNORE INTO app_config VALUES ('auto_scan_enabled','1')")
        conn.execute("INSERT OR IGNORE INTO app_config VALUES ('opensca_token','')")
        # 迁移旧版 scan_schedules（无 type / weekday / llm_profile_id 列）
        sched_cols = [r['name'] for r in conn.execute("PRAGMA table_info(scan_schedules)").fetchall()]
        if 'type' not in sched_cols:
            conn.execute("ALTER TABLE scan_schedules ADD COLUMN type TEXT NOT NULL DEFAULT 'poison'")
        if 'weekday' not in sched_cols:
            conn.execute("ALTER TABLE scan_schedules ADD COLUMN weekday INTEGER DEFAULT NULL")
        if 'llm_profile_id' not in sched_cols:
            conn.execute("ALTER TABLE scan_schedules ADD COLUMN llm_profile_id INTEGER DEFAULT NULL")
        # 迁移 scans 表
        scan_cols = [r['name'] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
        if 'llm_profile_id' not in scan_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN llm_profile_id INTEGER DEFAULT NULL")
        # 若各类型均无默认记录则初始化
        if not conn.execute("SELECT 1 FROM scan_schedules WHERE type='poison'").fetchone():
            conn.execute("INSERT INTO scan_schedules (type,hour,minute,enabled,label) VALUES ('poison',-1,0,1,'每小时执行')")
        if not conn.execute("SELECT 1 FROM scan_schedules WHERE type='incremental_audit'").fetchone():
            conn.execute("INSERT INTO scan_schedules (type,hour,minute,enabled,label) VALUES ('incremental_audit',2,0,1,'凌晨 2 点')")
        if not conn.execute("SELECT 1 FROM scan_schedules WHERE type='full_audit'").fetchone():
            conn.execute("INSERT INTO scan_schedules (type,hour,minute,weekday,enabled,label) VALUES ('full_audit',10,0,5,0,'周六早上 10 点')")
        conn.execute("INSERT OR IGNORE INTO app_config VALUES ('semgrep_token','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('deepseek_api_key','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('anthropic_api_key','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('provider','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('model','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('api_key','')")
        conn.execute("INSERT OR IGNORE INTO llm_config VALUES ('base_url','')")
        # Default prompts (INSERT OR IGNORE preserves user edits)
        now = datetime.now().isoformat()
        conn.execute("""INSERT OR IGNORE INTO prompts
            (name, category, extensions, content, is_default, enabled, created_at)
            VALUES (?,?,?,?,1,1,?)""",
            ('Frontend', 'frontend',
             '.js,.ts,.jsx,.tsx,.vue,.html,.css,.svelte,.mjs,.cjs',
             FRONTEND_PROMPT, now))
        conn.execute("""INSERT OR IGNORE INTO prompts
            (name, category, extensions, content, is_default, enabled, created_at)
            VALUES (?,?,?,?,1,1,?)""",
            ('Backend', 'backend',
             '.py,.go,.rb,.php,.rs,.cs,.cpp,.c,.sh,.bash,.json,.yaml,.yml,.toml,.env,.java,Dockerfile',
             BACKEND_PROMPT, now))
        conn.execute("""INSERT OR IGNORE INTO prompts
            (name, category, extensions, content, is_default, enabled, created_at)
            VALUES (?,?,?,?,1,1,?)""",
            ('Smart Contract', 'contract',
             '.sol',
             CONTRACT_PROMPT, now))
        # Migrations for existing databases
        existing_cols = [r['name'] for r in conn.execute("PRAGMA table_info(findings)").fetchall()]
        if 'status' not in existing_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN status TEXT DEFAULT 'new'")
        if 'fingerprint' not in existing_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT DEFAULT ''")
        if 'is_cross_file' not in existing_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN is_cross_file INTEGER DEFAULT 0")
        if 'cross_files' not in existing_cols:
            conn.execute("ALTER TABLE findings ADD COLUMN cross_files TEXT DEFAULT ''")
        scan_cols = [r['name'] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
        if 'scan_type' not in scan_cols:
            conn.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'incremental'")
        conn.commit()

# ── 账户 ─────────────────────────────────────────────────────────
def get_accounts():
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id").fetchall()]

def add_account(platform, name, token, url='', owner=''):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO accounts (platform,name,token,url,owner,created_at) VALUES (?,?,?,?,?,?)",
            (platform, name, token, url, owner, datetime.now().isoformat())
        )
        conn.commit()

def delete_account(aid):
    with get_conn() as conn:
        conn.execute("DELETE FROM accounts WHERE id=?", (aid,))
        conn.commit()

# ── 通知渠道 ──────────────────────────────────────────────────────
def get_channels():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM channels ORDER BY id").fetchall()
        return [dict(r) for r in rows]

def add_channel(name, ctype, config: dict):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO channels (name,type,config,enabled,created_at) VALUES (?,?,?,1,?)",
            (name, ctype, json.dumps(config, ensure_ascii=False), datetime.now().isoformat())
        )
        conn.commit()

def toggle_channel(cid, enabled):
    with get_conn() as conn:
        conn.execute("UPDATE channels SET enabled=? WHERE id=?", (1 if enabled else 0, cid))
        conn.commit()

def update_channel(cid, name, config: dict):
    with get_conn() as conn:
        conn.execute(
            "UPDATE channels SET name=?, config=? WHERE id=?",
            (name, json.dumps(config, ensure_ascii=False), cid)
        )
        conn.commit()

def delete_channel(cid):
    with get_conn() as conn:
        conn.execute("DELETE FROM channels WHERE id=?", (cid,))
        conn.commit()

# ── LLM 配置 ──────────────────────────────────────────────────────
def get_llm_config():
    with get_conn() as conn:
        rows = conn.execute("SELECT key,value FROM llm_config").fetchall()
        return {r['key']: r['value'] for r in rows}

def set_llm_config(key, value):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO llm_config VALUES (?,?)", (key, value))
        conn.commit()

# ── 应用配置 ──────────────────────────────────────────────────────
def get_app_config():
    with get_conn() as conn:
        rows = conn.execute("SELECT key,value FROM app_config").fetchall()
        return {r['key']: r['value'] for r in rows}

def set_app_config(key, value):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO app_config VALUES (?,?)", (key, str(value)))
        conn.commit()

# ── 扫描记录 ──────────────────────────────────────────────────────
def create_scan(scan_type='incremental_audit', full_scan=False, llm_profile_id=None):
    # full_scan 为旧版兼容参数
    if full_scan and scan_type == 'incremental_audit':
        scan_type = 'full_audit'
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, status, scan_type, llm_profile_id) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), 'running', scan_type, llm_profile_id)
        )
        conn.commit()
        return cur.lastrowid

def finish_scan(scan_id, total_commits, counts, report_path, error_msg='', status=None):
    if status is None:
        status = 'error' if error_msg else 'done'
    with get_conn() as conn:
        conn.execute("""
            UPDATE scans SET
                finished_at=?, status=?, total_commits=?, total_findings=?,
                critical_count=?, high_count=?, medium_count=?, low_count=?,
                report_path=?, error_msg=?
            WHERE id=?
        """, (
            datetime.now().isoformat(),
            status,
            total_commits,
            sum(counts.values()),
            counts.get('critical', 0), counts.get('high', 0),
            counts.get('medium', 0),  counts.get('low', 0),
            report_path, error_msg, scan_id
        ))
        conn.commit()

def update_scan_status(scan_id: int, status: str):
    with get_conn() as conn:
        conn.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        conn.commit()

def mark_interrupted_scans():
    """服务启动时将未正常结束的扫描标记为 interrupted。"""
    with get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status='interrupted', finished_at=? "
            "WHERE status IN ('running', 'paused')",
            (datetime.now().isoformat(),)
        )
        conn.commit()

def get_last_successful_scan_time(scan_type: str):
    """返回该扫描类型上次成功完成的 finished_at 字符串，若无则返回 None。"""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT finished_at FROM scans WHERE scan_type=? AND status='done' "
            "ORDER BY finished_at DESC LIMIT 1",
            (scan_type,)
        ).fetchone()
        return row['finished_at'] if row else None

def delete_scan(scan_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_logs  WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM findings   WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scan_repos WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM scans      WHERE id=?",      (scan_id,))
        conn.commit()

def get_scans(limit=50):
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()]


# ── Syslog 配置 ───────────────────────────────────────────────────
def get_syslog_config():
    with get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM syslog_config").fetchall()
        return {r['key']: r['value'] for r in rows}

def set_syslog_config(updates: dict):
    allowed = {'enabled', 'host', 'port', 'protocol', 'facility', 'app_name'}
    with get_conn() as conn:
        for k, v in updates.items():
            if k in allowed:
                conn.execute("INSERT OR REPLACE INTO syslog_config VALUES (?,?)", (k, str(v)))
        conn.commit()

# ── 仓库扫描明细 ──────────────────────────────────────────────────
def save_scan_repos(scan_id: int, repos: list):
    now = datetime.now().isoformat()
    with get_conn() as conn:
        for r in repos:
            total = r.get('critical', 0) + r.get('high', 0) + r.get('medium', 0) + r.get('low', 0)
            conn.execute(
                "INSERT INTO scan_repos "
                "(scan_id,repo,source,total_findings,critical_count,high_count,medium_count,low_count,scanned_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id, r['repo'], r.get('source', ''), total,
                 r.get('critical', 0), r.get('high', 0), r.get('medium', 0), r.get('low', 0), now)
            )
        conn.commit()

def save_findings(scan_id: int, scan_results: list):
    """保存每条漏洞发现到 findings 表（含指纹、跨文件标记）"""
    import json as _json
    with get_conn() as conn:
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        for item in scan_results:
            for f in item.get('findings', []):
                cross_files_json = _json.dumps(f.get('cross_files', []), ensure_ascii=False) \
                                   if f.get('is_cross_file') else ''
                conn.execute(
                    "INSERT INTO findings "
                    "(scan_id,repo,commit_sha,commit_url,author,committed_at,"
                    "severity,type,title,filename,line,description,recommendation,"
                    "fingerprint,is_cross_file,cross_files) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (scan_id,
                     item.get('repo', ''),
                     item.get('commit_sha', ''),
                     item.get('commit_url', ''),
                     item.get('author', ''),
                     item.get('committed_at', ''),
                     f.get('severity', 'low'),
                     f.get('type', 'vulnerability'),
                     f.get('title', ''),
                     f.get('filename', ''),
                     str(f.get('line', '')),
                     f.get('description', ''),
                     f.get('recommendation', ''),
                     f.get('fingerprint', ''),
                     1 if f.get('is_cross_file') else 0,
                     cross_files_json)
                )
        conn.commit()

def get_scan_findings(scan_id: int):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id=? "
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END, id",
            (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def get_finding_detail(finding_id: int):
    """获取单条漏洞详情，附带仓库负责人信息（无匹配时回退到提交人）。"""
    import re as _re
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return None
        f = dict(row)
        repo = f.get('repo', '')
        # 去除 "(branch)" 后缀再匹配，如 "org/repo(main)" → "org/repo"
        base_repo = _re.sub(r'\([^)]*\)$', '', repo).strip()
        owner_row = conn.execute(
            "SELECT responsible_person, contact FROM repo_owners "
            "WHERE repo=? OR repo=? ORDER BY id DESC LIMIT 1",
            (repo, base_repo)
        ).fetchone()
        if owner_row and owner_row['responsible_person']:
            f['responsible_person']    = owner_row['responsible_person']
            f['contact']               = owner_row['contact'] or ''
            f['responsible_is_author'] = False
        else:
            f['responsible_person']    = f.get('author', '—')
            f['contact']               = ''
            f['responsible_is_author'] = True
        return f

def get_repos():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT repo, source FROM scan_repos ORDER BY repo"
        ).fetchall()
        return [dict(r) for r in rows]

def get_stats(period: str, repo: str = 'all'):
    today = date.today()

    if period == 'day':
        fmt = '%Y-%m-%d'
        periods = [
            (today - timedelta(days=i)).strftime(fmt)
            for i in range(29, -1, -1)
        ]
        since = (today - timedelta(days=29)).isoformat()
    elif period == 'week':
        fmt = '%Y-W%W'
        periods = [
            (today - timedelta(weeks=i)).strftime(fmt)
            for i in range(11, -1, -1)
        ]
        since = (today - timedelta(weeks=11)).isoformat()
    else:  # year — monthly granularity, last 12 months
        fmt = '%Y-%m'
        periods = []
        for i in range(11, -1, -1):
            m = today.month - i
            y = today.year
            while m <= 0:
                m += 12
                y -= 1
            periods.append(f'{y}-{m:02d}')
        since = periods[0] + '-01'

    with get_conn() as conn:
        if repo and repo != 'all':
            rows = conn.execute(f"""
                SELECT strftime('{fmt}', scanned_at) AS period,
                       SUM(critical_count) AS critical,
                       SUM(high_count)     AS high,
                       SUM(medium_count)   AS medium,
                       SUM(low_count)      AS low
                FROM scan_repos
                WHERE repo = ? AND DATE(scanned_at) >= ?
                GROUP BY period
            """, (repo, since)).fetchall()
        else:
            rows = conn.execute(f"""
                SELECT strftime('{fmt}', started_at) AS period,
                       SUM(critical_count) AS critical,
                       SUM(high_count)     AS high,
                       SUM(medium_count)   AS medium,
                       SUM(low_count)      AS low
                FROM scans
                WHERE status = 'done' AND DATE(started_at) >= ?
                GROUP BY period
            """, (since,)).fetchall()

    data_map = {r['period']: dict(r) for r in rows}
    result = []
    for p in periods:
        row = data_map.get(p, {})
        result.append({
            'period':   p,
            'critical': row.get('critical') or 0,
            'high':     row.get('high')     or 0,
            'medium':   row.get('medium')   or 0,
            'low':      row.get('low')      or 0,
        })
    return result

# ── 提示词管理 ─────────────────────────────────────────────────────
def get_prompts():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id,name,category,extensions,content,is_default,enabled,created_at "
            "FROM prompts ORDER BY is_default DESC, id ASC"
        ).fetchall()
        return [dict(r) for r in rows]

def get_prompts_for_analysis():
    """Return enabled prompts sorted so custom prompts take priority over defaults."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id,name,category,extensions,content,is_default "
            "FROM prompts WHERE enabled=1 ORDER BY is_default ASC, id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

def add_prompt(name, category, extensions, content):
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM prompts WHERE name=?", (name,)).fetchone():
            return False
        conn.execute(
            "INSERT INTO prompts (name,category,extensions,content,is_default,enabled,created_at) "
            "VALUES (?,?,?,?,0,1,?)",
            (name, category, extensions, content, datetime.now().isoformat())
        )
        conn.commit()
        return True

def update_prompt(prompt_id, name, category, extensions, content, enabled):
    with get_conn() as conn:
        row = conn.execute("SELECT name,is_default FROM prompts WHERE id=?", (prompt_id,)).fetchone()
        if not row:
            return False
        # If renaming, check uniqueness
        if name != row['name']:
            if conn.execute("SELECT 1 FROM prompts WHERE name=? AND id!=?", (name, prompt_id)).fetchone():
                return None  # name conflict
        conn.execute(
            "UPDATE prompts SET name=?,category=?,extensions=?,content=?,enabled=? WHERE id=?",
            (name, category, extensions, content, 1 if enabled else 0, prompt_id)
        )
        conn.commit()
        return True

def delete_prompt(prompt_id):
    with get_conn() as conn:
        row = conn.execute("SELECT is_default FROM prompts WHERE id=?", (prompt_id,)).fetchone()
        if not row:
            return False
        if row['is_default']:
            return False  # cannot delete built-in defaults
        conn.execute("DELETE FROM prompts WHERE id=?", (prompt_id,))
        conn.commit()
        return True

def reset_prompt(prompt_id):
    """Reset a default prompt's content back to the original."""
    from default_prompts import FRONTEND_PROMPT, BACKEND_PROMPT, CONTRACT_PROMPT
    defaults = {
        'Frontend':       FRONTEND_PROMPT,
        'Backend':        BACKEND_PROMPT,
        'Smart Contract': CONTRACT_PROMPT,
    }
    with get_conn() as conn:
        row = conn.execute("SELECT name, is_default FROM prompts WHERE id=?", (prompt_id,)).fetchone()
        if not row or not row['is_default']:
            return False
        original = defaults.get(row['name'])
        if not original:
            return False
        conn.execute("UPDATE prompts SET content=? WHERE id=?", (original, prompt_id))
        conn.commit()
        return True

# ── 管理员认证 & 用户管理 ─────────────────────────────────────────
def get_admin_users():
    with get_conn() as conn:
        rows = conn.execute("SELECT username FROM admin_users ORDER BY username").fetchall()
        return [dict(r) for r in rows]

def add_admin_user(username: str, password: str) -> bool:
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM admin_users WHERE username=?", (username,)).fetchone():
            return False
        pwd_hash, salt = _hash_password(password)
        conn.execute("INSERT INTO admin_users VALUES (?,?,?)", (username, pwd_hash, salt))
        conn.commit()
        return True

def delete_admin_user(username: str) -> bool:
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
        if count <= 1:
            return False
        conn.execute("DELETE FROM admin_users WHERE username=?", (username,))
        conn.commit()
        return True

def update_admin_password(username: str, new_password: str) -> bool:
    with get_conn() as conn:
        if not conn.execute("SELECT 1 FROM admin_users WHERE username=?", (username,)).fetchone():
            return False
        pwd_hash, salt = _hash_password(new_password)
        conn.execute("UPDATE admin_users SET password_hash=?, salt=? WHERE username=?",
                     (pwd_hash, salt, username))
        conn.commit()
        return True

def verify_admin(username: str, password: str) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM admin_users WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return False
        computed, _ = _hash_password(password, row['salt'])
        return computed == row['password_hash']

# ── 扫描日志 ──────────────────────────────────────────────────────
def add_scan_log(scan_id: int, level: str, message: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_logs (scan_id, level, message, logged_at) VALUES (?,?,?,?)",
            (scan_id, level, message, datetime.now().isoformat())
        )
        conn.commit()

def get_scan_logs(scan_id: int):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_logs WHERE scan_id=? ORDER BY id",
            (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

# ── 漏洞状态 ──────────────────────────────────────────────────────
def update_finding_status(finding_id: int, status: str) -> bool:
    allowed = {'new', 'fixing', 'fixed', 'wont_fix'}
    if status not in allowed:
        return False
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE findings SET status=? WHERE id=?", (status, finding_id)
        )
        conn.commit()
        return cur.rowcount > 0

# ── 仓库负责人 ────────────────────────────────────────────────────
def get_repo_owners():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM repo_owners ORDER BY source, repo"
        ).fetchall()
        return [dict(r) for r in rows]

def upsert_repo_owner(repo: str, source: str, responsible_person: str, contact: str):
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM repo_owners WHERE repo=? AND source=?", (repo, source)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE repo_owners SET responsible_person=?, contact=? WHERE id=?",
                (responsible_person, contact, existing['id'])
            )
        else:
            conn.execute(
                "INSERT INTO repo_owners (repo, source, responsible_person, contact, created_at) VALUES (?,?,?,?,?)",
                (repo, source, responsible_person, contact, datetime.now().isoformat())
            )
        conn.commit()

def delete_repo_owner(oid: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM repo_owners WHERE id=?", (oid,))
        conn.commit()

def get_repo_owner_map() -> dict:
    """Returns {(repo, source): {responsible_person, contact}} for quick lookup."""
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM repo_owners").fetchall()
        return {(r['repo'], r['source']): dict(r) for r in rows}

# ── 误报白名单 ─────────────────────────────────────────────────────
def get_whitelist():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM finding_whitelist ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

def add_whitelist(repo: str, filename: str, title: str, reason: str, created_by: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO finding_whitelist (repo,filename,title,reason,created_by,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (repo, filename, title, reason, created_by, datetime.now().isoformat())
        )
        conn.commit()
        return cur.lastrowid

def delete_whitelist(wid: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM finding_whitelist WHERE id=?", (wid,))
        conn.commit()

def get_whitelist_set() -> set:
    """返回白名单匹配键集合，用于快速过滤漏洞。
    匹配规则：(repo, filename, title) 三元组，任意字段为空则视为通配。"""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT repo, filename, title FROM finding_whitelist"
        ).fetchall()
        return [(r['repo'], r['filename'], r['title']) for r in rows]

# ── 扫描时间表 ───────────────────────────────────────────────────
def get_scan_schedules(scan_type: str = None):
    with get_conn() as conn:
        if scan_type:
            rows = conn.execute(
                "SELECT id,type,hour,minute,weekday,enabled,label,llm_profile_id FROM scan_schedules "
                "WHERE type=? ORDER BY hour,minute",
                (scan_type,)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id,type,hour,minute,weekday,enabled,label,llm_profile_id FROM scan_schedules "
                "ORDER BY type,hour,minute"
            ).fetchall()
        return [dict(r) for r in rows]

def add_scan_schedule(scan_type: str, hour: int, minute: int,
                      weekday=None, label: str = '', llm_profile_id=None) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scan_schedules (type,hour,minute,weekday,enabled,label,llm_profile_id) VALUES (?,?,?,?,1,?,?)",
            (scan_type, hour, minute, weekday, label, llm_profile_id)
        )
        conn.commit()
        return cur.lastrowid

def toggle_scan_schedule(sid: int, enabled: bool):
    with get_conn() as conn:
        conn.execute("UPDATE scan_schedules SET enabled=? WHERE id=?",
                     (1 if enabled else 0, sid))
        conn.commit()

def delete_scan_schedule(sid: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM scan_schedules WHERE id=?", (sid,))
        conn.commit()

def is_whitelisted(repo: str, filename: str, title: str, whitelist: list) -> bool:
    for w_repo, w_file, w_title in whitelist:
        repo_match  = not w_repo  or w_repo  == repo
        file_match  = not w_file  or w_file  == filename
        title_match = not w_title or w_title == title
        if repo_match and file_match and title_match:
            return True
    return False

# ── LLM 配置列表 ──────────────────────────────────────────────────
def get_llm_profiles():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, provider, model, base_url FROM llm_profiles ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

def get_llm_profile(profile_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM llm_profiles WHERE id=?", (profile_id,)).fetchone()
        return dict(row) if row else None

def add_llm_profile(name: str, provider: str, model: str, api_key: str, base_url: str) -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO llm_profiles (name, provider, model, api_key, base_url) VALUES (?,?,?,?,?)",
            (name, provider, model, api_key, base_url)
        )
        conn.commit()
        return cur.lastrowid

def update_llm_profile(profile_id: int, name: str, provider: str, model: str, api_key: str, base_url: str):
    with get_conn() as conn:
        if api_key and '****' not in api_key:
            conn.execute(
                "UPDATE llm_profiles SET name=?, provider=?, model=?, api_key=?, base_url=? WHERE id=?",
                (name, provider, model, api_key, base_url, profile_id)
            )
        else:
            conn.execute(
                "UPDATE llm_profiles SET name=?, provider=?, model=?, base_url=? WHERE id=?",
                (name, provider, model, base_url, profile_id)
            )
        conn.commit()

def delete_llm_profile(profile_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM llm_profiles WHERE id=?", (profile_id,))
        conn.commit()
