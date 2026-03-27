import os, json, threading, secrets, re, zipfile, io
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
import database as db
import license_manager
from scanner import run_scan
from reporter import build_markdown_report, build_json_report
from notifier import test_channel as notifier_test_channel
import syslog_sender as syslog
from repo_sync import search_synced_code, normalize_repo_name
from clients.github    import test_connection as github_test
from clients.gitlab    import test_connection as gitlab_test
from clients.bitbucket import test_connection as bitbucket_test
from clients.gitee     import test_connection as gitee_test

# ── 登录鉴权 ──────────────────────────────────────────────────────
_sessions: dict = {}          # token -> username
_login_attempts: dict = {}    # username -> {'count': int, 'lock_until': datetime|None}
_MAX_ATTEMPTS = 5
_LOCK_MINUTES = 10

_http_bearer = HTTPBearer(auto_error=False)

def _check_password_strength(password: str):
    """返回错误信息，None 表示通过"""
    if len(password) < 8:
        return '密码长度不能少于 8 位'
    if not re.search(r'[a-z]', password):
        return '密码必须包含小写字母'
    if not re.search(r'[A-Z]', password):
        return '密码必须包含大写字母'
    if not re.search(r'\d', password):
        return '密码必须包含数字'
    return None

def require_auth(credentials: HTTPAuthorizationCredentials = Depends(_http_bearer)):
    if not credentials or credentials.credentials not in _sessions:
        raise HTTPException(status_code=401, detail='未授权，请先登录')
    return _sessions[credentials.credentials]

# ── 初始化 ────────────────────────────────────────────────────────
db.init_db()
db.mark_interrupted_scans()
syslog.reload(db.get_syslog_config())
app = FastAPI(title='春静企业代码安全平台')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

BASE_URL = os.getenv('BASE_URL', 'http://localhost:8000')

# ── 定时任务 ──────────────────────────────────────────────────────
scheduler    = BackgroundScheduler()
_scan_lock   = threading.Lock()
_stop_event  = threading.Event()   # set → 请求停止
_pause_event = threading.Event()   # set → 运行中；clear → 暂停中
_pause_event.set()
_scan_progress_lock = threading.Lock()
_scan_progress = {'percent': 0, 'phase': 'idle', 'message': '', 'updated_at': ''}

def _set_scan_progress(percent=None, phase=None, message=None):
    with _scan_progress_lock:
        if percent is not None:
            _scan_progress['percent'] = max(0, min(100, int(percent)))
        if phase is not None:
            _scan_progress['phase'] = phase
        if message is not None:
            _scan_progress['message'] = message
        _scan_progress['updated_at'] = datetime.now().isoformat()

def _get_scan_progress():
    with _scan_progress_lock:
        return dict(_scan_progress)

_WEEKDAY_CN = ['周一','周二','周三','周四','周五','周六','周日']
_LICENSE_WARN_DAYS = 30
_FEATURE_LABELS = {
    'poison_scan': '投毒检测',
    'incremental_audit': '增量代码审计',
    'full_audit': '全量代码审计',
    'instant_analysis': '即时分析',
}


def _get_license_status():
    cfg = db.get_app_config()
    license_key = (cfg.get('license_key') or '').strip()
    enforce_enabled = cfg.get('license_enforce_enabled', '0') == '1'
    instance_id = license_manager.get_instance_id()
    result = license_manager.verify_license(
        license_key,
        expected_product=license_manager.DEFAULT_PRODUCT,
        expected_machine_id=instance_id,
    )
    payload = result.get('payload') or {}
    expires_at = payload.get('expires_at', '')
    expires_in_days = None
    warning = ''
    if expires_at:
        try:
            expires_dt = license_manager._parse_iso8601(expires_at)
            if expires_dt:
                delta = expires_dt - datetime.now(expires_dt.tzinfo)
                expires_in_days = max(delta.days, 0)
                if result.get('valid') and expires_in_days <= _LICENSE_WARN_DAYS:
                    warning = f'授权将在 {expires_in_days} 天后到期'
        except Exception:
            expires_in_days = None
    return {
        'configured': bool(license_key),
        'enforce_enabled': enforce_enabled,
        'instance_id': instance_id,
        'valid': result.get('valid', False),
        'state': result.get('state', 'missing'),
        'message': result.get('message', '未配置授权码'),
        'product': payload.get('product', license_manager.DEFAULT_PRODUCT),
        'customer': payload.get('customer', ''),
        'issued_at': payload.get('issued_at', ''),
        'expires_at': expires_at,
        'expires_in_days': expires_in_days,
        'warning': warning,
        'features': payload.get('features', []),
        'machine_id': payload.get('machine_id', ''),
        'metadata': payload.get('metadata', {}),
    }


def _license_allows_feature(status: dict, feature: str) -> bool:
    features = status.get('features') or []
    if not features:
        return True
    return feature in features


def _require_license_if_enabled(feature: str = ''):
    status = _get_license_status()
    if status['enforce_enabled'] and not status['valid']:
        raise HTTPException(403, f'产品授权校验失败：{status["message"]}')
    if status['enforce_enabled'] and feature and not _license_allows_feature(status, feature):
        raise HTTPException(403, f'当前授权未开通：{_FEATURE_LABELS.get(feature, feature)}')
    return status

def _run_in_thread(scan_type: str, llm_profile_id=None):
    """在新线程中执行扫描，持有 _scan_lock。"""
    if not _scan_lock.acquire(blocking=False):
        print('[scheduler] 上次扫描未结束，跳过')
        return
    _stop_event.clear()
    _pause_event.set()
    _set_scan_progress(0, 'starting', f'{scan_type} starting')
    try:
        run_scan(BASE_URL, scan_type=scan_type,
                 stop_event=_stop_event, pause_event=_pause_event,
                 llm_profile_id=llm_profile_id,
                 progress_cb=_set_scan_progress)
    finally:
        _scan_lock.release()
        _set_scan_progress(0, 'idle', '')

def _reschedule():
    scheduler.remove_all_jobs()
    for s in db.get_scan_schedules():
        if not s['enabled']:
            continue
        if s['type'] not in {'poison', 'incremental_audit', 'full_audit'}:
            continue
        scan_type      = s['type']
        llm_profile_id = s.get('llm_profile_id')
        h  = s['hour']
        m  = s['minute']
        wd = s.get('weekday')
        fn = lambda st=scan_type, lpid=llm_profile_id: _run_in_thread(st, lpid)
        if h == -1:
            scheduler.add_job(fn, 'cron', hour='*', minute=m, id=f"sched_{s['id']}")
            print(f"[scheduler] {scan_type} #{s['id']}: 每小时第 {m:02d} 分")
        elif wd is not None:
            scheduler.add_job(fn, 'cron', day_of_week=wd, hour=h, minute=m,
                              id=f"sched_{s['id']}")
            print(f"[scheduler] {scan_type} #{s['id']}: 每{_WEEKDAY_CN[wd]} {h:02d}:{m:02d}")
        else:
            scheduler.add_job(fn, 'cron', hour=h, minute=m, id=f"sched_{s['id']}")
            print(f"[scheduler] {scan_type} #{s['id']}: 每天 {h:02d}:{m:02d}")

_reschedule()
scheduler.start()

# ── 静态文件 ──────────────────────────────────────────────────────
os.makedirs('reports', exist_ok=True)
os.makedirs('static', exist_ok=True)
app.mount('/reports', StaticFiles(directory='reports'), name='reports')

@app.get('/', response_class=HTMLResponse)
def index():
    path = os.path.join(os.path.dirname(__file__), 'static', 'index.html')
    return open(path, encoding='utf-8').read()

# ── 登录 / 登出 ───────────────────────────────────────────────────
class LoginIn(BaseModel):
    username: str
    password: str

@app.post('/api/login')
def login(body: LoginIn):
    now = datetime.now()
    username = body.username
    attempt = _login_attempts.get(username, {'count': 0, 'lock_until': None})

    # 检查是否处于锁定期
    if attempt['lock_until'] and now < attempt['lock_until']:
        remaining = int((attempt['lock_until'] - now).total_seconds() / 60) + 1
        syslog.send('warning', 'AUTH', f'登录被拒 (账户锁定): {username}')
        raise HTTPException(403, f'账户已锁定，请 {remaining} 分钟后重试')

    # 锁定已到期则重置
    if attempt['lock_until'] and now >= attempt['lock_until']:
        attempt = {'count': 0, 'lock_until': None}

    if not db.verify_admin(username, body.password):
        attempt['count'] += 1
        if attempt['count'] >= _MAX_ATTEMPTS:
            attempt['lock_until'] = now + timedelta(minutes=_LOCK_MINUTES)
            attempt['count'] = 0
            _login_attempts[username] = attempt
            syslog.send('warning', 'AUTH', f'账户锁定 (连续失败 {_MAX_ATTEMPTS} 次): {username}')
            raise HTTPException(403, f'密码错误次数过多，账户已锁定 {_LOCK_MINUTES} 分钟')
        _login_attempts[username] = attempt
        left = _MAX_ATTEMPTS - attempt['count']
        syslog.send('warning', 'AUTH', f'登录失败 (剩余 {left} 次): {username}')
        raise HTTPException(401, f'用户名或密码错误，还有 {left} 次机会')

    # 登录成功
    _login_attempts.pop(username, None)
    token = secrets.token_hex(32)
    _sessions[token] = username
    syslog.send('info', 'AUTH', f'登录成功: {username}')
    return {'token': token, 'username': username}

@app.post('/api/logout')
def logout(credentials: HTTPAuthorizationCredentials = Depends(_http_bearer)):
    if credentials and credentials.credentials in _sessions:
        user = _sessions.pop(credentials.credentials)
        syslog.send('info', 'AUTH', f'登出: {user}')
    return {'ok': True}

@app.get('/api/me')
def me(username: str = Depends(require_auth)):
    return {'username': username}

# ── 用户管理 API ──────────────────────────────────────────────────
class UserIn(BaseModel):
    username: str
    password: str

class PasswordIn(BaseModel):
    password: str

@app.get('/api/admin-users')
def list_admin_users(_: str = Depends(require_auth)):
    return db.get_admin_users()

@app.post('/api/admin-users')
def create_admin_user(body: UserIn, _: str = Depends(require_auth)):
    if not body.username or len(body.username.strip()) < 2:
        raise HTTPException(400, '用户名至少 2 个字符')
    err = _check_password_strength(body.password)
    if err:
        raise HTTPException(400, err)
    if not db.add_admin_user(body.username.strip(), body.password):
        raise HTTPException(409, '用户名已存在')
    syslog.send('info', 'ADMIN', f'添加用户: {body.username.strip()} by {_}')
    return {'ok': True}

@app.delete('/api/admin-users/{username}')
def delete_admin_user(username: str, current: str = Depends(require_auth)):
    if username == current:
        raise HTTPException(400, '不能删除当前登录的账户')
    if not db.delete_admin_user(username):
        if not any(u['username'] == username for u in db.get_admin_users()):
            raise HTTPException(404, '用户不存在')
        raise HTTPException(400, '至少保留一个管理员账户')
    syslog.send('info', 'ADMIN', f'删除用户: {username} by {current}')
    return {'ok': True}

@app.patch('/api/admin-users/{username}/password')
def change_password(username: str, body: PasswordIn, current: str = Depends(require_auth)):
    err = _check_password_strength(body.password)
    if err:
        raise HTTPException(400, err)
    if not db.update_admin_password(username, body.password):
        raise HTTPException(404, '用户不存在')
    syslog.send('info', 'ADMIN', f'修改密码: {username} by {current}')
    return {'ok': True}

# ── 账户 API ──────────────────────────────────────────────────────
class AccountIn(BaseModel):
    platform: str
    name    : str
    token   : str
    url     : str = ''
    owner   : str = ''

@app.get('/api/accounts')
def list_accounts(_: str = Depends(require_auth)):
    rows = db.get_accounts()
    # 隐藏 token
    for r in rows:
        t = r.get('token', '')
        r['token_masked'] = t[:6] + '****' + t[-4:] if len(t) > 10 else '****'
    return rows

@app.post('/api/accounts')
def create_account(body: AccountIn, _: str = Depends(require_auth)):
    db.add_account(body.platform, body.name, body.token, body.url, body.owner)
    return {'ok': True}

@app.delete('/api/accounts/{aid}')
def remove_account(aid: int, _: str = Depends(require_auth)):
    db.delete_account(aid)
    return {'ok': True}

class AccountTestIn(BaseModel):
    platform: str
    token   : str
    url     : str = ''

@app.post('/api/accounts/test')
def test_account(body: AccountTestIn, _: str = Depends(require_auth)):
    platform = body.platform
    token    = body.token
    url      = body.url.strip() or 'https://gitlab.com'
    if platform == 'github':
        err, user = github_test(token)
    elif platform == 'bitbucket':
        err, user = bitbucket_test(token)
    elif platform == 'gitee':
        err, user = gitee_test(token)
    elif platform in ('tgit', 'codeup'):
        _default_urls = {'tgit': 'https://git.code.tencent.com', 'codeup': 'https://codeup.aliyun.com'}
        base = body.url.strip() or _default_urls[platform]
        err, user = gitlab_test(token, base)
    else:  # gitlab
        err, user = gitlab_test(token, url)
    if err:
        raise HTTPException(400, f'连接失败: {err}')
    return {'ok': True, 'msg': f'连接成功，当前用户: {user}'}

# ── 通知渠道 API ──────────────────────────────────────────────────
class ChannelIn(BaseModel):
    name  : str
    type  : str
    config: dict

@app.get('/api/channels')
def list_channels(_: str = Depends(require_auth)):
    return db.get_channels()

@app.post('/api/channels')
def create_channel(body: ChannelIn, _: str = Depends(require_auth)):
    db.add_channel(body.name, body.type, body.config)
    return {'ok': True}

@app.patch('/api/channels/{cid}')
def toggle_channel(cid: int, body: dict, _: str = Depends(require_auth)):
    db.toggle_channel(cid, body.get('enabled', True))
    return {'ok': True}

class ChannelUpdateIn(BaseModel):
    name  : str
    config: dict

@app.put('/api/channels/{cid}')
def update_channel(cid: int, body: ChannelUpdateIn, _: str = Depends(require_auth)):
    if not body.name.strip():
        raise HTTPException(400, '渠道名称不能为空')
    db.update_channel(cid, body.name.strip(), body.config)
    return {'ok': True}

@app.delete('/api/channels/{cid}')
def remove_channel(cid: int, _: str = Depends(require_auth)):
    db.delete_channel(cid)
    return {'ok': True}

@app.post('/api/channels/{cid}/test')
def test_channel_api(cid: int, _: str = Depends(require_auth)):
    channels = db.get_channels()
    ch = next((c for c in channels if c['id'] == cid), None)
    if not ch:
        raise HTTPException(404, '渠道不存在')
    cfg = json.loads(ch.get('config', '{}'))
    err = notifier_test_channel(ch['type'], cfg)
    if err:
        raise HTTPException(400, f'发送失败: {err}')
    return {'ok': True, 'msg': f'测试消息已发送至 {ch["name"]}'}

# ── LLM 配置 API ─────────────────────────────────────────────────
# ── LLM 配置列表 API ──────────────────────────────────────────────
class LLMProfileIn(BaseModel):
    name    : str
    provider: str
    model   : str = ''
    api_key : str = ''
    base_url: str = ''

@app.get('/api/llm-profiles')
def list_llm_profiles(_: str = Depends(require_auth)):
    return db.get_llm_profiles()

@app.post('/api/llm-profiles')
def add_llm_profile(body: LLMProfileIn, _: str = Depends(require_auth)):
    if not body.name.strip() or not body.provider.strip():
        raise HTTPException(400, '名称和提供商不能为空')
    pid = db.add_llm_profile(body.name.strip(), body.provider, body.model, body.api_key, body.base_url)
    return {'ok': True, 'id': pid}

@app.put('/api/llm-profiles/{pid}')
def update_llm_profile(pid: int, body: LLMProfileIn, _: str = Depends(require_auth)):
    if not db.get_llm_profile(pid):
        raise HTTPException(404, '配置不存在')
    db.update_llm_profile(pid, body.name.strip(), body.provider, body.model, body.api_key, body.base_url)
    return {'ok': True}

@app.delete('/api/llm-profiles/{pid}')
def delete_llm_profile(pid: int, _: str = Depends(require_auth)):
    db.delete_llm_profile(pid)
    return {'ok': True}

@app.post('/api/llm-profiles/{pid}/test')
def test_llm_profile(pid: int, _: str = Depends(require_auth)):
    from analyzer import build_llm_caller
    profile = db.get_llm_profile(pid)
    if not profile:
        raise HTTPException(404, '配置不存在')
    llm_cfg = {'provider': profile['provider'], 'model': profile['model'],
               'api_key': profile['api_key'], 'base_url': profile['base_url']}
    call_fn = build_llm_caller(llm_cfg)
    if not call_fn:
        raise HTTPException(400, '未配置 API Key')
    try:
        reply = call_fn('Reply with exactly one word: OK')
        return {'ok': True, 'reply': reply.strip()}
    except Exception as e:
        raise HTTPException(502, str(e))

_SENSITIVE_LLM_KEYS = {'api_key'}

class LLMConfig(BaseModel):
    provider : str = ''
    model    : str = ''
    api_key  : str = ''
    base_url : str = ''

@app.get('/api/llm-config')
def get_llm(_: str = Depends(require_auth)):
    cfg = db.get_llm_config()
    # 仅返回新版字段，隐藏旧版兼容字段
    cfg = {k: cfg.get(k, '') for k in ('provider', 'model', 'api_key', 'base_url')}
    def mask(k, v):
        if k in _SENSITIVE_LLM_KEYS:
            return v[:8] + '****' if len(v) > 8 else ('****' if v else '')
        return v
    return {k: mask(k, v) for k, v in cfg.items()}

@app.post('/api/llm-config')
def save_llm(body: LLMConfig, _: str = Depends(require_auth)):
    if body.provider is not None:
        db.set_llm_config('provider', body.provider)
    if body.model is not None:
        db.set_llm_config('model', body.model)
    if body.base_url is not None:
        db.set_llm_config('base_url', body.base_url)
    if body.api_key and '****' not in body.api_key:
        db.set_llm_config('api_key', body.api_key)
    return {'ok': True}

@app.post('/api/llm-config/test')
def test_llm(_: str = Depends(require_auth)):
    from analyzer import build_llm_caller
    llm_cfg = db.get_llm_config()
    call_fn = build_llm_caller(llm_cfg)
    if not call_fn:
        raise HTTPException(400, '未配置 LLM，请先填写提供商和 API Key')
    try:
        reply = call_fn('Reply with exactly one word: OK')
        return {'ok': True, 'reply': reply.strip()}
    except Exception as e:
        raise HTTPException(502, str(e))

# ── 应用设置 API ──────────────────────────────────────────────────
@app.get('/api/settings')
def get_settings(_: str = Depends(require_auth)):
    return db.get_app_config()

@app.post('/api/settings')
def save_settings(body: dict, _: str = Depends(require_auth)):
    for k, v in body.items():
        db.set_app_config(k, v)
    _reschedule()
    return {'ok': True}


@app.get('/api/license-status')
def get_license_status(_: str = Depends(require_auth)):
    return _get_license_status()


class LicenseConfigIn(BaseModel):
    license_key: str = ''
    replace_license_key: bool = False
    enforce_enabled: bool = False


@app.post('/api/license-config')
def save_license_config(body: LicenseConfigIn, _: str = Depends(require_auth)):
    if body.replace_license_key:
        db.set_app_config('license_key', body.license_key.strip())
    db.set_app_config('license_enforce_enabled', '1' if body.enforce_enabled else '0')
    return {'ok': True, 'status': _get_license_status()}

# ── 扫描时间表 API ────────────────────────────────────────────────
_VALID_TYPES = {'poison', 'incremental_audit', 'full_audit'}

class ScanScheduleIn(BaseModel):
    type          : str
    hour          : int          # -1 = 每小时
    minute        : int = 0
    weekday       : int = None   # None=每天, 0-6=指定星期
    label         : str = ''
    llm_profile_id: int = None

@app.get('/api/scan-schedules')
def list_scan_schedules(_: str = Depends(require_auth)):
    return db.get_scan_schedules()

@app.post('/api/scan-schedules')
def add_scan_schedule(body: ScanScheduleIn, _: str = Depends(require_auth)):
    if body.type not in _VALID_TYPES:
        raise HTTPException(400, f'无效类型，可选: {", ".join(_VALID_TYPES)}')
    if body.hour != -1 and not (0 <= body.hour <= 23):
        raise HTTPException(400, '小时必须在 0-23 之间，或 -1 表示每小时')
    if not (0 <= body.minute <= 59):
        raise HTTPException(400, '分钟必须在 0-59 之间')
    if body.weekday is not None and not (0 <= body.weekday <= 6):
        raise HTTPException(400, '星期必须在 0-6 之间')
    sid = db.add_scan_schedule(body.type, body.hour, body.minute,
                               body.weekday, body.label.strip(), body.llm_profile_id)
    _reschedule()
    return {'ok': True, 'id': sid}

@app.patch('/api/scan-schedules/{sid}')
def toggle_scan_schedule(sid: int, body: dict, _: str = Depends(require_auth)):
    db.toggle_scan_schedule(sid, body.get('enabled', True))
    _reschedule()
    return {'ok': True}

@app.delete('/api/scan-schedules/{sid}')
def delete_scan_schedule(sid: int, _: str = Depends(require_auth)):
    db.delete_scan_schedule(sid)
    _reschedule()
    return {'ok': True}

# ── 扫描 API ──────────────────────────────────────────────────────
_SCAN_TYPE_LABELS = {
    'poison'           : '投毒检测',
    'incremental_audit': '增量代码审计',
    'full_audit'       : '全量代码审计',
}

class ScanTrigger(BaseModel):
    scan_type     : str  = 'incremental_audit'
    llm_profile_id: int  = None
    # 旧版兼容
    full_scan     : bool = False

@app.post('/api/scan/trigger')
def trigger_scan(body: ScanTrigger = ScanTrigger(), operator: str = Depends(require_auth)):
    scan_type = body.scan_type
    if body.full_scan and scan_type == 'incremental_audit':
        scan_type = 'full_audit'
    if scan_type not in _SCAN_TYPE_LABELS:
        raise HTTPException(400, f'无效类型，可选: {", ".join(_SCAN_TYPE_LABELS)}')
    feature_key = 'poison_scan' if scan_type == 'poison' else scan_type
    _require_license_if_enabled(feature_key)
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(400, '扫描正在进行中')
    _stop_event.clear()
    _pause_event.set()
    _set_scan_progress(0, 'starting', f'{scan_type} starting')
    label = _SCAN_TYPE_LABELS[scan_type]
    syslog.send('info', 'SCAN', f'{label}由 {operator} 触发')
    llm_profile_id = body.llm_profile_id
    def _run():
        try:
            run_scan(BASE_URL, scan_type=scan_type,
                     stop_event=_stop_event, pause_event=_pause_event,
                     manual=True, llm_profile_id=llm_profile_id,
                     progress_cb=_set_scan_progress)
        finally:
            _scan_lock.release()
            _set_scan_progress(0, 'idle', '')
    threading.Thread(target=_run, daemon=True).start()
    return {'ok': True, 'msg': f'{label}已启动'}

@app.post('/api/scan/stop')
def stop_scan(operator: str = Depends(require_auth)):
    if _scan_lock.acquire(blocking=False):
        _scan_lock.release()
        raise HTTPException(400, '当前没有正在进行的扫描')
    _stop_event.set()
    _pause_event.set()   # 解除暂停，让线程能检测到 stop
    syslog.send('info', 'SCAN', f'扫描被 {operator} 手动停止')
    return {'ok': True, 'msg': '已发送停止信号'}

@app.post('/api/scan/pause')
def pause_scan(operator: str = Depends(require_auth)):
    if _scan_lock.acquire(blocking=False):
        _scan_lock.release()
        raise HTTPException(400, '当前没有正在进行的扫描')
    _pause_event.clear()
    # 更新 DB 中正在运行的扫描状态为 paused
    running = [s for s in db.get_scans(limit=5) if s['status'] == 'running']
    if running:
        db.update_scan_status(running[0]['id'], 'paused')
    syslog.send('info', 'SCAN', f'扫描被 {operator} 暂停')
    return {'ok': True, 'msg': '扫描已暂停'}

@app.post('/api/scan/resume')
def resume_scan(operator: str = Depends(require_auth)):
    if _scan_lock.acquire(blocking=False):
        _scan_lock.release()
        raise HTTPException(400, '当前没有正在进行的扫描')
    _pause_event.set()
    # 更新 DB 中暂停的扫描状态为 running
    paused = [s for s in db.get_scans(limit=5) if s['status'] == 'paused']
    if paused:
        db.update_scan_status(paused[0]['id'], 'running')
    syslog.send('info', 'SCAN', f'扫描被 {operator} 恢复')
    return {'ok': True, 'msg': '扫描已恢复'}

@app.get('/api/scans')
def list_scans(_: str = Depends(require_auth)):
    return db.get_scans()

@app.delete('/api/scans/{scan_id}')
def delete_scan(scan_id: int, _: str = Depends(require_auth)):
    # 禁止删除正在运行的扫描
    row = db.get_scans(limit=200)
    target = next((s for s in row if s['id'] == scan_id), None)
    if not target:
        raise HTTPException(404, '扫描记录不存在')
    if target['status'] in ('running', 'paused'):
        raise HTTPException(400, '无法删除正在运行或暂停中的扫描，请先停止')
    db.delete_scan(scan_id)
    return {'ok': True}

@app.post('/api/scans/{scan_id}/rerun')
def rerun_scan(scan_id: int, operator: str = Depends(require_auth)):
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(400, '扫描正在进行中，请等待结束后重新扫描')
    row = db.get_scans(limit=200)
    target = next((s for s in row if s['id'] == scan_id), None)
    if not target:
        _scan_lock.release()
        raise HTTPException(404, '扫描记录不存在')
    scan_type = target.get('scan_type') or 'incremental_audit'
    # 兼容旧记录
    if scan_type == 'full':
        scan_type = 'full_audit'
    elif scan_type == 'incremental':
        scan_type = 'incremental_audit'
    feature_key = 'poison_scan' if scan_type == 'poison' else scan_type
    _require_license_if_enabled(feature_key)
    _stop_event.clear()
    _pause_event.set()
    _set_scan_progress(0, 'starting', f'{scan_type} rerun starting')
    label          = _SCAN_TYPE_LABELS.get(scan_type, scan_type)
    llm_profile_id = target.get('llm_profile_id')
    syslog.send('info', 'SCAN', f'{label}（重新运行 #{scan_id}）由 {operator} 触发')
    def _run():
        try:
            run_scan(BASE_URL, scan_type=scan_type,
                     stop_event=_stop_event, pause_event=_pause_event,
                     manual=True, llm_profile_id=llm_profile_id,
                     progress_cb=_set_scan_progress)
        finally:
            _scan_lock.release()
            _set_scan_progress(0, 'idle', '')
    threading.Thread(target=_run, daemon=True).start()
    return {'ok': True, 'msg': f'{label}已重新启动'}

@app.get('/api/scans/{scan_id}/findings')
def get_findings(scan_id: int, _: str = Depends(require_auth)):
    return db.get_scan_findings(scan_id)

@app.get('/api/scans/{scan_id}/logs')
def get_scan_logs(scan_id: int, _: str = Depends(require_auth)):
    return db.get_scan_logs(scan_id)

def _build_docx_report(scan_results):
    """生成 Word 格式审计报告，返回 bytes。"""
    from docx import Document
    from docx.shared import Pt, RGBColor, Cm
    from docx.oxml.ns import qn
    SEV_ZH = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '信息'}
    SEV_COLOR = {'critical': 'FF4D4F', 'high': 'FA8C16', 'medium': 'D4B106', 'low': '52C41A', 'info': '1677FF'}
    doc = Document()
    # 页边距
    for section in doc.sections:
        section.top_margin = Cm(2); section.bottom_margin = Cm(2)
        section.left_margin = Cm(2.5); section.right_margin = Cm(2.5)
    doc.add_heading('代码安全审计报告', 0)
    doc.add_paragraph(f'生成时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    total = sum(len(e.get('findings', [])) for e in scan_results)
    doc.add_paragraph(f'共发现漏洞：{total} 个，涉及仓库：{len(scan_results)} 个')
    doc.add_paragraph()
    for entry in scan_results:
        doc.add_heading(f'仓库：{entry["repo"]}', level=1)
        meta = doc.add_paragraph()
        meta.add_run('提交 SHA：').bold = True
        meta.add_run(entry.get('commit_sha', '-')[:12])
        meta.add_run('　作者：').bold = True
        meta.add_run(entry.get('author', '-'))
        if entry.get('committed_at'):
            meta.add_run(f'　时间：{entry["committed_at"]}')
        findings = entry.get('findings', [])
        if not findings:
            doc.add_paragraph('（本提交无发现漏洞）')
            continue
        for finding in findings:
            sev = finding.get('severity', 'info')
            sev_zh = SEV_ZH.get(sev, sev)
            h = doc.add_heading(f'[{sev_zh}] {finding.get("title", "未知漏洞")}', level=2)
            run = h.runs[0] if h.runs else None
            if run:
                color = SEV_COLOR.get(sev, '1677FF')
                run.font.color.rgb = RGBColor(int(color[:2],16), int(color[2:4],16), int(color[4:],16))
            if finding.get('filename'):
                p = doc.add_paragraph()
                p.add_run('文件：').bold = True
                p.add_run(finding['filename'])
            if finding.get('description'):
                doc.add_paragraph(finding['description'])
            if finding.get('recommendation'):
                p2 = doc.add_paragraph()
                p2.add_run('修复建议：').bold = True
                p2.add_run(finding['recommendation'])
            doc.add_paragraph()
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()

@app.get('/api/scans/{scan_id}/export')
def export_scan(scan_id: int, format: str = 'json', _: str = Depends(require_auth)):
    """导出扫描结果为 json / markdown / docx 格式。"""
    if format not in ('json', 'markdown', 'docx'):
        raise HTTPException(400, '无效格式，可选：json / markdown / docx')
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, '扫描记录不存在')
    findings = db.get_scan_findings(scan_id)
    # 重组为 build_*_report 所需的 scan_results 格式
    commit_map: dict = {}
    for f in findings:
        key = (f['commit_sha'], f['repo'])
        if key not in commit_map:
            commit_map[key] = {
                'repo'        : f['repo'],
                'source'      : '',
                'commit_sha'  : f['commit_sha'],
                'commit_url'  : f['commit_url'],
                'author'      : f['author'],
                'message'     : '',
                'committed_at': f['committed_at'],
                'files'       : [],
                'findings'    : [],
            }
        commit_map[key]['findings'].append(f)
    scan_results = list(commit_map.values())
    if format == 'json':
        data = build_json_report(scan_results)
        return Response(
            content=json.dumps(data, ensure_ascii=False, indent=2),
            media_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="scan_{scan_id}.json"'}
        )
    elif format == 'docx':
        content = _build_docx_report(scan_results)
        return Response(
            content=content,
            media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            headers={'Content-Disposition': f'attachment; filename="scan_{scan_id}.docx"'}
        )
    else:
        md = build_markdown_report(scan_results)
        return Response(
            content=md,
            media_type='text/markdown; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename="scan_{scan_id}.md"'}
        )

@app.get('/api/findings/{finding_id}')
def get_finding(finding_id: int, _: str = Depends(require_auth)):
    """获取单条漏洞详情，含仓库负责人信息。"""
    f = db.get_finding_detail(finding_id)
    if not f:
        raise HTTPException(404, '漏洞不存在')
    return f

class FindingStatusIn(BaseModel):
    status: str

@app.patch('/api/findings/{finding_id}/status')
def update_finding_status(finding_id: int, body: FindingStatusIn, _: str = Depends(require_auth)):
    if not db.update_finding_status(finding_id, body.status):
        raise HTTPException(400, '无效的状态值或漏洞不存在')
    return {'ok': True}

@app.get('/api/stats')
def get_stats_api(period: str = 'day', repo: str = 'all', _: str = Depends(require_auth)):
    if period not in ('day', 'week', 'year'):
        raise HTTPException(400, '无效的统计周期，可选：day / week / year')
    return db.get_stats(period, repo)

@app.get('/api/repos')
def list_repos(_: str = Depends(require_auth)):
    return db.get_repos()

@app.get('/api/repo-sync-status')
def repo_sync_status(_: str = Depends(require_auth)):
    return db.get_repo_sync_status()

@app.get('/api/components')
def list_components(keyword: str = '', repo: str = '', source: str = '',
                    ecosystem: str = '', limit: int = 500,
                    _: str = Depends(require_auth)):
    return db.query_components(keyword=keyword, repo=repo, source=source,
                               ecosystem=ecosystem, limit=limit)

@app.get('/api/components/summary')
def component_summary(_: str = Depends(require_auth)):
    return db.get_component_summary()

class EmergencyDependencyIn(BaseModel):
    keyword: str
    exact: bool = False
    source: str = ''
    repo: str = ''
    ecosystem: str = ''
    limit: int = 500

@app.post('/api/emergency/dependency-check')
def emergency_dependency_check(body: EmergencyDependencyIn, _: str = Depends(require_auth)):
    keyword = body.keyword.strip()
    if not keyword:
        raise HTTPException(400, '依赖关键字不能为空')
    rows = db.query_components(
        keyword='' if body.exact else keyword,
        repo=normalize_repo_name(body.repo),
        source=body.source.strip(),
        ecosystem=body.ecosystem.strip(),
        limit=body.limit,
    )
    if body.exact:
        rows = [r for r in rows if (r.get('component', '').lower() == keyword.lower())]
    return {
        'keyword': keyword,
        'exact': body.exact,
        'total': len(rows),
        'hits': rows,
    }

class EmergencyCodeSearchIn(BaseModel):
    keyword: str
    case_sensitive: bool = False
    source: str = ''
    repo: str = ''
    limit: int = 200

@app.post('/api/emergency/code-search')
def emergency_code_search(body: EmergencyCodeSearchIn, _: str = Depends(require_auth)):
    keyword = body.keyword.strip()
    if not keyword:
        raise HTTPException(400, '检索关键词不能为空')
    hits = search_synced_code(
        keyword=keyword,
        case_sensitive=body.case_sensitive,
        source=body.source.strip(),
        repo=normalize_repo_name(body.repo),
        limit=body.limit,
    )
    return {'keyword': keyword, 'total': len(hits), 'hits': hits}

# ── 仓库负责人 API ────────────────────────────────────────────────
class RepoOwnerIn(BaseModel):
    repo               : str
    source             : str = ''
    responsible_person : str = ''
    contact            : str = ''

@app.get('/api/repo-owners')
def list_repo_owners(_: str = Depends(require_auth)):
    return db.get_repo_owners()

@app.post('/api/repo-owners')
def save_repo_owner(body: RepoOwnerIn, _: str = Depends(require_auth)):
    if not body.repo.strip():
        raise HTTPException(400, '仓库路径不能为空')
    db.upsert_repo_owner(body.repo.strip(), body.source.strip(), body.responsible_person.strip(), body.contact.strip())
    return {'ok': True}

@app.delete('/api/repo-owners/{oid}')
def remove_repo_owner(oid: int, _: str = Depends(require_auth)):
    db.delete_repo_owner(oid)
    return {'ok': True}

@app.get('/api/repo-owner-map')
def get_repo_owner_map(_: str = Depends(require_auth)):
    raw = db.get_repo_owner_map()
    # Convert tuple keys to string keys for JSON
    return {f"{k[0]}|{k[1]}": v for k, v in raw.items()}

# ── 提示词管理 API ─────────────────────────────────────────────────
class PromptIn(BaseModel):
    name      : str
    category  : str = 'custom'
    extensions: str = ''
    content   : str
    enabled   : bool = True

@app.get('/api/prompts')
def list_prompts(_: str = Depends(require_auth)):
    return db.get_prompts()

@app.post('/api/prompts')
def create_prompt(body: PromptIn, _: str = Depends(require_auth)):
    if not body.name.strip():
        raise HTTPException(400, '名称不能为空')
    if not body.content.strip():
        raise HTTPException(400, '提示词内容不能为空')
    if not db.add_prompt(body.name.strip(), body.category, body.extensions, body.content):
        raise HTTPException(409, '名称已存在')
    return {'ok': True}

@app.put('/api/prompts/{pid}')
def update_prompt(pid: int, body: PromptIn, _: str = Depends(require_auth)):
    if not body.name.strip():
        raise HTTPException(400, '名称不能为空')
    result = db.update_prompt(pid, body.name.strip(), body.category,
                               body.extensions, body.content, body.enabled)
    if result is None:
        raise HTTPException(409, '名称已存在')
    if not result:
        raise HTTPException(404, '提示词不存在')
    return {'ok': True}

@app.delete('/api/prompts/{pid}')
def delete_prompt(pid: int, _: str = Depends(require_auth)):
    if not db.delete_prompt(pid):
        raise HTTPException(400, '内置提示词不可删除，或不存在')
    return {'ok': True}

@app.post('/api/prompts/{pid}/reset')
def reset_prompt(pid: int, _: str = Depends(require_auth)):
    if not db.reset_prompt(pid):
        raise HTTPException(400, '仅内置提示词支持重置')
    return {'ok': True}

# ── 白名单 API ───────────────────────────────────────────────────
class WhitelistIn(BaseModel):
    repo    : str = ''
    filename: str = ''
    title   : str = ''
    reason  : str = ''

@app.get('/api/whitelist')
def list_whitelist(_: str = Depends(require_auth)):
    return db.get_whitelist()

@app.post('/api/whitelist')
def add_whitelist(body: WhitelistIn, operator: str = Depends(require_auth)):
    if not body.repo and not body.filename and not body.title:
        raise HTTPException(400, '至少填写一个匹配条件（仓库、文件名或漏洞标题）')
    wid = db.add_whitelist(body.repo, body.filename, body.title, body.reason, operator)
    syslog.send('info', 'WHITELIST', f'添加白名单 #{wid}: repo={body.repo} file={body.filename} title={body.title}')
    return {'ok': True, 'id': wid}

@app.delete('/api/whitelist/{wid}')
def remove_whitelist(wid: int, operator: str = Depends(require_auth)):
    db.delete_whitelist(wid)
    syslog.send('info', 'WHITELIST', f'删除白名单 #{wid} by {operator}')
    return {'ok': True}

# ── Syslog 配置 API ───────────────────────────────────────────────
@app.get('/api/syslog-config')
def get_syslog(_: str = Depends(require_auth)):
    return db.get_syslog_config()

@app.post('/api/syslog-config')
def save_syslog(body: dict, _: str = Depends(require_auth)):
    db.set_syslog_config(body)
    syslog.reload(db.get_syslog_config())
    return {'ok': True}

@app.post('/api/syslog-test')
def test_syslog(_: str = Depends(require_auth)):
    cfg = db.get_syslog_config()
    if not cfg.get('host', '').strip():
        raise HTTPException(400, '请先填写 Syslog 服务器地址')
    err = syslog.test_send({**cfg, 'enabled': '1'})
    if err:
        raise HTTPException(400, f'发送失败: {err}')
    return {'ok': True, 'msg': f'测试消息已发送至 {cfg["host"]}:{cfg.get("port", 514)}'}

# ── 即时代码分析 API ──────────────────────────────────────────────
class InstantAnalysisIn(BaseModel):
    filename: str
    code    : str
    language: str = ''
    llm_profile_id: Optional[int] = None


def _resolve_llm_config(llm_profile_id: Optional[int]):
    if llm_profile_id:
        profile = db.get_llm_profile(llm_profile_id)
        if profile:
            return {
                'provider': profile['provider'],
                'model': profile['model'],
                'api_key': profile['api_key'],
                'base_url': profile['base_url'],
            }
    return db.get_llm_config()

@app.post('/api/analyze/instant')
def instant_analyze(body: InstantAnalysisIn, _: str = Depends(require_auth)):
    """对任意代码片段直接进行 LLM 安全分析，无需 git commit。"""
    _require_license_if_enabled('instant_analysis')
    from analyzer import build_llm_caller, _find_prompt, _parse, AUDIT_EXTENSIONS, SKIP_EXTENSIONS
    import os as _os

    filename = body.filename.strip() or 'snippet.py'
    code     = body.code.strip()
    if not code:
        raise HTTPException(400, '代码内容不能为空')
    if len(code) > 30000:
        raise HTTPException(400, '代码内容过长，最多 30000 字符')

    llm_cfg = _resolve_llm_config(body.llm_profile_id)
    call_fn = build_llm_caller(llm_cfg)
    if not call_fn:
        raise HTTPException(400, '未配置 LLM，请先在 AI 配置中填写 API Key')

    prompts = db.get_prompts_for_analysis()
    prompt_tpl = _find_prompt(filename, prompts)
    if not prompt_tpl:
        # fallback to backend prompt
        backend_prompts = [p for p in prompts if p.get('category') == 'backend']
        prompt_tpl = backend_prompts[0]['content'] if backend_prompts else prompts[0]['content'] if prompts else None
    if not prompt_tpl:
        raise HTTPException(500, '未找到可用提示词')

    # 构造一个"全量 diff"形式（+行前缀）
    diff = '\n'.join(f'+{line}' for line in code.splitlines())
    prompt = prompt_tpl.format(filename=filename, message='即时分析', diff=diff)
    try:
        raw    = call_fn(prompt)
        result = _parse(raw)
        return {
            'filename': filename,
            'findings': result.get('findings', []),
            'summary' : result.get('summary', ''),
        }
    except Exception as e:
        raise HTTPException(500, f'LLM 分析失败: {e}')

@app.post('/api/analyze/instant-upload')
async def instant_analyze_upload(
    files: List[UploadFile] = File(...),
    llm_profile_id: Optional[int] = Form(None),
    credentials: HTTPAuthorizationCredentials = Depends(_http_bearer)
):
    """上传文件/文件夹/压缩包进行 LLM 安全分析。"""
    _ = require_auth(credentials)
    _require_license_if_enabled('instant_analysis')
    from analyzer import build_llm_caller, _find_prompt, _parse, AUDIT_EXTENSIONS, SKIP_EXTENSIONS

    _MAX_FILE_SIZE  = 300_000   # 单文件最大 300 KB
    _MAX_TOTAL_SIZE = 1_000_000 # 总计最大 1 MB
    _MAX_FILES      = 50        # 最多分析 50 个文件

    llm_cfg = _resolve_llm_config(llm_profile_id)
    call_fn = build_llm_caller(llm_cfg)
    if not call_fn:
        raise HTTPException(400, '未配置 LLM，请先在 AI 配置中填写 API Key')

    prompts = db.get_prompts_for_analysis()

    def _should_analyze(fname: str) -> bool:
        _, ext = os.path.splitext(fname)
        ext = ext.lower()
        base = os.path.basename(fname)
        if ext in SKIP_EXTENSIONS:
            return False
        return ext in AUDIT_EXTENSIONS or base in AUDIT_EXTENSIONS

    # 收集 (filename, content_bytes) 列表
    collected: list[tuple[str, bytes]] = []
    total_bytes = 0

    for upload in files:
        raw = await upload.read()
        fname = upload.filename or 'file'

        # zip 压缩包：展开
        _, ext = os.path.splitext(fname)
        if ext.lower() == '.zip':
            try:
                with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                    for entry in zf.infolist():
                        if entry.is_dir():
                            continue
                        entry_name = entry.filename.lstrip('/')
                        if not _should_analyze(entry_name):
                            continue
                        data = zf.read(entry)
                        if len(data) > _MAX_FILE_SIZE:
                            continue
                        collected.append((entry_name, data))
                        total_bytes += len(data)
                        if total_bytes > _MAX_TOTAL_SIZE or len(collected) >= _MAX_FILES:
                            break
            except zipfile.BadZipFile:
                raise HTTPException(400, f'{fname} 不是有效的 ZIP 文件')
        else:
            if not _should_analyze(fname):
                continue
            if len(raw) > _MAX_FILE_SIZE:
                continue
            collected.append((fname, raw))
            total_bytes += len(raw)

        if total_bytes > _MAX_TOTAL_SIZE or len(collected) >= _MAX_FILES:
            break

    if not collected:
        raise HTTPException(400, '未找到可分析的代码文件（不支持的类型或文件过大）')

    def _analyze_one(fname: str, data: bytes):
        try:
            code = data.decode('utf-8', errors='replace')
        except Exception:
            return {'filename': fname, 'findings': [], 'summary': '文件解码失败', 'error': True}
        if not code.strip():
            return {'filename': fname, 'findings': [], 'summary': '文件为空'}

        prompt_tpl = _find_prompt(fname, prompts)
        if not prompt_tpl:
            backend_prompts = [p for p in prompts if p.get('category') == 'backend']
            prompt_tpl = (backend_prompts[0]['content'] if backend_prompts
                          else prompts[0]['content'] if prompts else None)
        if not prompt_tpl:
            return {'filename': fname, 'findings': [], 'summary': '未找到可用提示词', 'error': True}

        diff = '\n'.join(f'+{line}' for line in code.splitlines())
        prompt = prompt_tpl.format(filename=fname, message='即时分析', diff=diff)
        try:
            raw_resp = call_fn(prompt)
            result   = _parse(raw_resp)
            return {
                'filename': fname,
                'findings': result.get('findings', []),
                'summary' : result.get('summary', ''),
            }
        except Exception as e:
            return {'filename': fname, 'findings': [], 'summary': f'LLM 分析失败: {e}', 'error': True}

    import concurrent.futures
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(_analyze_one, fn, data): fn for fn, data in collected}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    results.sort(key=lambda r: r['filename'])
    total_findings = sum(len(r['findings']) for r in results)
    return {'files': results, 'total_findings': total_findings}


@app.get('/api/status')
def status(_: str = Depends(require_auth)):
    scanning = not _scan_lock.acquire(blocking=False)
    if not scanning:
        _scan_lock.release()

    schedules_out = []
    for s in db.get_scan_schedules():
        job = scheduler.get_job(f"sched_{s['id']}")
        schedules_out.append({
            'id'      : s['id'],
            'type'    : s['type'],
            'hour'    : s['hour'],
            'minute'  : s['minute'],
            'weekday' : s.get('weekday'),
            'enabled' : bool(s['enabled']),
            'label'   : s.get('label', ''),
            'next_run': str(job.next_run_time) if job else None,
        })

    return {
        'scheduler_running': scheduler.running,
        'scanning'         : scanning,
        'paused'           : scanning and not _pause_event.is_set(),
        'progress'         : _get_scan_progress() if scanning else None,
        'schedules'        : schedules_out,
        'license'          : _get_license_status(),
    }

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app:app', host='0.0.0.0', port=8000, reload=False)
