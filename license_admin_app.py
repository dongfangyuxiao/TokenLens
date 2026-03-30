import json
import os
import re
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

import database as db
import license_manager
import syslog_sender as syslog

_sessions: dict = {}
_login_attempts: dict = {}
_MAX_ATTEMPTS = 5
_LOCK_MINUTES = 10
_SESSION_TTL_MINUTES = max(10, int(os.getenv('SESSION_TTL_MINUTES', '720')))
_SESSION_IDLE_MINUTES = max(5, int(os.getenv('SESSION_IDLE_MINUTES', '120')))
_http_bearer = HTTPBearer(auto_error=False)

db.init_db()
syslog.reload(db.get_syslog_config())
app = FastAPI(title='SpringStillness 授权管理系统')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])


def _purge_expired_sessions():
    now = datetime.now()
    dead = []
    for tok, sess in list(_sessions.items()):
        expires_at = sess.get('expires_at') if isinstance(sess, dict) else None
        last_seen = sess.get('last_seen') if isinstance(sess, dict) else None
        if not isinstance(expires_at, datetime) or not isinstance(last_seen, datetime):
            dead.append(tok)
            continue
        if now > expires_at or now - last_seen > timedelta(minutes=_SESSION_IDLE_MINUTES):
            dead.append(tok)
    for tok in dead:
        _sessions.pop(tok, None)


def _issue_session(username: str) -> str:
    now = datetime.now()
    token = secrets.token_hex(32)
    _sessions[token] = {
        'username': username,
        'expires_at': now + timedelta(minutes=_SESSION_TTL_MINUTES),
        'last_seen': now,
    }
    return token


def _auth_token_to_user(token: str, touch: bool = True) -> str:
    _purge_expired_sessions()
    if not token:
        return ''
    sess = _sessions.get(token)
    if not isinstance(sess, dict):
        return ''
    if touch:
        sess['last_seen'] = datetime.now()
    return sess.get('username', '')


def require_auth(credentials: HTTPAuthorizationCredentials = Depends(_http_bearer)):
    token = credentials.credentials if credentials else ''
    username = _auth_token_to_user(token, touch=True)
    if not username:
        raise HTTPException(status_code=401, detail='未授权，请先登录')
    return username


@app.middleware('http')
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response


class LoginIn(BaseModel):
    username: str
    password: str


class LicenseGenerateIn(BaseModel):
    customer: str
    expires_at: str
    machine_code: str
    features: List[str] = []
    product: str = license_manager.DEFAULT_PRODUCT
    metadata: dict = {}
    remark: str = ''


class LicenseRecordUpdateIn(BaseModel):
    record_status: Optional[str] = None
    remark: Optional[str] = None


@app.get('/', response_class=HTMLResponse)
def index():
    path = os.path.join(os.path.dirname(__file__), 'static', 'license_admin.html')
    return open(path, encoding='utf-8').read()


@app.post('/api/login')
def login(body: LoginIn):
    now = datetime.now()
    username = body.username
    attempt = _login_attempts.get(username, {'count': 0, 'lock_until': None})
    if attempt['lock_until'] and now < attempt['lock_until']:
        remaining = int((attempt['lock_until'] - now).total_seconds() / 60) + 1
        raise HTTPException(403, f'账户已锁定，请 {remaining} 分钟后重试')
    if attempt['lock_until'] and now >= attempt['lock_until']:
        attempt = {'count': 0, 'lock_until': None}
    if not db.verify_admin(username, body.password):
        attempt['count'] += 1
        if attempt['count'] >= _MAX_ATTEMPTS:
            attempt['lock_until'] = now + timedelta(minutes=_LOCK_MINUTES)
            attempt['count'] = 0
            _login_attempts[username] = attempt
            raise HTTPException(403, f'密码错误次数过多，账户已锁定 {_LOCK_MINUTES} 分钟')
        _login_attempts[username] = attempt
        left = _MAX_ATTEMPTS - attempt['count']
        raise HTTPException(401, f'用户名或密码错误，还有 {left} 次机会')
    _login_attempts.pop(username, None)
    token = _issue_session(username)
    return {'token': token, 'username': username}


@app.post('/api/logout')
def logout(credentials: HTTPAuthorizationCredentials = Depends(_http_bearer)):
    if credentials and credentials.credentials in _sessions:
        _sessions.pop(credentials.credentials, None)
    return {'ok': True}


@app.get('/api/me')
def me(username: str = Depends(require_auth)):
    return {'username': username}


@app.get('/api/license-records')
def list_license_records(status: str = '', keyword: str = '', limit: int = 200, _: str = Depends(require_auth)):
    return db.list_license_records(status=status, keyword=keyword, limit=limit)


@app.get('/api/license-records/summary')
def get_license_record_summary(_: str = Depends(require_auth)):
    return db.get_license_record_summary()


@app.post('/api/license/generate-file')
def generate_license_file(body: LicenseGenerateIn, _: str = Depends(require_auth)):
    customer = (body.customer or '').strip()
    if not customer:
        raise HTTPException(400, '客户名称不能为空')
    expires_at = (body.expires_at or '').strip()
    if not license_manager._parse_iso8601(expires_at):
        raise HTTPException(400, '过期时间格式不正确，请使用 ISO8601 格式')
    try:
        machine_code = license_manager.load_machine_code(body.machine_code)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not machine_code:
        raise HTTPException(400, '客户机器码不能为空')
    features = [str(x).strip() for x in (body.features or []) if str(x).strip()]
    payload = license_manager.build_license_payload(
        customer=customer,
        expires_at=expires_at,
        product=(body.product or license_manager.DEFAULT_PRODUCT).strip() or license_manager.DEFAULT_PRODUCT,
        features=features,
        machine_code=machine_code,
        metadata=body.metadata or {},
    )
    license_token = license_manager.generate_license_token(payload)
    out = {**payload, 'license_token': license_token}
    db.create_license_record(
        customer=customer,
        product=payload['product'],
        machine_code=machine_code,
        expires_at=expires_at,
        features=features,
        metadata=body.metadata or {},
        license_token=license_token,
        created_by=_,
        remark=(body.remark or '').strip(),
    )
    syslog.send('info', 'LICENSE', f'生成授权文件: {customer} / {machine_code[:8]} by {_}')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_customer = re.sub(r'[^0-9A-Za-z._-]+', '_', customer)[:32] or 'customer'
    fname = f'license_{safe_customer}_{machine_code[:8]}_{ts}.json'
    return Response(
        content=json.dumps(out, ensure_ascii=False, indent=2).encode('utf-8'),
        media_type='application/json; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{fname}"'}
    )


@app.get('/api/license-records/{record_id}/download')
def download_license_record(record_id: int, _: str = Depends(require_auth)):
    item = db.get_license_record(record_id)
    if not item:
        raise HTTPException(404, '授权记录不存在')
    db.mark_license_record_downloaded(record_id)
    out = {
        'product': item.get('product') or license_manager.DEFAULT_PRODUCT,
        'customer': item.get('customer') or '',
        'issued_at': item.get('created_at') or '',
        'expires_at': item.get('expires_at') or '',
        'features': item.get('features') or [],
        'machine_code': item.get('machine_code') or '',
        'metadata': item.get('metadata') or {},
        'license_token': item.get('license_token') or '',
    }
    safe_customer = re.sub(r'[^0-9A-Za-z._-]+', '_', (item.get('customer') or 'customer'))[:32] or 'customer'
    machine_code = item.get('machine_code') or ''
    fname = f'license_{safe_customer}_{machine_code[:8]}_{record_id}.json'
    return Response(
        content=json.dumps(out, ensure_ascii=False, indent=2).encode('utf-8'),
        media_type='application/json; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename="{fname}"'}
    )


@app.patch('/api/license-records/{record_id}')
def update_license_record(record_id: int, body: LicenseRecordUpdateIn, _: str = Depends(require_auth)):
    status = (body.record_status or '').strip()
    if status and status not in ('active', 'revoked'):
        raise HTTPException(400, '授权状态仅支持 active 或 revoked')
    remark = body.remark
    if remark is not None:
        remark = remark.strip()
    if not db.update_license_record(record_id, record_status=status, remark=remark):
        raise HTTPException(404, '授权记录不存在或未发生变更')
    syslog.send('info', 'LICENSE', f'更新授权记录: #{record_id} by {_}')
    return {'ok': True, 'item': db.get_license_record(record_id)}


@app.delete('/api/license-records/{record_id}')
def delete_license_record(record_id: int, _: str = Depends(require_auth)):
    if not db.delete_license_record(record_id):
        raise HTTPException(404, '授权记录不存在')
    syslog.send('warning', 'LICENSE', f'删除授权记录: #{record_id} by {_}')
    return {'ok': True}
