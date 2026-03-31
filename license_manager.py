import base64
import hashlib
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_PRODUCT = 'TokenLens'

# 公钥硬编码，对应私钥由 TokenLens 授权管理系统持有
_PUBLIC_KEY_PEM = b"""\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7oX0TvB7BanHuBdam8KITwEZ6Lja9iRCRH9iLDh7iz8=
-----END PUBLIC KEY-----
"""

_PUBLIC_KEY: Optional[Ed25519PublicKey] = None


def _get_public_key() -> Ed25519PublicKey:
    global _PUBLIC_KEY
    if _PUBLIC_KEY is None:
        _PUBLIC_KEY = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)
    return _PUBLIC_KEY


def _b64url_decode(text: str) -> bytes:
    padding = '=' * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _parse_iso8601(text: str):
    if not text:
        return None
    return datetime.fromisoformat(text.strip().replace('Z', '+00:00'))


def get_machine_code() -> str:
    explicit = os.getenv('PRODUCT_INSTANCE_ID', '').strip()
    if explicit:
        return explicit
    source = f'{socket.gethostname()}::{uuid.getnode()}'
    return hashlib.sha256(source.encode('utf-8')).hexdigest()[:24]


def verify_license_token(token: str, expected_product: str = DEFAULT_PRODUCT,
                         expected_machine_code: Optional[str] = None, **_) -> dict:
    token = (token or '').strip()
    if not token:
        return {'valid': False, 'state': 'missing', 'message': '未导入授权文件'}
    try:
        encoded, signature = token.split('.', 1)
    except ValueError:
        return {'valid': False, 'state': 'format_error', 'message': '授权文件令牌格式不正确'}
    try:
        _get_public_key().verify(_b64url_decode(signature), encoded.encode('ascii'))
    except InvalidSignature:
        return {'valid': False, 'state': 'invalid_signature', 'message': '授权文件签名校验失败'}
    except Exception as exc:
        return {'valid': False, 'state': 'verify_error', 'message': f'授权校验异常：{exc}'}
    try:
        payload = json.loads(_b64url_decode(encoded).decode('utf-8'))
    except Exception:
        return {'valid': False, 'state': 'payload_error', 'message': '授权文件内容无法解析'}
    if payload.get('product') != expected_product:
        return {'valid': False, 'state': 'product_mismatch', 'message': '授权产品不匹配', 'payload': payload}
    expires_at = _parse_iso8601(payload.get('expires_at', ''))
    if not expires_at:
        return {'valid': False, 'state': 'expires_invalid', 'message': '授权过期时间无效', 'payload': payload}
    if expires_at <= datetime.now(timezone.utc):
        return {'valid': False, 'state': 'expired', 'message': '授权已过期', 'payload': payload}
    bound_machine = (payload.get('machine_code') or '').strip()
    if bound_machine and expected_machine_code and bound_machine != expected_machine_code:
        return {'valid': False, 'state': 'machine_mismatch', 'message': '授权机器码不匹配', 'payload': payload}
    return {'valid': True, 'state': 'valid', 'message': '授权校验通过', 'payload': payload}


def load_license_file_content(text: str) -> str:
    text = (text or '').strip()
    if not text:
        raise ValueError('授权文件内容为空')
    try:
        data = json.loads(text)
    except Exception as exc:
        raise ValueError('授权文件不是有效 JSON') from exc
    token = (data.get('license_token') or '').strip()
    if not token:
        raise ValueError('授权文件中未找到 license_token')
    return token


def load_machine_code(text: str) -> str:
    text = (text or '').strip()
    if not text:
        return ''
    if not text.startswith('{'):
        return text
    try:
        data = json.loads(text)
    except Exception as exc:
        raise ValueError('机器码内容不是有效 JSON') from exc
    machine_code = (data.get('machine_code') or '').strip()
    if not machine_code:
        raise ValueError('机器码文件中未找到 machine_code')
    return machine_code


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'machine-code':
        print(get_machine_code())
    else:
        print(f'机器码: {get_machine_code()}')
