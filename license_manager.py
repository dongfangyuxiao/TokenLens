import argparse
import base64
import hashlib
import hmac
import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_PRODUCT = 'SpringStillness'
DEV_SECRET = 'springstillness-dev-license-secret'


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def _b64url_decode(text: str) -> bytes:
    padding = '=' * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _parse_iso8601(text: str):
    if not text:
        return None
    normalized = text.strip().replace('Z', '+00:00')
    return datetime.fromisoformat(normalized)


def get_secret() -> str:
    return os.getenv('LICENSE_SECRET', DEV_SECRET)


def get_instance_id() -> str:
    explicit = os.getenv('PRODUCT_INSTANCE_ID', '').strip()
    if explicit:
        return explicit
    source = f'{socket.gethostname()}::{uuid.getnode()}'
    return hashlib.sha256(source.encode('utf-8')).hexdigest()[:24]


def build_payload(customer: str, expires_at: str, product: str = DEFAULT_PRODUCT,
                  features=None, machine_id: str = '', metadata=None) -> dict:
    return {
        'product': product,
        'customer': customer.strip(),
        'issued_at': _iso_now(),
        'expires_at': expires_at.strip(),
        'features': features or [],
        'machine_id': machine_id.strip(),
        'metadata': metadata or {},
    }


def generate_license(payload: dict, secret: Optional[str] = None) -> str:
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')
    encoded = _b64url_encode(body)
    digest = hmac.new((secret or get_secret()).encode('utf-8'), encoded.encode('ascii'), hashlib.sha256).digest()
    return f'{encoded}.{_b64url_encode(digest)}'


def verify_license(token: str, secret: Optional[str] = None, expected_product: str = DEFAULT_PRODUCT,
                   expected_machine_id: Optional[str] = None) -> dict:
    token = (token or '').strip()
    if not token:
        return {'valid': False, 'state': 'missing', 'message': '未配置授权码'}
    try:
        encoded, signature = token.split('.', 1)
    except ValueError:
        return {'valid': False, 'state': 'format_error', 'message': '授权码格式不正确'}
    expected_sig = _b64url_encode(hmac.new(
        (secret or get_secret()).encode('utf-8'),
        encoded.encode('ascii'),
        hashlib.sha256
    ).digest())
    if not hmac.compare_digest(signature, expected_sig):
        return {'valid': False, 'state': 'invalid_signature', 'message': '授权码签名校验失败'}
    try:
        payload = json.loads(_b64url_decode(encoded).decode('utf-8'))
    except Exception:
        return {'valid': False, 'state': 'payload_error', 'message': '授权码内容无法解析'}
    if payload.get('product') != expected_product:
        return {'valid': False, 'state': 'product_mismatch', 'message': '授权产品不匹配', 'payload': payload}
    expires_at = _parse_iso8601(payload.get('expires_at', ''))
    if not expires_at:
        return {'valid': False, 'state': 'expires_invalid', 'message': '授权过期时间无效', 'payload': payload}
    now = datetime.now(timezone.utc)
    if expires_at <= now:
        return {'valid': False, 'state': 'expired', 'message': '授权已过期', 'payload': payload}
    bound_machine = (payload.get('machine_id') or '').strip()
    if bound_machine and expected_machine_id and bound_machine != expected_machine_id:
        return {'valid': False, 'state': 'machine_mismatch', 'message': '授权实例不匹配', 'payload': payload}
    return {'valid': True, 'state': 'valid', 'message': '授权校验通过', 'payload': payload}


def _build_parser():
    parser = argparse.ArgumentParser(description='SpringStillness 授权工具')
    sub = parser.add_subparsers(dest='command', required=True)

    gen = sub.add_parser('generate', help='生成授权码')
    gen.add_argument('--customer', required=True, help='客户名称')
    gen.add_argument('--expires-at', required=True, help='过期时间，ISO8601 格式，例如 2027-03-31T23:59:59Z')
    gen.add_argument('--product', default=DEFAULT_PRODUCT, help='产品名称')
    gen.add_argument('--feature', action='append', default=[], help='功能点，可重复传入')
    gen.add_argument('--machine-id', default='', help='绑定实例 ID，可选')
    gen.add_argument('--metadata', default='{}', help='扩展 JSON 元数据，可选')

    gen_file = sub.add_parser('generate-file', help='生成授权文件（JSON）')
    gen_file.add_argument('--customer', required=True, help='客户名称')
    gen_file.add_argument('--expires-at', required=True, help='过期时间，ISO8601 格式，例如 2027-03-31T23:59:59Z')
    gen_file.add_argument('--product', default=DEFAULT_PRODUCT, help='产品名称')
    gen_file.add_argument('--feature', action='append', default=[], help='功能点，可重复传入')
    gen_file.add_argument('--machine-id', default='', help='绑定实例 ID，可选')
    gen_file.add_argument('--metadata', default='{}', help='扩展 JSON 元数据，可选')
    gen_file.add_argument('--output', default='license.json', help='输出文件路径')

    verify = sub.add_parser('verify', help='校验授权码')
    verify.add_argument('--license-key', required=True, help='授权码')
    verify.add_argument('--product', default=DEFAULT_PRODUCT, help='产品名称')
    verify.add_argument('--machine-id', default='', help='实例 ID，可选')
    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == 'generate':
        payload = build_payload(
            customer=args.customer,
            expires_at=args.expires_at,
            product=args.product,
            features=args.feature,
            machine_id=args.machine_id,
            metadata=json.loads(args.metadata or '{}'),
        )
        print(generate_license(payload))
        return
    if args.command == 'generate-file':
        payload = build_payload(
            customer=args.customer,
            expires_at=args.expires_at,
            product=args.product,
            features=args.feature,
            machine_id=args.machine_id,
            metadata=json.loads(args.metadata or '{}'),
        )
        license_key = generate_license(payload)
        out = {**payload, 'license_key': license_key}
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding='utf-8')
        print(str(path))
        return
    result = verify_license(
        args.license_key,
        expected_product=args.product,
        expected_machine_id=(args.machine_id or None),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
