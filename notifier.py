import json, time, hmac, hashlib, base64, smtplib, requests
from urllib.parse import quote
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def _severity_emoji(counts):
    if counts.get('critical', 0): return '🚨'
    if counts.get('high', 0):     return '⚠️'
    return '✅'

def _build_text(summary, report_url=''):
    counts = summary['counts']
    emoji  = _severity_emoji(counts)
    lines  = [
        f"{emoji} *代码安全扫描报告*",
        f"扫描提交：{summary['total_commits']} 次　发现问题：{summary['total_findings']} 个",
        f"🔴 严重 {counts['critical']}　🟠 高危 {counts['high']}　🟡 中危 {counts['medium']}　🟢 低危 {counts['low']}",
    ]
    if report_url:
        lines.append(f"📄 查看报告：{report_url}")
    return '\n'.join(lines)

# ── 钉钉 ─────────────────────────────────────────────────────────
def send_dingtalk(config, summary, report_url=''):
    webhook = config.get('webhook', '')
    secret  = config.get('secret', '')
    keyword = config.get('keyword', '').strip()
    if not webhook:
        return
    url = webhook
    if secret:
        ts  = str(round(time.time() * 1000))
        s   = f'{ts}\n{secret}'
        sig = base64.b64encode(
            hmac.new(secret.encode('utf-8'), s.encode('utf-8'), hashlib.sha256).digest()
        ).decode()
        url = f'{webhook}&timestamp={ts}&sign={quote(sig)}'
    text = _build_text(summary, report_url)
    # 关键词安全校验：确保消息包含关键词
    if keyword and keyword not in text:
        text = f'{keyword}\n{text}'
    title = f'{keyword} - 代码安全扫描报告' if keyword else '代码安全扫描报告'
    payload = {
        'msgtype': 'markdown',
        'markdown': {
            'title': title,
            'text' : text,
        }
    }
    requests.post(url, json=payload, timeout=10).raise_for_status()

# ── 企业微信 ──────────────────────────────────────────────────────
def send_wecom(config, summary, report_url=''):
    webhook = config.get('webhook', '')
    if not webhook:
        return
    payload = {
        'msgtype': 'markdown',
        'markdown': {'content': _build_text(summary, report_url)}
    }
    requests.post(webhook, json=payload, timeout=10).raise_for_status()

# ── 飞书 ─────────────────────────────────────────────────────────
def send_feishu(config, summary, report_url=''):
    webhook = config.get('webhook', '')
    secret  = config.get('secret', '').strip()
    keyword = config.get('keyword', '').strip()
    if not webhook:
        return
    counts = summary['counts']
    color  = 'red' if counts.get('critical') else ('orange' if counts.get('high') else 'green')
    text   = _build_text(summary, report_url).replace('*', '**')
    title  = '代码安全扫描报告'
    # 关键词安全校验：确保消息包含关键词
    if keyword:
        if keyword not in title:
            title = f'{keyword} - {title}'
        if keyword not in text:
            text = f'{keyword}\n{text}'
    card = {
        'msg_type': 'interactive',
        'card': {
            'config': {'wide_screen_mode': True},
            'header': {
                'title': {'content': title, 'tag': 'plain_text'},
                'template': color,
            },
            'elements': [{
                'tag': 'div',
                'text': {'content': text, 'tag': 'lark_md'},
            }]
        }
    }
    # 签名验证（飞书机器人安全设置 → 签名校验）
    if secret:
        ts = str(round(time.time()))
        sign_str = f'{ts}\n{secret}'
        hmac_code = hmac.new(sign_str.encode('utf-8'), digestmod=hashlib.sha256).digest()
        sign = base64.b64encode(hmac_code).decode('utf-8')
        card['timestamp'] = ts
        card['sign']      = sign
    requests.post(webhook, json=card, timeout=10).raise_for_status()

# ── Slack ─────────────────────────────────────────────────────────
def send_slack(config, summary, report_url=''):
    webhook = config.get('webhook', '')
    if not webhook:
        return
    counts = summary['counts']
    color  = '#ff4d4f' if counts.get('critical') else ('#fa8c16' if counts.get('high') else '#52c41a')
    payload = {
        'attachments': [{
            'color'     : color,
            'text'      : _build_text(summary, report_url),
            'mrkdwn_in' : ['text'],
        }]
    }
    requests.post(webhook, json=payload, timeout=10).raise_for_status()

# ── 邮件 ─────────────────────────────────────────────────────────
def send_email(config, summary, html_body, report_url=''):
    host   = config.get('smtp_host', '')
    port   = int(config.get('smtp_port', 465))
    user   = config.get('smtp_user', '')
    passwd = config.get('smtp_pass', '')
    to     = [e.strip() for e in config.get('email_to', '').split(',') if e.strip()]
    if not all([host, user, passwd, to]):
        return
    counts  = summary['counts']
    total   = summary['total_findings']
    if not total:
        subject = '✅ 代码安全扫描：未发现问题'
    elif counts.get('critical'):
        subject = f'🚨 代码安全扫描：发现 {counts["critical"]} 个严重问题'
    elif counts.get('high'):
        subject = f'⚠️ 代码安全扫描：发现 {counts["high"]} 个高危问题'
    else:
        subject = f'📋 代码安全扫描：发现 {total} 个问题'
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = user
    msg['To']      = ', '.join(to)
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))
    with smtplib.SMTP_SSL(host, port) as server:
        server.login(user, passwd)
        server.sendmail(user, to, msg.as_string())

# ── 统一发送 ──────────────────────────────────────────────────────
def notify_all(channels, summary, html_report='', report_url=''):
    for ch in channels:
        if not ch.get('enabled', 1):
            continue
        cfg   = json.loads(ch.get('config', '{}'))
        ctype = ch['type']
        name  = ch['name']
        try:
            if ctype == 'dingtalk': send_dingtalk(cfg, summary, report_url)
            elif ctype == 'wecom':  send_wecom(cfg, summary, report_url)
            elif ctype == 'feishu': send_feishu(cfg, summary, report_url)
            elif ctype == 'slack':  send_slack(cfg, summary, report_url)
            elif ctype == 'email':  send_email(cfg, summary, html_report, report_url)
            print(f'  [通知] {name} ({ctype}) 发送成功')
        except Exception as e:
            print(f'  [通知] {name} ({ctype}) 发送失败: {e}')


def test_channel(ctype: str, cfg: dict) -> str | None:
    """测试通知渠道。返回 None 表示成功，否则返回错误信息。"""
    test_summary = {
        'total_commits' : 1,
        'total_findings': 1,
        'counts'        : {'critical': 0, 'high': 1, 'medium': 0, 'low': 0},
    }
    test_html = '<p>这是一条测试通知，来自代码安全审计平台。</p>'
    try:
        if ctype == 'dingtalk':
            send_dingtalk(cfg, test_summary)
        elif ctype == 'wecom':
            send_wecom(cfg, test_summary)
        elif ctype == 'feishu':
            send_feishu(cfg, test_summary)
        elif ctype == 'slack':
            send_slack(cfg, test_summary)
        elif ctype == 'email':
            send_email(cfg, test_summary, test_html)
        else:
            return f'不支持的渠道类型: {ctype}'
        return None
    except Exception as e:
        return str(e)
