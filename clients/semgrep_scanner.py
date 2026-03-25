import subprocess, json, tempfile, os

def is_available():
    try:
        r = subprocess.run(['semgrep', '--version'], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def scan_patch(filename, patch, token=''):
    """用 semgrep 扫描 diff patch 中的新增/修改代码，返回 findings 列表。
    token: Semgrep AppSec Platform token，配置后可使用 Pro 规则。"""
    ext = os.path.splitext(filename)[1] or '.txt'
    lines = []
    for line in patch.split('\n'):
        if line.startswith(('@@', '---', '+++')):
            continue
        if line.startswith('-'):
            continue
        lines.append(line[1:] if line.startswith(('+', ' ')) else line)

    if not lines:
        return []

    with tempfile.NamedTemporaryFile(
        mode='w', suffix=ext, delete=False, encoding='utf-8', errors='replace'
    ) as f:
        f.write('\n'.join(lines))
        tmp = f.name

    try:
        env = os.environ.copy()
        if token:
            env['SEMGREP_APP_TOKEN'] = token
        r = subprocess.run(
            ['semgrep', '--json', '--config=auto', '--quiet', '--no-git-ignore', tmp],
            capture_output=True, text=True, timeout=120, env=env
        )
        try:
            data = json.loads(r.stdout)
        except Exception:
            return []

        findings = []
        for hit in data.get('results', []):
            sev_raw = hit.get('extra', {}).get('severity', 'INFO').upper()
            sev = {'ERROR': 'high', 'WARNING': 'medium'}.get(sev_raw, 'low')
            rule = hit.get('check_id', '')
            findings.append({
                'title'      : rule.split('.')[-1].replace('-', ' ').title(),
                'severity'   : sev,
                'description': hit.get('extra', {}).get('message', ''),
                'line'       : str(hit.get('start', {}).get('line', '')),
                'type'       : 'vulnerability',
                'recommendation': f'Rule: {rule}',
            })
        return findings
    except subprocess.TimeoutExpired:
        return []
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
