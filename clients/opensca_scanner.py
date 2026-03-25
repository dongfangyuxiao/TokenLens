import subprocess, json, tempfile, os

# opensca 会扫描这些依赖文件
DEPENDENCY_FILES = {
    'package.json', 'package-lock.json', 'yarn.lock',
    'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
    'go.mod', 'go.sum',
    'pom.xml', 'build.gradle', 'build.gradle.kts',
    'Gemfile', 'Gemfile.lock',
    'Cargo.toml', 'Cargo.lock',
    'composer.json', 'composer.lock',
}

_SEARCH_PATHS = [
    'opensca-cli',
    '/root/.config/opensca-cli/opensca-cli',
    '/usr/local/bin/opensca-cli',
]

def _find_bin():
    for p in _SEARCH_PATHS:
        try:
            r = subprocess.run([p, '-version'], capture_output=True, timeout=5)
            if r.returncode == 0 or b'version' in (r.stdout + r.stderr).lower():
                return p
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None

def is_available():
    return _find_bin() is not None

def scan_patch(filename, patch, token=''):
    """用 opensca-cli 扫描依赖文件的 patch 内容，返回 findings 列表。"""
    basename = os.path.basename(filename)
    if basename not in DEPENDENCY_FILES:
        return []

    bin_path = _find_bin()
    if not bin_path:
        return []

    # 从 patch 重建文件内容（context + added 行）
    lines = []
    for line in patch.split('\n'):
        if line.startswith(('@@', '---', '+++')):
            continue
        if line.startswith('-'):
            continue
        lines.append(line[1:] if line.startswith(('+', ' ')) else line)

    content = '\n'.join(lines).strip()
    if not content:
        return []

    ext = os.path.splitext(filename)[1] or '.txt'
    with tempfile.NamedTemporaryFile(
        mode='w', suffix=ext, prefix='opensca_', delete=False, encoding='utf-8'
    ) as f:
        f.write(content)
        tmp = f.name

    out = tmp + '.json'
    try:
        cmd = [bin_path, '-path', tmp, f'-out={out}']
        if token:
            cmd += ['-token', token]
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if not os.path.exists(out):
            return []
        with open(out, encoding='utf-8') as f:
            data = json.load(f)
        return _parse(data)
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        try:
            os.unlink(out)
        except OSError:
            pass

_SEV_MAP = {
    'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
    '4': 'critical', '3': 'high', '2': 'medium', '1': 'low',
}

def _parse(data):
    vulns = []
    if isinstance(data, list):
        vulns = data
    else:
        for key in ('Vulnerabilities', 'vulnerabilities', 'Vulns', 'vulns'):
            if key in data:
                vulns = data[key]
                break

    findings = []
    for v in vulns:
        sev_raw = str(v.get('Severity', v.get('severity', v.get('level', 'low')))).lower()
        sev = _SEV_MAP.get(sev_raw, 'low')

        cve = v.get('CveId', v.get('cve_id', v.get('Id', v.get('id', ''))))
        comps = v.get('Components', v.get('components', v.get('AffectedComponents', [])))
        pkg = ''
        if comps:
            c = comps[0]
            n = c.get('Name', c.get('name', ''))
            ver = c.get('Version', c.get('version', ''))
            pkg = f'{n}@{ver}' if ver else n

        name = v.get('Name', v.get('name', cve or 'Unknown'))
        title = f'{pkg}: {name}' if pkg else name

        findings.append({
            'title'          : title,
            'severity'       : sev,
            'description'    : v.get('Description', v.get('description', '')),
            'type'           : 'dependency',
            'recommendation' : v.get('Solution', v.get('solution', '')),
        })
    return findings
