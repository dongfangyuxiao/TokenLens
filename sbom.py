import json
import re
from collections import deque

try:
    import tomllib
except Exception:  # pragma: no cover
    tomllib = None


_MANIFEST_NAMES = {
    'requirements.txt',
    'pyproject.toml',
    'package.json',
    'package-lock.json',
    'go.mod',
    'pom.xml',
    'build.gradle',
    'build.gradle.kts',
    'Cargo.toml',
    'composer.json',
    'Gemfile',
}


def _add(components: list, seen: set, ecosystem: str, name: str,
         version: str, manifest: str, raw_spec: str = ''):
    n = (name or '').strip()
    if not n:
        return
    v = (version or '').strip() or 'unknown'
    key = (ecosystem, n.lower(), v, manifest)
    if key in seen:
        return
    seen.add(key)
    components.append({
        'ecosystem': ecosystem,
        'component': n,
        'version': v,
        'manifest_file': manifest,
        'raw_spec': (raw_spec or '').strip()[:300],
    })


def _parse_requirements(text: str, manifest: str, components: list, seen: set):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*([<>=!~]{1,2})\s*([^;\s#]+)', line)
        if m:
            _add(components, seen, 'pypi', m.group(1), f'{m.group(2)}{m.group(3)}', manifest, line)
            continue
        m2 = re.match(r'^([A-Za-z0-9_.\-]+)', line)
        if m2:
            _add(components, seen, 'pypi', m2.group(1), 'unknown', manifest, line)


def _parse_pyproject(text: str, manifest: str, components: list, seen: set):
    if not tomllib:
        return
    try:
        data = tomllib.loads(text)
    except Exception:
        return

    project = data.get('project', {})
    for dep in project.get('dependencies', []) or []:
        line = str(dep)
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(.*)$', line)
        if m:
            _add(components, seen, 'pypi', m.group(1), m.group(2).strip() or 'unknown', manifest, line)

    for _, deps in (project.get('optional-dependencies', {}) or {}).items():
        for dep in deps or []:
            line = str(dep)
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*(.*)$', line)
            if m:
                _add(components, seen, 'pypi', m.group(1), m.group(2).strip() or 'unknown', manifest, line)

    poetry_deps = (((data.get('tool') or {}).get('poetry') or {}).get('dependencies') or {})
    for name, spec in poetry_deps.items():
        if name.lower() == 'python':
            continue
        if isinstance(spec, str):
            _add(components, seen, 'pypi', name, spec, manifest, spec)
        elif isinstance(spec, dict):
            _add(components, seen, 'pypi', name, spec.get('version', 'unknown'), manifest, json.dumps(spec, ensure_ascii=False))


def _parse_package_json(text: str, manifest: str, components: list, seen: set):
    try:
        data = json.loads(text)
    except Exception:
        return
    for key in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
        deps = data.get(key, {}) or {}
        for name, ver in deps.items():
            _add(components, seen, 'npm', name, str(ver), manifest, f'{key}:{ver}')


def _parse_package_lock(text: str, manifest: str, components: list, seen: set):
    try:
        data = json.loads(text)
    except Exception:
        return

    deps = data.get('dependencies') or {}
    queue = deque([(name, val) for name, val in deps.items()])
    while queue:
        name, meta = queue.popleft()
        if not isinstance(meta, dict):
            continue
        _add(components, seen, 'npm', name, str(meta.get('version', 'unknown')), manifest, 'package-lock')
        for child_name, child_meta in (meta.get('dependencies') or {}).items():
            queue.append((child_name, child_meta))


def _parse_go_mod(text: str, manifest: str, components: list, seen: set):
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('//'):
            continue
        if s.startswith('require ('):
            in_block = True
            continue
        if in_block and s == ')':
            in_block = False
            continue
        if s.startswith('require '):
            s = s[len('require '):].strip()
        parts = s.split()
        if len(parts) >= 2 and (in_block or line.strip().startswith('require ') or '/' in parts[0]):
            _add(components, seen, 'gomod', parts[0], parts[1], manifest, line)


def _parse_pom_xml(text: str, manifest: str, components: list, seen: set):
    pattern = re.compile(
        r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?(?:<version>(.*?)</version>)?.*?</dependency>',
        re.S,
    )
    for g, a, v in pattern.findall(text):
        name = f'{g.strip()}:{a.strip()}'
        _add(components, seen, 'maven', name, (v or 'unknown').strip(), manifest, name)


def _parse_gradle(text: str, manifest: str, components: list, seen: set):
    pattern = re.compile(r'\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[\(\s]*["\']([^"\']+)["\']')
    for dep in pattern.findall(text):
        parts = dep.split(':')
        if len(parts) >= 3:
            name = f'{parts[0]}:{parts[1]}'
            version = ':'.join(parts[2:])
            _add(components, seen, 'maven', name, version, manifest, dep)


def _parse_cargo_toml(text: str, manifest: str, components: list, seen: set):
    in_deps = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if s.startswith('['):
            in_deps = s in ('[dependencies]', '[dev-dependencies]', '[build-dependencies]')
            continue
        if not in_deps or '=' not in s:
            continue
        name, spec = [x.strip() for x in s.split('=', 1)]
        spec = spec.strip().strip('"').strip("'")
        _add(components, seen, 'cargo', name, spec or 'unknown', manifest, line)


def _parse_composer_json(text: str, manifest: str, components: list, seen: set):
    try:
        data = json.loads(text)
    except Exception:
        return
    for key in ('require', 'require-dev'):
        deps = data.get(key, {}) or {}
        for name, ver in deps.items():
            if name.lower() == 'php':
                continue
            _add(components, seen, 'composer', name, str(ver), manifest, f'{key}:{ver}')


def _parse_gemfile(text: str, manifest: str, components: list, seen: set):
    pattern = re.compile(r'^\s*gem\s+["\']([^"\']+)["\']\s*(?:,\s*["\']([^"\']+)["\'])?', re.M)
    for name, ver in pattern.findall(text):
        _add(components, seen, 'rubygems', name, ver or 'unknown', manifest, name)


def extract_components_from_files(files: list) -> list:
    components = []
    seen = set()

    for f in files or []:
        path = (f.get('filename') or '').replace('\\', '/')
        if not path:
            continue
        base = path.split('/')[-1]
        if base not in _MANIFEST_NAMES:
            continue
        text = f.get('patch', '')
        if not isinstance(text, str) or not text.strip():
            continue

        if base == 'requirements.txt':
            _parse_requirements(text, path, components, seen)
        elif base == 'pyproject.toml':
            _parse_pyproject(text, path, components, seen)
        elif base == 'package.json':
            _parse_package_json(text, path, components, seen)
        elif base == 'package-lock.json':
            _parse_package_lock(text, path, components, seen)
        elif base == 'go.mod':
            _parse_go_mod(text, path, components, seen)
        elif base == 'pom.xml':
            _parse_pom_xml(text, path, components, seen)
        elif base in ('build.gradle', 'build.gradle.kts'):
            _parse_gradle(text, path, components, seen)
        elif base == 'Cargo.toml':
            _parse_cargo_toml(text, path, components, seen)
        elif base == 'composer.json':
            _parse_composer_json(text, path, components, seen)
        elif base == 'Gemfile':
            _parse_gemfile(text, path, components, seen)

    return components
