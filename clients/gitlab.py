import requests, base64, os
from urllib.parse import quote

AUDIT_EXTENSIONS = {'.js','.ts','.jsx','.tsx','.vue','.html','.css','.py','.go','.java',
                    '.rb','.php','.rs','.cs','.cpp','.c','.sol','.json','.yaml','.yml',
                    '.toml','.env','.sh','.bash','.svelte','.mjs','.cjs'}
AUDIT_BASENAMES  = {'Dockerfile'}
SKIP_EXTENSIONS  = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.mp4','.mp3',
                    '.wav','.pdf','.zip','.tar','.gz','.lock','.sum','.woff','.woff2',
                    '.ttf','.eot','.map','.min.js'}
MAIN_BRANCHES    = ['main', 'master']

def _get(base_url, token, path, params=None):
    resp = requests.get(
        f'{base_url}/api/v4{path}',
        headers={'PRIVATE-TOKEN': token},
        params=params, timeout=30
    )
    resp.raise_for_status()
    return resp.json()

def _raw(base_url, token, path, params=None):
    """获取原始文本内容（不 JSON 解析）。"""
    resp = requests.get(
        f'{base_url}/api/v4{path}',
        headers={'PRIVATE-TOKEN': token},
        params=params, timeout=30
    )
    resp.raise_for_status()
    return resp.text

def _paginate(base_url, token, path, params=None):
    params = dict(params or {})
    params['per_page'] = 100
    results, page = [], 1
    while True:
        params['page'] = page
        data = _get(base_url, token, path, params)
        if not data:
            break
        results.extend(data)
        if len(data) < 100:
            break
        page += 1
    return results

def _should_scan(path):
    ext  = os.path.splitext(path)[1].lower()
    base = os.path.basename(path)
    if ext in SKIP_EXTENSIONS:
        return False
    return ext in AUDIT_EXTENSIONS or base in AUDIT_BASENAMES

def _find_head(base_url, token, pid, repo_name):
    """找 main/master 分支，返回 (branch, sha, author, message)。"""
    for branch in MAIN_BRANCHES:
        try:
            c = _get(base_url, token, f'/projects/{pid}/repository/commits/{branch}')
            return branch, c['id'], c.get('author_name', ''), c.get('title', '')
        except Exception:
            continue
    return None, None, '', ''

def _fetch_content(base_url, token, pid, path, ref):
    """取单个文件当前内容，失败返回空字符串。"""
    try:
        encoded = quote(path, safe='')
        return _raw(base_url, token,
                    f'/projects/{pid}/repository/files/{encoded}/raw',
                    {'ref': ref})
    except Exception:
        return ''

def test_connection(token, base_url='https://gitlab.com'):
    try:
        resp = requests.get(
            f'{base_url}/api/v4/user',
            headers={'PRIVATE-TOKEN': token},
            timeout=10
        )
        resp.raise_for_status()
        user = resp.json()
        return None, user.get('username', 'unknown')
    except Exception as e:
        return str(e), None

def fetch_recent_changes(token, base_url='https://gitlab.com', since_iso=None):
    results = []
    try:
        repos = _paginate(base_url, token, '/projects', {'membership': True})
    except Exception as e:
        print(f'  [GitLab] 获取仓库失败: {e}')
        return []

    print(f'  [GitLab] 共 {len(repos)} 个仓库')
    for repo in repos:
        if repo.get('marked_for_deletion_at'):
            continue
        pid  = repo['id']
        name = repo['path_with_namespace']
        print(f'  [GitLab] {name}')

        branch, head_sha, author, message = _find_head(base_url, token, pid, name)
        if not head_sha:
            continue

        if since_iso is None:
            # 全量：只扫 main/master 当前状态
            files = _fetch_full_tree(base_url, token, pid, head_sha)
            if not files:
                continue
            results.append({
                'source'      : 'gitlab',
                'repo'        : name,
                'branch'      : branch,
                'commit_sha'  : head_sha,
                'commit_url'  : f'{base_url}/{name}/-/commit/{head_sha}',
                'author'      : author,
                'message'     : message,
                'committed_at': '',
                'files'       : files,
            })
        else:
            # 增量：扫所有分支的新提交
            try:
                branches = _paginate(base_url, token, f'/projects/{pid}/repository/branches')
            except Exception:
                branches = [{'name': branch}]
            for br in branches:
                br_name = br['name']
                files = _fetch_changed_files(base_url, token, pid, head_sha, br_name, since_iso)
                if not files:
                    continue
                results.append({
                    'source'      : 'gitlab',
                    'repo'        : f'{name}({br_name})',
                    'branch'      : br_name,
                    'commit_sha'  : head_sha,
                    'commit_url'  : f'{base_url}/{name}/-/tree/{br_name}',
                    'author'      : author,
                    'message'     : f'[{br_name}] {message}',
                    'committed_at': '',
                    'files'       : files,
                })

    return results

def _fetch_full_tree(base_url, token, pid, head_sha):
    """全量：递归获取 main/master 所有代码文件的当前内容。"""
    try:
        items = _paginate(base_url, token,
                          f'/projects/{pid}/repository/tree',
                          {'ref': head_sha, 'recursive': 'true'})
    except Exception as e:
        print(f'    获取文件树失败: {e}')
        return []

    files = []
    for item in items:
        if item['type'] != 'blob' or not _should_scan(item['path']):
            continue
        content = _fetch_content(base_url, token, pid, item['path'], head_sha)
        if content.strip():
            files.append({'filename': item['path'], 'patch': content, 'status': 'added'})
    print(f'    全量: 共 {len(files)} 个待分析文件')
    return files

def _fetch_changed_files(base_url, token, pid, head_sha, branch, since_iso):
    """增量：收集 since 以来变更文件名（去重），取当前最新内容。"""
    try:
        commits = _paginate(base_url, token,
                             f'/projects/{pid}/repository/commits',
                             {'ref_name': branch, 'since': since_iso})
    except Exception:
        return []

    if not commits:
        return []

    changed = set()
    for commit in commits:
        sha = commit['id']
        try:
            diffs = _get(base_url, token, f'/projects/{pid}/repository/commits/{sha}/diff')
            for d in diffs:
                path = d.get('new_path') or d.get('old_path', '')
                if not d.get('deleted_file') and _should_scan(path):
                    changed.add(path)
        except Exception:
            continue

    files = []
    for path in changed:
        content = _fetch_content(base_url, token, pid, path, head_sha)
        if content.strip():
            files.append({'filename': path, 'patch': content, 'status': 'modified'})
    return files
