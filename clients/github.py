import requests, base64, os

AUDIT_EXTENSIONS = {'.js','.ts','.jsx','.tsx','.vue','.html','.css','.py','.go','.java',
                    '.rb','.php','.rs','.cs','.cpp','.c','.sol','.json','.yaml','.yml',
                    '.toml','.env','.sh','.bash','.svelte','.mjs','.cjs'}
AUDIT_BASENAMES  = {'Dockerfile'}
SKIP_EXTENSIONS  = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.mp4','.mp3',
                    '.wav','.pdf','.zip','.tar','.gz','.lock','.sum','.woff','.woff2',
                    '.ttf','.eot','.map','.min.js'}
MAIN_BRANCHES    = ['main', 'master']

def _headers(token):
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }

def _get(url, token, params=None):
    resp = requests.get(url, headers=_headers(token), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _paginate(url, token, params=None):
    params = dict(params or {})
    params['per_page'] = 100
    results, page = [], 1
    while True:
        params['page'] = page
        data = _get(url, token, params)
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

def _get_repos(token, owner):
    try:
        if owner:
            try:
                return _paginate(f'https://api.github.com/orgs/{owner}/repos', token)
            except Exception:
                return _paginate('https://api.github.com/user/repos', token, {'type': 'all'})
        return _paginate('https://api.github.com/user/repos', token, {'type': 'all'})
    except Exception as e:
        print(f'  [GitHub] 获取仓库列表失败: {e}')
        return []

def _find_head(token, owner, name):
    """找 main/master 分支，返回 (branch, sha, author, message)。"""
    for branch in MAIN_BRANCHES:
        try:
            c = _get(f'https://api.github.com/repos/{owner}/{name}/commits/{branch}', token)
            return branch, c['sha'], c['commit']['author']['name'], c['commit']['message'].split('\n')[0]
        except Exception:
            continue
    return None, None, '', ''

def _fetch_content(token, owner, name, path, ref):
    """取单个文件当前内容，失败返回空字符串。"""
    try:
        data = _get(f'https://api.github.com/repos/{owner}/{name}/contents/{path}',
                    token, {'ref': ref})
        if data.get('encoding') == 'base64' and data.get('content'):
            return base64.b64decode(data['content'].replace('\n', '')).decode('utf-8', errors='replace')
    except Exception:
        pass
    return ''

def test_connection(token):
    try:
        resp = requests.get('https://api.github.com/user', headers=_headers(token), timeout=10)
        resp.raise_for_status()
        user = resp.json()
        return None, user.get('login', 'unknown')
    except Exception as e:
        return str(e), None

def fetch_recent_changes(token, owner, since_iso=None, on_repo=None, on_progress=None):
    results = []
    repos = _get_repos(token, owner)
    print(f'  [GitHub] 共 {len(repos)} 个仓库')

    total_repos = len(repos)
    for idx, repo in enumerate(repos, 1):
        repo_results = []
        repo_owner = repo['owner']['login']
        repo_name  = repo['name']
        repo_label = f'{repo_owner}/{repo_name}'
        print(f'  [GitHub] {repo_owner}/{repo_name}')

        branch, head_sha, author, message = _find_head(token, repo_owner, repo_name)
        if not head_sha:
            continue

        if since_iso is None:
            # 全量：只扫 main/master 当前状态
            files = _fetch_full_tree(token, repo_owner, repo_name, head_sha)
            if not files:
                continue
            repo_results.append({
                'source'      : 'github',
                'repo'        : f'{repo_owner}/{repo_name}',
                'branch'      : branch,
                'commit_sha'  : head_sha,
                'commit_url'  : f'https://github.com/{repo_owner}/{repo_name}/commit/{head_sha}',
                'author'      : author,
                'message'     : message,
                'committed_at': '',
                'files'       : files,
            })
        else:
            # 增量：扫所有分支的新提交，每个分支单独一条记录
            try:
                branches = _paginate(
                    f'https://api.github.com/repos/{repo_owner}/{repo_name}/branches', token)
            except Exception:
                branches = [{'name': branch}]
            for br in branches:
                br_name = br['name']
                files = _fetch_changed_files(token, repo_owner, repo_name, head_sha, br_name, since_iso)
                if not files:
                    continue
                repo_results.append({
                    'source'      : 'github',
                    'repo'        : f'{repo_owner}/{repo_name}({br_name})',
                    'branch'      : br_name,
                    'commit_sha'  : head_sha,
                    'commit_url'  : f'https://github.com/{repo_owner}/{repo_name}/tree/{br_name}',
                    'author'      : author,
                    'message'     : f'[{br_name}] {message}',
                    'committed_at': '',
                    'files'       : files,
                })

        if repo_results and on_repo:
            on_repo(repo_results)
        results.extend(repo_results)
        if on_progress:
            on_progress(idx, total_repos, repo_label)

    return results

def _fetch_full_tree(token, owner, name, head_sha):
    """全量：用 git tree API 获取 main/master 所有代码文件的当前内容。"""
    try:
        tree = _get(f'https://api.github.com/repos/{owner}/{name}/git/trees/{head_sha}',
                    token, {'recursive': '1'})
    except Exception as e:
        print(f'    获取文件树失败: {e}')
        return []

    files = []
    for item in tree.get('tree', []):
        if item['type'] != 'blob' or not _should_scan(item['path']):
            continue
        content = _fetch_content(token, owner, name, item['path'], head_sha)
        if content.strip():
            files.append({'filename': item['path'], 'patch': content, 'status': 'added'})
    print(f'    全量: 共 {len(files)} 个待分析文件')
    return files

def _fetch_changed_files(token, owner, name, head_sha, branch, since_iso):
    """增量：收集 since 以来变更的文件名（去重），取当前最新内容。"""
    try:
        commits = _paginate(
            f'https://api.github.com/repos/{owner}/{name}/commits',
            token, {'sha': branch, 'since': since_iso}
        )
    except Exception:
        return []

    if not commits:
        return []

    changed = set()
    for commit in commits:
        try:
            data = _get(f'https://api.github.com/repos/{owner}/{name}/commits/{commit["sha"]}', token)
            for f in data.get('files', []):
                if f.get('status') != 'removed' and _should_scan(f['filename']):
                    changed.add(f['filename'])
        except Exception:
            continue

    files = []
    for path in changed:
        content = _fetch_content(token, owner, name, path, head_sha)
        if content.strip():
            files.append({'filename': path, 'patch': content, 'status': 'modified'})
    return files
