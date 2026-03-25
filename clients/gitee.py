import requests
from datetime import datetime, timezone, timedelta

BASE = 'https://gitee.com/api/v5'


def _get(url, token, params=None):
    p = dict(params or {})
    p['access_token'] = token
    resp = requests.get(url, params=p, timeout=30)
    resp.raise_for_status()
    return resp.json()


def test_connection(token, base_url=''):
    """Returns (error_msg, username). error_msg is None on success."""
    try:
        resp = requests.get(f'{BASE}/user', params={'access_token': token}, timeout=10)
        resp.raise_for_status()
        user = resp.json()
        return None, user.get('login', 'unknown')
    except Exception as e:
        return str(e), None

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


def fetch_recent_changes(token, owner='', scan_hours=1, full_scan=False):
    since = (None if full_scan
             else (datetime.now(timezone.utc) - timedelta(hours=scan_hours))
             .strftime('%Y-%m-%dT%H:%M:%S+00:00'))
    results = []

    try:
        if owner:
            try:
                repos = _paginate(f'{BASE}/orgs/{owner}/repos', token)
            except Exception:
                repos = _paginate(f'{BASE}/users/{owner}/repos', token)
        else:
            repos = _paginate(f'{BASE}/user/repos', token, {'type': 'all'})
    except Exception as e:
        print(f'  [Gitee] 获取仓库失败: {e}')
        return []

    MAIN_BRANCHES = ['main', 'master']

    for repo in repos:
        repo_owner = repo.get('owner', {}).get('login', '')
        repo_name  = repo.get('name', '')
        if not repo_owner or not repo_name:
            continue
        base_commits = f'{BASE}/repos/{repo_owner}/{repo_name}/commits'
        try:
            if full_scan:
                # 全量扫描：只拉 main / master 分支，去重合并
                seen, commits = set(), []
                for branch in MAIN_BRANCHES:
                    try:
                        for c in _paginate(base_commits, token, {'sha': branch}):
                            sha = c.get('sha', '')
                            if sha and sha not in seen:
                                seen.add(sha)
                                commits.append(c)
                    except Exception:
                        pass
            else:
                commit_params = {'since': since} if since else {}
                commits = _paginate(base_commits, token, commit_params)
        except Exception:
            continue

        for commit in commits:
            sha = commit.get('sha', '')
            if not sha:
                continue
            try:
                detail = _get(
                    f'{BASE}/repos/{repo_owner}/{repo_name}/commits/{sha}', token)
                raw_files = detail.get('files', [])
            except Exception:
                continue

            author = commit.get('commit', {}).get('author', {})
            results.append({
                'source':       'gitee',
                'repo':         f'{repo_owner}/{repo_name}',
                'commit_sha':   sha,
                'commit_url':   commit.get('html_url', ''),
                'author':       author.get('name', ''),
                'message':      commit.get('commit', {}).get('message', '').split('\n')[0],
                'committed_at': author.get('date', ''),
                'files': [
                    {
                        'filename': f['filename'],
                        'patch':    f.get('patch', ''),
                        'status':   f.get('status', 'modified'),
                    }
                    for f in raw_files if f.get('patch')
                ],
            })

    return results
