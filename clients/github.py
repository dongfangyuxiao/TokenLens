import requests
from datetime import datetime, timezone, timedelta

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

def test_connection(token):
    """Returns (error_msg, username). error_msg is None on success."""
    try:
        resp = requests.get('https://api.github.com/user', headers=_headers(token), timeout=10)
        resp.raise_for_status()
        user = resp.json()
        return None, user.get('login', 'unknown')
    except Exception as e:
        return str(e), None

MAIN_BRANCHES = ['main', 'master']

def fetch_recent_changes(token, owner, scan_hours=1, full_scan=False):
    since = None if full_scan else (datetime.now(timezone.utc) - timedelta(hours=scan_hours)).isoformat()
    results = []
    try:
        if owner:
            # 先尝试 org，失败则当 user
            try:
                repos = _paginate(f'https://api.github.com/orgs/{owner}/repos', token)
            except Exception:
                repos = _paginate('https://api.github.com/user/repos', token, {'type': 'all'})
        else:
            repos = _paginate('https://api.github.com/user/repos', token, {'type': 'all'})
    except Exception as e:
        print(f'  [GitHub] 获取仓库失败: {e}')
        return []

    for repo in repos:
        repo_owner = repo['owner']['login']
        repo_name  = repo['name']
        base_url   = f'https://api.github.com/repos/{repo_owner}/{repo_name}/commits'
        try:
            if full_scan:
                # 全量扫描：只拉 main / master 分支，去重合并
                seen, commits = set(), []
                for branch in MAIN_BRANCHES:
                    try:
                        for c in _paginate(base_url, token, {'sha': branch}):
                            if c['sha'] not in seen:
                                seen.add(c['sha'])
                                commits.append(c)
                    except Exception:
                        pass
            else:
                commit_params = {'since': since} if since else {}
                commits = _paginate(base_url, token, commit_params)
        except Exception:
            continue

        for commit in commits:
            sha = commit['sha']
            try:
                data  = _get(f'https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{sha}', token)
                files = data.get('files', [])
            except Exception:
                continue

            results.append({
                'source'      : 'github',
                'repo'        : f'{repo_owner}/{repo_name}',
                'commit_sha'  : sha,
                'commit_url'  : commit['html_url'],
                'author'      : commit['commit']['author']['name'],
                'message'     : commit['commit']['message'].split('\n')[0],
                'committed_at': commit['commit']['author']['date'],
                'files'       : [
                    {'filename': f['filename'], 'patch': f.get('patch',''), 'status': f['status']}
                    for f in files if f.get('patch')
                ],
            })
    return results
