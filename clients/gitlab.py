import requests
from datetime import datetime, timezone, timedelta

def _get(base_url, token, path, params=None):
    resp = requests.get(
        f'{base_url}/api/v4{path}',
        headers={'PRIVATE-TOKEN': token},
        params=params, timeout=30
    )
    resp.raise_for_status()
    return resp.json()

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

def test_connection(token, base_url='https://gitlab.com'):
    """Returns (error_msg, username). error_msg is None on success."""
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

def fetch_recent_changes(token, base_url='https://gitlab.com', scan_hours=1, full_scan=False):
    since = None if full_scan else (datetime.now(timezone.utc) - timedelta(hours=scan_hours)).isoformat()
    results = []
    try:
        repos = _paginate(base_url, token, '/projects', {'membership': True})
    except Exception as e:
        print(f'  [GitLab] 获取仓库失败: {e}')
        return []

    MAIN_BRANCHES = ['main', 'master']

    for repo in repos:
        if repo.get('marked_for_deletion_at'):
            continue
        pid  = repo['id']
        name = repo['path_with_namespace']
        path = f'/projects/{pid}/repository/commits'
        try:
            if full_scan:
                # 全量扫描：只拉 main / master 分支，去重合并
                seen, commits = set(), []
                for branch in MAIN_BRANCHES:
                    try:
                        for c in _paginate(base_url, token, path, {'ref_name': branch}):
                            if c['id'] not in seen:
                                seen.add(c['id'])
                                commits.append(c)
                    except Exception:
                        pass
            else:
                commit_params = {'since': since} if since else {}
                commits = _paginate(base_url, token, path, commit_params)
        except Exception:
            continue

        for commit in commits:
            sha = commit['id']
            try:
                diffs = _get(base_url, token, f'/projects/{pid}/repository/commits/{sha}/diff')
            except Exception:
                continue

            results.append({
                'source'      : 'gitlab',
                'repo'        : name,
                'commit_sha'  : sha,
                'commit_url'  : f'{base_url}/{name}/-/commit/{sha}',
                'author'      : commit.get('author_name', ''),
                'message'     : commit.get('title', ''),
                'committed_at': commit.get('committed_date', ''),
                'files'       : [
                    {
                        'filename': d['new_path'],
                        'patch'   : d.get('diff', ''),
                        'status'  : 'deleted' if d['deleted_file'] else ('added' if d['new_file'] else 'modified'),
                    }
                    for d in diffs if d.get('diff')
                ],
            })
    return results
