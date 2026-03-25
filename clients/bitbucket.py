import base64
import requests
from datetime import datetime, timezone, timedelta

BASE = 'https://api.bitbucket.org/2.0'


def _headers(token: str) -> dict:
    """支持 Bearer Token 或 'username:app_password' Basic Auth 两种格式。"""
    if ':' in token:
        enc = base64.b64encode(token.encode()).decode()
        return {'Authorization': f'Basic {enc}'}
    return {'Authorization': f'Bearer {token}'}


def _get(url, token, params=None):
    resp = requests.get(url, headers=_headers(token), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def test_connection(token, base_url=''):
    """Returns (error_msg, username). error_msg is None on success."""
    try:
        resp = requests.get(f'{BASE}/user', headers=_headers(token), timeout=10)
        resp.raise_for_status()
        user = resp.json()
        return None, user.get('display_name') or user.get('username', 'unknown')
    except Exception as e:
        return str(e), None

def _paginate(url, token, params=None):
    """Bitbucket 使用 cursor 分页，next 链接已含参数。"""
    cur_params = dict(params or {})
    cur_params.setdefault('pagelen', 50)
    results = []
    first = True
    while url:
        data = _get(url, token, cur_params if first else None)
        first = False
        results.extend(data.get('values', []))
        url = data.get('next')
    return results


def _paginate_commits(url, token, since, branch=None):
    """分页拉取 commits，遇到超出时间范围的条目时提前停止。"""
    cur_params = {'pagelen': 50}
    if branch:
        cur_params['branch'] = branch
    results = []
    first = True
    while url:
        data = _get(url, token, cur_params if first else None)
        first = False
        done = False
        for commit in data.get('values', []):
            if since:
                date_str = commit.get('date', '')
                if date_str:
                    try:
                        committed_dt = datetime.fromisoformat(
                            date_str.replace('Z', '+00:00'))
                        if committed_dt <= since:
                            done = True
                            break
                    except Exception:
                        pass
            results.append(commit)
        if done:
            break
        url = data.get('next')
    return results


def _parse_unified_diff(diff_text: str) -> list:
    """将 unified diff 文本解析为 [{filename, status, patch}] 列表。"""
    files, current, patch_lines = [], None, []

    for line in diff_text.splitlines():
        if line.startswith('diff --git '):
            if current is not None and patch_lines:
                current['patch'] = '\n'.join(patch_lines)
                files.append(current)
            current = {'filename': '', 'status': 'modified'}
            patch_lines = []
        elif current is not None:
            if line.startswith('+++ b/'):
                current['filename'] = line[6:]
            elif line.startswith('+++ /dev/null'):
                current['status'] = 'deleted'
            elif line.startswith('--- /dev/null'):
                current['status'] = 'added'
            else:
                patch_lines.append(line)

    if current is not None and patch_lines:
        current['patch'] = '\n'.join(patch_lines)
        files.append(current)

    return [f for f in files if f.get('filename') and f.get('patch')]


def fetch_recent_changes(token, workspace='', scan_hours=1, full_scan=False):
    since = (None if full_scan
             else datetime.now(timezone.utc) - timedelta(hours=scan_hours))
    results = []

    try:
        if workspace:
            repos = _paginate(f'{BASE}/repositories/{workspace}', token,
                              {'role': 'member'})
        else:
            repos = _paginate(f'{BASE}/repositories', token, {'role': 'member'})
    except Exception as e:
        print(f'  [Bitbucket] 获取仓库失败: {e}')
        return []

    MAIN_BRANCHES = ['main', 'master']

    for repo in repos:
        full_name = repo.get('full_name', '')
        if not full_name:
            continue
        try:
            if full_scan:
                # 全量扫描：只拉 main / master 分支，去重合并
                seen, commits = set(), []
                for branch in MAIN_BRANCHES:
                    try:
                        for c in _paginate_commits(
                            f'{BASE}/repositories/{full_name}/commits',
                            token, None, branch=branch
                        ):
                            if c.get('hash') not in seen:
                                seen.add(c['hash'])
                                commits.append(c)
                    except Exception:
                        pass
            else:
                commits = _paginate_commits(
                    f'{BASE}/repositories/{full_name}/commits', token, since)
        except Exception:
            continue

        for commit in commits:
            sha = commit.get('hash', '')
            if not sha:
                continue
            try:
                diff_resp = requests.get(
                    f'{BASE}/repositories/{full_name}/diff/{sha}',
                    headers=_headers(token), timeout=30)
                diff_text = diff_resp.text if diff_resp.ok else ''
            except Exception:
                diff_text = ''

            files = _parse_unified_diff(diff_text)
            author_info = commit.get('author', {})
            author_name = (author_info.get('user', {}).get('display_name')
                           or author_info.get('raw', ''))

            results.append({
                'source':       'bitbucket',
                'repo':         full_name,
                'commit_sha':   sha,
                'commit_url':   commit.get('links', {}).get('html', {}).get('href', ''),
                'author':       author_name,
                'message':      commit.get('message', '').split('\n')[0],
                'committed_at': commit.get('date', ''),
                'files':        files,
            })

    return results
