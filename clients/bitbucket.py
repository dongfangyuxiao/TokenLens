import base64
import os
from datetime import datetime
from urllib.parse import quote

import requests

BASE = 'https://api.bitbucket.org/2.0'
AUDIT_EXTENSIONS = {'.js', '.ts', '.jsx', '.tsx', '.vue', '.html', '.css', '.py', '.go', '.java',
                    '.rb', '.php', '.rs', '.cs', '.cpp', '.c', '.sol', '.json', '.yaml', '.yml',
                    '.toml', '.env', '.sh', '.bash', '.svelte', '.mjs', '.cjs'}
AUDIT_BASENAMES = {'Dockerfile'}
SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.mp4', '.mp3',
                   '.wav', '.pdf', '.zip', '.tar', '.gz', '.lock', '.sum', '.woff', '.woff2',
                   '.ttf', '.eot', '.map', '.min.js'}
MAIN_BRANCHES = ['main', 'master']


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


def _should_scan(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path)
    if ext in SKIP_EXTENSIONS:
        return False
    return ext in AUDIT_EXTENSIONS or base in AUDIT_BASENAMES


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
        cur_params['include'] = branch
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
                        committed_dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
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


def _find_head(token, full_name: str):
    """找 main/master 分支，返回 (branch, sha, author, message)。"""
    for branch in MAIN_BRANCHES:
        try:
            data = _get(f'{BASE}/repositories/{full_name}/commits/{branch}', token, {'pagelen': 1})
            values = data.get('values') or []
            if not values:
                continue
            c = values[0]
            author_info = c.get('author', {})
            author_name = (author_info.get('user', {}).get('display_name')
                           or author_info.get('raw', ''))
            message = (c.get('message', '') or '').split('\n')[0]
            return branch, c.get('hash', ''), author_name, message
        except Exception:
            continue
    return None, None, '', ''


def _fetch_content(token, full_name: str, ref: str, path: str) -> str:
    try:
        encoded = quote(path)
        resp = requests.get(
            f'{BASE}/repositories/{full_name}/src/{ref}/{encoded}',
            headers=_headers(token), timeout=30
        )
        if not resp.ok:
            return ''
        return resp.text
    except Exception:
        return ''


def _fetch_full_tree(token, full_name: str, ref: str) -> list:
    """全量：递归获取 main/master 所有代码文件的当前内容。"""
    url = f'{BASE}/repositories/{full_name}/src/{ref}'
    files = []
    first = True
    params = {'pagelen': 100}
    while url:
        try:
            data = _get(url, token, params if first else None)
        except Exception:
            break
        first = False
        for item in data.get('values', []):
            if item.get('type') != 'commit_file':
                continue
            path = item.get('path', '')
            if not path or not _should_scan(path):
                continue
            content = _fetch_content(token, full_name, ref, path)
            if content.strip():
                files.append({'filename': path, 'patch': content, 'status': 'added'})
        url = data.get('next')
    return files


def fetch_recent_changes(token, workspace='', since_iso=None):
    """
    拉取 since_iso 之后的所有提交。since_iso=None 时拉取各仓库 main/master 当前快照。
    """
    since_dt = None
    if since_iso:
        try:
            since_dt = datetime.fromisoformat(since_iso.replace('Z', '+00:00'))
        except Exception:
            since_dt = None
    results = []

    try:
        if workspace:
            repos = _paginate(f'{BASE}/repositories/{workspace}', token, {'role': 'member'})
        else:
            repos = _paginate(f'{BASE}/repositories', token, {'role': 'member'})
    except Exception as e:
        print(f'  [Bitbucket] 获取仓库失败: {e}')
        return []

    for repo in repos:
        full_name = repo.get('full_name', '')
        if not full_name:
            continue

        if since_iso is None:
            branch, head_sha, author, message = _find_head(token, full_name)
            if not head_sha:
                continue
            files = _fetch_full_tree(token, full_name, head_sha)
            if not files:
                continue
            results.append({
                'source': 'bitbucket',
                'repo': full_name,
                'branch': branch,
                'commit_sha': head_sha,
                'commit_url': f'https://bitbucket.org/{full_name}/commits/{head_sha}',
                'author': author,
                'message': message,
                'committed_at': '',
                'files': files,
            })
            continue

        try:
            commits = _paginate_commits(
                f'{BASE}/repositories/{full_name}/commits', token, since_dt)
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
                'source': 'bitbucket',
                'repo': full_name,
                'branch': '',
                'commit_sha': sha,
                'commit_url': commit.get('links', {}).get('html', {}).get('href', ''),
                'author': author_name,
                'message': commit.get('message', '').split('\n')[0],
                'committed_at': commit.get('date', ''),
                'files': files,
            })

    return results
