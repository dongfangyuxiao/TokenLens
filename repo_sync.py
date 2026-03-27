import os
import re
import shutil
from pathlib import Path

SYNC_ROOT = 'synced_repos'
_MAX_FILE_BYTES = 2 * 1024 * 1024


def _safe_segment(name: str) -> str:
    name = (name or '').strip().replace('\\', '/').strip('/')
    if not name:
        return 'unknown'
    return re.sub(r'[^0-9A-Za-z._/-]+', '_', name)


def normalize_repo_name(repo: str) -> str:
    # incremental 结果可能带分支后缀: org/repo(branch)
    return re.sub(r'\([^)]*\)$', '', (repo or '').strip())


def repo_local_dir(source: str, repo: str) -> str:
    src = _safe_segment(source or 'unknown').replace('/', '_')
    rp = _safe_segment(normalize_repo_name(repo))
    return os.path.join(SYNC_ROOT, src, rp)


def sync_repo_snapshot(source: str, repo: str, files: list) -> tuple[str, int]:
    target = repo_local_dir(source, repo)
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if os.path.isdir(target):
        shutil.rmtree(target)
    os.makedirs(target, exist_ok=True)

    written = 0
    base = Path(target).resolve()
    for item in files or []:
        rel = (item.get('filename') or '').replace('\\', '/').lstrip('/')
        if not rel:
            continue
        out = (base / rel).resolve()
        if base not in out.parents and out != base:
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        content = item.get('patch', '')
        if not isinstance(content, str):
            continue
        out.write_text(content, encoding='utf-8', errors='replace')
        written += 1
    return target, written


def cleanup_synced_repos(source: str, existing_repos: list) -> int:
    """
    清理某来源下已不存在的本地仓库快照目录。
    返回删除的仓库目录数量。
    """
    src = _safe_segment(source or 'unknown').replace('/', '_')
    src_root = Path(SYNC_ROOT) / src
    if not src_root.exists() or not src_root.is_dir():
        return 0

    keep = {_safe_segment(normalize_repo_name(r)) for r in (existing_repos or []) if r}
    deleted = 0
    for repo_dir in src_root.iterdir():
        if not repo_dir.is_dir():
            continue
        if repo_dir.name not in keep:
            shutil.rmtree(repo_dir, ignore_errors=True)
            deleted += 1

    # 来源目录空了则顺带清理
    try:
        next(src_root.iterdir())
    except StopIteration:
        src_root.rmdir()
    except Exception:
        pass
    return deleted


def search_synced_code(keyword: str, case_sensitive: bool = False,
                       repo: str = '', source: str = '',
                       limit: int = 200) -> list:
    kw = keyword if case_sensitive else keyword.lower()
    if not kw:
        return []

    root = Path(SYNC_ROOT)
    if not root.exists():
        return []

    repo_filter = normalize_repo_name(repo).strip()
    results = []

    for src_dir in root.iterdir():
        if not src_dir.is_dir():
            continue
        if source and src_dir.name != source:
            continue
        for repo_dir in src_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            rel_repo = repo_dir.relative_to(src_dir).as_posix()
            if repo_filter and repo_filter != rel_repo:
                continue

            for path in repo_dir.rglob('*'):
                if len(results) >= limit:
                    return results
                if not path.is_file():
                    continue
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding='utf-8', errors='ignore')
                except Exception:
                    continue
                hay = text if case_sensitive else text.lower()
                idx = hay.find(kw)
                if idx < 0:
                    continue

                line_no = text.count('\n', 0, idx) + 1
                line_start = text.rfind('\n', 0, idx)
                line_end = text.find('\n', idx)
                if line_start < 0:
                    line_start = -1
                if line_end < 0:
                    line_end = len(text)
                snippet = text[line_start + 1:line_end].strip()

                results.append({
                    'source': src_dir.name,
                    'repo': rel_repo,
                    'file': path.relative_to(repo_dir).as_posix(),
                    'line': line_no,
                    'snippet': snippet[:300],
                })
    return results
