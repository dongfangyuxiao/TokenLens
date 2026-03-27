#!/usr/bin/env python3
import re
import sys
from pathlib import Path

BLOCK_PATTERNS = [
    re.compile(r'ghp_[A-Za-z0-9]{20,}'),
    re.compile(r'github_pat_[A-Za-z0-9_]{30,}'),
    re.compile(r'glpat-[A-Za-z0-9_.-]{20,}'),
    re.compile(r'AKIA[0-9A-Z]{16}'),
    re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'),
    re.compile(r'(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*[\'"][A-Za-z0-9_\-./=]{16,}[\'"]'),
]

ALLOW_FILES = {
    '.env.example',
    'README.md',
    'docs/technical-document.md',
    'docs/user-manual.md',
    'CHANGELOG.md',
}


def check_file(path: Path) -> list[str]:
    issues = []
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return issues

    for i, line in enumerate(text.splitlines(), start=1):
        for p in BLOCK_PATTERNS:
            if p.search(line):
                issues.append(f'{path}:{i}: potential secret pattern matched')
                break
    return issues


def main(argv: list[str]) -> int:
    files = [Path(a) for a in argv[1:] if a and not a.startswith('-')]
    if not files:
        return 0
    all_issues = []
    for f in files:
        if not f.exists() or not f.is_file():
            continue
        if f.name in ALLOW_FILES:
            continue
        all_issues.extend(check_file(f))
    if all_issues:
        print('Secret guard failed:')
        for item in all_issues:
            print('  -', item)
        print('\nIf this is a false positive, remove sensitive text or move examples to .env.example/docs.')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
