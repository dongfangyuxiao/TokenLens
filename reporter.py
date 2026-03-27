"""报告生成模块 —— 支持 HTML / Markdown / JSON 三种格式"""
import json
from datetime import datetime
from urllib.parse import urlparse
from jinja2 import Environment, select_autoescape

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
SEVERITY_COLOR = {
    'critical': '#ff4d4f',
    'high'    : '#fa8c16',
    'medium'  : '#fadb14',
    'low'     : '#52c41a',
}
SEVERITY_ZH = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危'}

_JINJA_ENV = Environment(autoescape=select_autoescape(default_for_string=True, default=True))


def _safe_http_url(url: str) -> str:
    u = (url or '').strip()
    if not u:
        return ''
    try:
        p = urlparse(u)
        if p.scheme in ('http', 'https'):
            return u
    except Exception:
        pass
    return ''

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>代码安全扫描报告</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'PingFang SC',sans-serif;
  background:#f0f2f5;color:#1a1a1a;padding:24px}
.container{max-width:980px;margin:0 auto}
h1{font-size:22px;font-weight:700;margin-bottom:4px}
.meta{font-size:13px;color:#888;margin-bottom:24px}
.summary-cards{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:24px}
.card{background:#fff;border-radius:10px;padding:16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.card-num{font-size:28px;font-weight:700}
.card-label{font-size:12px;color:#888;margin-top:4px}
.card.critical .card-num{color:#ff4d4f}
.card.high .card-num{color:#fa8c16}
.card.medium .card-num{color:#d4b106}
.card.low .card-num{color:#52c41a}
/* 过滤栏 */
.filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-btn{padding:4px 14px;border:1px solid #e8e8e8;border-radius:16px;font-size:12px;
  font-weight:600;cursor:pointer;background:#fff;color:#666;transition:.15s}
.filter-btn:hover{border-color:#1677ff;color:#1677ff}
.filter-btn.active{border-color:#1677ff;background:#e6f4ff;color:#1677ff}
.filter-btn.c.active{border-color:#ff4d4f;background:#fff1f0;color:#ff4d4f}
.filter-btn.h.active{border-color:#fa8c16;background:#fff7e6;color:#fa8c16}
.filter-btn.m.active{border-color:#d4b106;background:#feffe6;color:#d4b106}
.filter-btn.l.active{border-color:#52c41a;background:#f6ffed;color:#52c41a}
/* 漏洞块 */
.repo-block{background:#fff;border-radius:10px;margin-bottom:16px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06)}
.repo-header{padding:14px 18px;background:#fafafa;border-bottom:1px solid #f0f0f0;
  display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.repo-name{font-size:15px;font-weight:700}
.source-tag{font-size:11px;padding:2px 8px;border-radius:4px;font-weight:600}
.source-github{background:#e6f4ff;color:#1677ff}
.source-gitlab{background:#fff0f6;color:#c41d7f}
.commit-info{font-size:12px;color:#888}
.commit-link{color:#1677ff;text-decoration:none}
.no-issues{padding:14px 18px;font-size:13px;color:#52c41a}
.finding{border-top:1px solid #f5f5f5;padding:14px 18px}
.finding.hidden{display:none}
.finding-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.severity-badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;color:#fff}
.type-badge{font-size:11px;padding:2px 8px;border-radius:4px;background:#f5f5f5;color:#666}
.finding-title{font-size:14px;font-weight:600}
.finding-file{font-size:12px;color:#888;margin-bottom:6px}
.finding-desc{font-size:13px;color:#555;line-height:1.6;margin-bottom:6px}
.finding-rec{font-size:12px;color:#1677ff;padding:8px 12px;background:#f0f5ff;border-radius:6px}
.finding-rec::before{content:'💡 修复建议：';font-weight:600}
/* 导出按钮 */
.export-bar{display:flex;gap:8px;margin-bottom:16px}
.export-btn{padding:6px 14px;border:1px solid #d9d9d9;border-radius:6px;font-size:12px;
  cursor:pointer;background:#fff;color:#555;text-decoration:none}
.export-btn:hover{border-color:#1677ff;color:#1677ff}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 代码安全扫描报告</h1>
  <div class="meta">扫描时间：{{ scan_time }}　|　共扫描 {{ total_commits }} 次提交，{{ total_files }} 个文件</div>

  <div class="summary-cards">
    <div class="card">
      <div class="card-num">{{ total_findings }}</div>
      <div class="card-label">发现总数</div>
    </div>
    <div class="card critical">
      <div class="card-num">{{ counts.critical }}</div>
      <div class="card-label">严重</div>
    </div>
    <div class="card high">
      <div class="card-num">{{ counts.high }}</div>
      <div class="card-label">高危</div>
    </div>
    <div class="card medium">
      <div class="card-num">{{ counts.medium }}</div>
      <div class="card-label">中危</div>
    </div>
    <div class="card low">
      <div class="card-num">{{ counts.low }}</div>
      <div class="card-label">低危</div>
    </div>
  </div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterSev('all',this)">全部（{{ total_findings }}）</button>
    {% if counts.critical %}<button class="filter-btn c" onclick="filterSev('critical',this)">严重（{{ counts.critical }}）</button>{% endif %}
    {% if counts.high %}<button class="filter-btn h" onclick="filterSev('high',this)">高危（{{ counts.high }}）</button>{% endif %}
    {% if counts.medium %}<button class="filter-btn m" onclick="filterSev('medium',this)">中危（{{ counts.medium }}）</button>{% endif %}
    {% if counts.low %}<button class="filter-btn l" onclick="filterSev('low',this)">低危（{{ counts.low }}）</button>{% endif %}
  </div>

  {% for repo_data in repos %}
  <div class="repo-block">
    <div class="repo-header">
      <span class="repo-name">{{ repo_data.repo }}</span>
      <span class="source-tag source-{{ repo_data.source }}">{{ repo_data.source }}</span>
      <span class="commit-info">
        {% if repo_data.commit_url %}
        <a class="commit-link" href="{{ repo_data.commit_url }}" target="_blank" rel="noopener noreferrer">{{ repo_data.commit_sha[:7] }}</a>
        {% else %}
        {{ repo_data.commit_sha[:7] }}
        {% endif %}
        　{{ repo_data.author }}：{{ repo_data.message }}
        　{{ repo_data.committed_at }}
      </span>
    </div>
    {% if repo_data.findings %}
      {% for f in repo_data.findings %}
      <div class="finding" data-sev="{{ f.severity }}">
        <div class="finding-header">
          <span class="severity-badge" style="background:{{ severity_color[f.severity] }}">{{ severity_zh[f.severity] }}</span>
          <span class="type-badge">{{ '🔴 投毒' if f.type == 'poisoning' else '🛡️ 漏洞' }}</span>
          <span class="finding-title">{{ f.title }}</span>
        </div>
        <div class="finding-file">📄 {{ f.filename }}{% if f.line %}  第 {{ f.line }} 行{% endif %}</div>
        <div class="finding-desc">{{ f.description }}</div>
        {% if f.recommendation %}
        <div class="finding-rec">{{ f.recommendation }}</div>
        {% endif %}
      </div>
      {% endfor %}
    {% else %}
      <div class="no-issues">✅ 未发现安全问题</div>
    {% endif %}
  </div>
  {% endfor %}
</div>
<script>
function filterSev(sev, btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding').forEach(el => {
    el.classList.toggle('hidden', sev !== 'all' && el.dataset.sev !== sev);
  });
}
</script>
</body>
</html>"""


def build_report(scan_results):
    """
    生成 HTML 报告。
    scan_results: list of {commit info + findings}
    返回 (html_str, summary_dict)
    """
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    total_findings = 0
    total_files    = 0

    repos = []
    for item in scan_results:
        findings = item.get('findings', [])
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'low'), 3))
        for f in findings:
            sev = f.get('severity', 'low')
            counts[sev] = counts.get(sev, 0) + 1
            total_findings += 1
        total_files += len(item.get('files', []))
        repos.append({**item, 'findings': findings})

    repos_view = []
    for r in repos:
        repos_view.append({**r, 'commit_url': _safe_http_url(r.get('commit_url', ''))})

    html = _JINJA_ENV.from_string(HTML_TEMPLATE).render(
        scan_time      = datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        total_commits  = len(scan_results),
        total_files    = total_files,
        total_findings = total_findings,
        counts         = counts,
        repos          = repos_view,
        severity_color = SEVERITY_COLOR,
        severity_zh    = SEVERITY_ZH,
    )

    summary = {
        'total_commits' : len(scan_results),
        'total_findings': total_findings,
        'counts'        : counts,
    }
    return html, summary


def build_markdown_report(scan_results):
    """生成 Markdown 格式报告，返回字符串。"""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    total_findings = 0

    lines = [
        '# 代码安全扫描报告',
        f'',
        f'> 扫描时间：{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
        f'',
    ]

    all_items = []
    for item in scan_results:
        findings = sorted(item.get('findings', []),
                          key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'low'), 3))
        for f in findings:
            sev = f.get('severity', 'low')
            counts[sev] = counts.get(sev, 0) + 1
            total_findings += 1
        all_items.append({**item, 'findings': findings})

    # 摘要
    lines += [
        '## 摘要',
        '',
        f'| 指标 | 数量 |',
        f'|------|------|',
        f'| 总提交数 | {len(scan_results)} |',
        f'| 发现总数 | {total_findings} |',
        f'| 严重 | {counts["critical"]} |',
        f'| 高危 | {counts["high"]} |',
        f'| 中危 | {counts["medium"]} |',
        f'| 低危 | {counts["low"]} |',
        '',
    ]

    if not total_findings:
        lines.append('> ✅ 未发现安全问题')
        return '\n'.join(lines)

    lines.append('## 漏洞详情')
    lines.append('')

    for item in all_items:
        if not item['findings']:
            continue
        sha = item.get('commit_sha', '')[:7]
        lines += [
            f'### {item.get("repo", "unknown")} — `{sha}`',
            f'',
            f'- **作者**：{item.get("author", "")}',
            f'- **提交**：{item.get("message", "")}',
            f'- **时间**：{item.get("committed_at", "")}',
            f'',
        ]
        for idx, f in enumerate(item['findings'], 1):
            sev_zh = SEVERITY_ZH.get(f.get('severity', 'low'), '未知')
            lines += [
                f'#### {idx}. [{sev_zh}] {f.get("title", "")}',
                f'',
                f'- **文件**：`{f.get("filename", "")}`'
                + (f'  第 {f.get("line")} 行' if f.get('line') else ''),
                f'- **类型**：{"投毒" if f.get("type") == "poisoning" else "漏洞"}',
                f'',
                f'**描述**：{f.get("description", "")}',
                f'',
            ]
            if f.get('recommendation'):
                lines += [f'**修复建议**：{f["recommendation"]}', '']
            lines.append('---')
            lines.append('')

    return '\n'.join(lines)


def build_json_report(scan_results):
    """生成 JSON 格式报告，返回 dict。"""
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    items  = []

    for item in scan_results:
        findings = []
        for f in item.get('findings', []):
            sev = f.get('severity', 'low')
            counts[sev] = counts.get(sev, 0) + 1
            findings.append({
                'severity'      : sev,
                'type'          : f.get('type', 'vulnerability'),
                'title'         : f.get('title', ''),
                'filename'      : f.get('filename', ''),
                'line'          : f.get('line', ''),
                'description'   : f.get('description', ''),
                'recommendation': f.get('recommendation', ''),
                'fingerprint'   : f.get('fingerprint', ''),
            })
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 3))
        items.append({
            'repo'        : item.get('repo', ''),
            'source'      : item.get('source', ''),
            'commit_sha'  : item.get('commit_sha', ''),
            'commit_url'  : item.get('commit_url', ''),
            'author'      : item.get('author', ''),
            'message'     : item.get('message', ''),
            'committed_at': item.get('committed_at', ''),
            'findings'    : findings,
        })

    return {
        'generated_at'  : datetime.now().isoformat(),
        'total_commits' : len(scan_results),
        'total_findings': sum(counts.values()),
        'counts'        : counts,
        'items'         : items,
    }
