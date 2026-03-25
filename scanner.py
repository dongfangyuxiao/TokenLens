"""核心扫描逻辑，供 scheduler 和 API 调用"""
import os
from datetime import datetime
from clients.github    import fetch_recent_changes as github_changes
from clients.gitlab    import fetch_recent_changes as gitlab_changes
from clients.bitbucket import fetch_recent_changes as bitbucket_changes
from clients.gitee     import fetch_recent_changes as gitee_changes
from analyzer  import analyze_commit
from reporter  import build_report
from notifier  import notify_all
import database as db
import syslog_sender as syslog

REPORTS_DIR = 'reports'

class _StopRequested(Exception):
    pass

def _check(stop_event, pause_event):
    """暂停时阻塞；收到停止信号时抛出异常。"""
    if pause_event:
        pause_event.wait()
    if stop_event and stop_event.is_set():
        raise _StopRequested()

def run_scan(base_url='', scan_type='incremental_audit', full_scan=False,
            stop_event=None, pause_event=None):
    """
    执行一次完整扫描。
    base_url:  用于报告链接，如 http://your-server:8000
    scan_type: 'poison' | 'incremental_audit' | 'full_audit'
    full_scan: 旧版兼容参数，True 映射到 full_audit
    返回 scan_id
    """
    # 旧版兼容
    if full_scan and scan_type == 'incremental_audit':
        scan_type = 'full_audit'

    scan_id = db.create_scan(scan_type=scan_type)

    _MODE_LABELS = {
        'poison'           : '增量扫描(投毒/供应链)',
        'incremental_audit': '增量审计(严重/高危)',
        'full_audit'       : '全量审计(main/master)',
    }
    mode = _MODE_LABELS.get(scan_type, scan_type)

    # 扫描行为映射
    _do_full_scan = (scan_type == 'full_audit')
    _added_only   = False

    def log(level, msg):
        print(msg)
        db.add_scan_log(scan_id, level, msg)

    log('info', f'{"="*60}')
    log('info', f'扫描开始 [{mode}] #{scan_id}  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    log('info', '='*60)

    try:
        accounts   = db.get_accounts()
        llm_cfg    = db.get_llm_config()
        app_cfg    = db.get_app_config()
        channels   = db.get_channels()
        whitelist  = db.get_whitelist_set()
        scan_hours = int(app_cfg.get('scan_interval_hours', 1))
        max_diff   = int(app_cfg.get('max_diff_chars', 12000))
        prompts    = db.get_prompts_for_analysis()
        opensca_token  = app_cfg.get('opensca_token', '')
        semgrep_token  = app_cfg.get('semgrep_token', '')

        # 打印当前使用的 LLM 提供商
        provider = llm_cfg.get('provider', '')
        if not provider:
            if llm_cfg.get('deepseek_api_key'):
                provider = 'deepseek (legacy)'
            elif llm_cfg.get('anthropic_api_key'):
                provider = 'anthropic (legacy)'
        log('info', f'LLM 提供商: {provider or "未配置（使用静态扫描）"}')
        if whitelist:
            log('info', f'白名单条目: {len(whitelist)} 条')

        if not accounts:
            log('warning', '未配置任何代码平台账户，扫描跳过')
            db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '')
            return scan_id

        # 1. 拉取提交
        changes = []
        for acc in accounts:
            _check(stop_event, pause_event)
            log('info', f'\n[{acc["platform"]}] {acc["name"]}')
            try:
                platform = acc['platform']
                if platform == 'github':
                    items = github_changes(acc['token'], acc.get('owner', ''), scan_hours, _do_full_scan)
                elif platform == 'bitbucket':
                    items = bitbucket_changes(acc['token'], acc.get('owner', ''), scan_hours, _do_full_scan)
                elif platform == 'gitee':
                    items = gitee_changes(acc['token'], acc.get('owner', ''), scan_hours, _do_full_scan)
                elif platform in ('tgit', 'codeup'):
                    _default_urls = {
                        'tgit':   'https://git.code.tencent.com',
                        'codeup': 'https://codeup.aliyun.com',
                    }
                    url = acc.get('url', '').strip() or _default_urls[platform]
                    items = gitlab_changes(acc['token'], url, scan_hours, _do_full_scan)
                else:
                    items = gitlab_changes(acc['token'], acc.get('url', 'https://gitlab.com'), scan_hours, _do_full_scan)
                log('info', f'  获取到 {len(items)} 次提交')
                changes.extend(items)
            except Exception as e:
                log('error', f'  拉取失败: {e}')

        if not changes:
            log('info', '无新提交，扫描结束')
            db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '')
            syslog.send('info', 'SCAN', f'扫描完成 #{scan_id} [{mode}]: 无新提交')
            return scan_id

        # 2. 分析
        log('info', f'\n开始分析 {len(changes)} 次提交...')
        scan_results = []
        suppressed_total = 0
        for commit in changes:
            _check(stop_event, pause_event)
            log('info', f"  [{commit['source']}] {commit['repo']} {commit['commit_sha'][:7]} by {commit.get('author','')}")
            findings = analyze_commit(
                commit,
                llm_cfg=llm_cfg,
                max_diff_chars=max_diff,
                prompts=prompts,
                opensca_token=opensca_token,
                semgrep_token=semgrep_token,
                added_only=_added_only,
                scan_type=scan_type,
            )

            # 白名单过滤
            if whitelist and findings:
                before = len(findings)
                findings = [
                    f for f in findings
                    if not db.is_whitelisted(
                        commit.get('repo', ''),
                        f.get('filename', ''),
                        f.get('title', ''),
                        whitelist
                    )
                ]
                suppressed = before - len(findings)
                if suppressed:
                    suppressed_total += suppressed
                    log('info', f"    白名单过滤 {suppressed} 条")

            if findings:
                log('info', f"    发现 {len(findings)} 个漏洞: " +
                    ', '.join(f"{f.get('severity','?')}:{f.get('title','')[:30]}" for f in findings))
            scan_results.append({**commit, 'findings': findings})

        if suppressed_total:
            log('info', f'\n白名单共过滤 {suppressed_total} 条误报')

        # 3. 报告
        html, summary = build_report(scan_results)
        os.makedirs(REPORTS_DIR, exist_ok=True)
        fname = f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html'
        fpath = os.path.join(REPORTS_DIR, fname)
        with open(fpath, 'w', encoding='utf-8') as f:
            f.write(html)
        counts = summary['counts']
        log('info', f'\n报告已生成: {fpath}')
        log('info', f'扫描结果: 严重 {counts["critical"]} / 高危 {counts["high"]} / 中危 {counts["medium"]} / 低危 {counts["low"]}')

        db.finish_scan(scan_id, len(changes), counts, fpath)
        db.save_findings(scan_id, scan_results)
        syslog.send('info', 'SCAN',
            f'扫描完成 #{scan_id} [{mode}]: 严重 {counts["critical"]} / 高危 {counts["high"]} / '
            f'中危 {counts["medium"]} / 低危 {counts["low"]}, 共 {len(changes)} 次提交')

        # 3b. 按仓库统计
        repo_counts = {}
        for item in scan_results:
            key = (item.get('repo', 'unknown'), item.get('source', ''))
            if key not in repo_counts:
                repo_counts[key] = {'repo': key[0], 'source': key[1],
                                    'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for f in item.get('findings', []):
                sev = f.get('severity', 'low')
                if sev in repo_counts[key]:
                    repo_counts[key][sev] += 1
        db.save_scan_repos(scan_id, list(repo_counts.values()))

        # 3c. 严重/高危漏洞逐条上报 syslog
        for item in scan_results:
            for f in item.get('findings', []):
                if f.get('severity') in ('critical', 'high'):
                    syslog.send('warning', 'FINDING',
                        f'[{f["severity"].upper()}] {item["repo"]} {item["commit_sha"][:7]}: '
                        f'{f.get("title", "")} ({f.get("filename", "")})')

        # 4. 通知
        report_url = f'{base_url}/reports/{fname}' if base_url else ''
        notify_all(channels, summary, html, report_url)

    except _StopRequested:
        log('info', '\n扫描已被手动停止')
        db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '', '', status='stopped')
        syslog.send('info', 'SCAN', f'扫描已停止 #{scan_id} [{mode}]')
    except Exception as e:
        log('error', f'\n扫描异常: {e}')
        db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '', str(e))
        syslog.send('error', 'SCAN', f'扫描异常 #{scan_id}: {e}')

    log('info', f'\n扫描完成 #{scan_id}')
    return scan_id
