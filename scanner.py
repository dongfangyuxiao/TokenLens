"""核心扫描逻辑，供 scheduler 和 API 调用"""
import os
from datetime import datetime, timezone, timedelta
from clients.github    import fetch_recent_changes as github_changes
from clients.gitlab    import fetch_recent_changes as gitlab_changes
from clients.bitbucket import fetch_recent_changes as bitbucket_changes
from clients.gitee     import fetch_recent_changes as gitee_changes
from analyzer  import analyze_commit, LLMQuotaExhausted
from reporter  import build_report
from notifier  import notify_all
import database as db
import syslog_sender as syslog
from repo_sync import sync_repo_snapshot, normalize_repo_name
from sbom import extract_components_from_files

REPORTS_DIR = 'reports'


def _dedup_files_by_repo(changes):
    """
    将同一仓库多次提交中的文件去重：每个文件只保留最新提交的 patch。
    API 已按时间倒序返回提交（最新在前），遍历时首次出现的即为最新版本。
    返回列表：每个仓库一条记录，commit_sha / author / message 取最新提交，
    files 为去重后的文件列表，额外附带 commit_count 供日志使用。
    """
    from collections import defaultdict, OrderedDict
    # 按 (repo, source) 分组，保持仓库顺序
    groups = OrderedDict()
    for c in changes:
        key = (c['repo'], c['source'])
        groups.setdefault(key, []).append(c)

    result = []
    for (repo, source), commits in groups.items():
        seen = set()
        deduped_files = []
        for commit in commits:          # commits[0] 是最新的
            for f in commit['files']:
                fname = f['filename']
                if fname not in seen:
                    seen.add(fname)
                    deduped_files.append(f)

        if not deduped_files:
            continue

        latest = commits[0]
        result.append({
            **latest,
            'files'        : deduped_files,
            'commit_count' : len(commits),
            'message'      : f'[{len(commits)} 次提交] {latest["message"]}',
        })
    return result

class _StopRequested(Exception):
    pass

def _check(stop_event, pause_event):
    """暂停时阻塞；收到停止信号时抛出异常。"""
    if pause_event:
        pause_event.wait()
    if stop_event and stop_event.is_set():
        raise _StopRequested()

def run_scan(base_url='', scan_type='incremental_audit', full_scan=False,
            stop_event=None, pause_event=None, manual=False, llm_profile_id=None):
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

    scan_id = db.create_scan(scan_type=scan_type, llm_profile_id=llm_profile_id)

    _MODE_LABELS = {
        'poison'           : '增量扫描(投毒/供应链)',
        'incremental_audit': '增量审计(严重/高危)',
        'full_audit'       : '全量审计(main/master)',
    }
    mode = _MODE_LABELS.get(scan_type, scan_type)

    # 扫描行为映射
    _added_only = False

    def log(level, msg):
        print(msg)
        db.add_scan_log(scan_id, level, msg)

    log('info', f'{"="*60}')
    log('info', f'扫描开始 [{mode}] #{scan_id}  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    log('info', '='*60)

    try:
        accounts   = db.get_accounts()
        if llm_profile_id:
            _profile = db.get_llm_profile(llm_profile_id)
            llm_cfg  = {
                'provider': _profile['provider'],
                'model':    _profile['model'],
                'api_key':  _profile['api_key'],
                'base_url': _profile['base_url'],
            } if _profile else db.get_llm_config()
        else:
            llm_cfg = db.get_llm_config()
        app_cfg    = db.get_app_config()
        channels   = db.get_channels()
        whitelist  = db.get_whitelist_set()
        scan_hours = int(app_cfg.get('scan_interval_hours', 1))
        max_diff   = int(app_cfg.get('max_diff_chars', 12000))
        prompts    = db.get_prompts_for_analysis()
        opensca_token  = app_cfg.get('opensca_token', '')
        semgrep_token  = app_cfg.get('semgrep_token', '')

        # 手动触发：全量拉取所有提交，不受时间窗口限制
        if manual:
            scan_since_iso = None
            log('info', f'手动触发 [{mode}]，全量拉取所有仓库文件（不限时间范围）')
        else:
            # 动态计算 since：优先使用上次同类型扫描的完成时间，
            # 保证不遗漏两次扫描之间的任何提交。
            last_scan_time = db.get_last_successful_scan_time(scan_type)
            if last_scan_time:
                since_dt = datetime.fromisoformat(last_scan_time).replace(tzinfo=timezone.utc)
                log('info', f'上次 [{mode}] 扫描完成于 {last_scan_time}，本次从该时间点起获取提交')
            else:
                since_dt = datetime.now(timezone.utc) - timedelta(hours=scan_hours)
                log('info', f'首次 [{mode}] 扫描，回溯 {scan_hours} 小时')
            scan_since_iso = since_dt.isoformat()

        # 打印当前使用的 LLM 提供商
        provider = llm_cfg.get('provider', '')
        log('info', f'LLM 提供商: {provider or "未配置（使用静态扫描）"}')
        if whitelist:
            log('info', f'白名单条目: {len(whitelist)} 条')

        if not accounts:
            log('warning', '未配置任何代码平台账户，扫描跳过')
            db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '')
            return scan_id

        # 流水线：每个账号拉取完毕后立即去重并分析，无需等待所有账号拉取完成
        scan_results = []
        suppressed_total = 0
        _quota_paused = False

        for acc in accounts:
            if _quota_paused:
                break
            _check(stop_event, pause_event)
            log('info', f'\n[{acc["platform"]}] {acc["name"]}')
            try:
                platform = acc['platform']
                if platform == 'github':
                    items = github_changes(acc['token'], acc.get('owner', ''), scan_since_iso)
                elif platform == 'bitbucket':
                    items = bitbucket_changes(acc['token'], acc.get('owner', ''), scan_since_iso)
                elif platform == 'gitee':
                    items = gitee_changes(acc['token'], acc.get('owner', ''), scan_since_iso)
                elif platform in ('tgit', 'codeup'):
                    _default_urls = {
                        'tgit':   'https://git.code.tencent.com',
                        'codeup': 'https://codeup.aliyun.com',
                    }
                    url = acc.get('url', '').strip() or _default_urls[platform]
                    items = gitlab_changes(acc['token'], url, scan_since_iso)
                else:
                    items = gitlab_changes(acc['token'], acc.get('url', 'https://gitlab.com'), scan_since_iso)
                log('info', f'  获取到 {len(items)} 次提交')
            except Exception as e:
                log('error', f'  拉取失败: {e}')
                continue

            if not items:
                log('info', '  无新提交，跳过')
                continue

            if scan_type == 'full_audit':
                for snapshot in items:
                    try:
                        source = snapshot.get('source', '')
                        repo_name = normalize_repo_name(snapshot.get('repo', ''))
                        files = snapshot.get('files', []) or []
                        branch = snapshot.get('branch', 'main')
                        local_path, file_count = sync_repo_snapshot(source, repo_name, files)
                        db.save_repo_sync_status(
                            scan_id=scan_id,
                            source=source,
                            repo=repo_name,
                            branch=branch,
                            commit_sha=snapshot.get('commit_sha', ''),
                            local_path=local_path,
                            file_count=file_count,
                        )

                        components = extract_components_from_files(files)
                        db.replace_repo_components(scan_id, source, repo_name, components)
                        log('info', f'  [同步] {source}/{repo_name} -> {local_path} ({file_count} 文件)')
                        log('info', f'  [SCA] {source}/{repo_name} 识别组件 {len(components)} 个')
                    except Exception as e:
                        log('warning', f'  同步或组件分析失败 {snapshot.get("repo","")}: {e}')

            # 按仓库聚合，同一文件只保留最新版本
            deduped = _dedup_files_by_repo(items)
            if not deduped:
                continue
            total_files = sum(len(c["files"]) for c in deduped)
            log('info', f'  共 {total_files} 个文件待分析，开始...')

            for commit in deduped:
                _check(stop_event, pause_event)
                log('info', f"  [{commit['source']}] {commit['repo']} {commit['commit_sha'][:7]} by {commit.get('author','')}")
                try:
                    findings = analyze_commit(
                        commit,
                        llm_cfg=llm_cfg,
                        max_diff_chars=max_diff,
                        prompts=prompts,
                        opensca_token=opensca_token,
                        semgrep_token=semgrep_token,
                        added_only=_added_only,
                        scan_type=scan_type,
                        stop_event=stop_event,
                    )
                except LLMQuotaExhausted as e:
                    log('error', f'\n⚠️  API Key 额度已耗尽，扫描自动暂停！请充值后手动恢复。\n    原因: {e}')
                    if pause_event:
                        pause_event.clear()
                    db.update_scan_status(scan_id, 'paused')
                    syslog.send('warning', 'SCAN',
                                f'扫描 #{scan_id} [{mode}] 因 API Key 额度耗尽自动暂停')
                    _quota_paused = True
                    break  # 跳出内层循环，外层检查 _quota_paused 后退出

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

        if not scan_results:
            log('info', '无新提交，扫描结束')
            db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '')
            syslog.send('info', 'SCAN', f'扫描完成 #{scan_id} [{mode}]: 无新提交')
            return scan_id

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

        final_status = 'paused' if _quota_paused else None
        db.finish_scan(scan_id, len(scan_results), counts, fpath, status=final_status)
        db.save_findings(scan_id, scan_results)
        syslog.send('info', 'SCAN',
            f'扫描{"暂停" if _quota_paused else "完成"} #{scan_id} [{mode}]: '
            f'严重 {counts["critical"]} / 高危 {counts["high"]} / '
            f'中危 {counts["medium"]} / 低危 {counts["low"]}, 共 {len(scan_results)} 个仓库')

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

        # 4. 通知（额度暂停时跳过通知，避免发出不完整的告警）
        if not _quota_paused:
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
