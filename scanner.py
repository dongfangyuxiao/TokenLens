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
from repo_sync import sync_repo_snapshot, normalize_repo_name, cleanup_synced_repos
from sbom import extract_components_from_files

REPORTS_DIR = 'reports'
CONFIG_EXTENSIONS = {
    '.json', '.yaml', '.yml', '.toml', '.env', '.ini', '.conf', '.cfg',
    '.properties', '.xml', '.lock', '.sum'
}
CONFIG_BASENAMES = {
    'dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'requirements.txt', 'pipfile', 'pipfile.lock',
    'pom.xml', 'go.mod', 'go.sum', '.env', '.env.local', '.env.prod', '.env.production',
}


def _is_config_file(path: str) -> bool:
    p = (path or '').strip().lower()
    if not p:
        return False
    base = os.path.basename(p)
    ext = os.path.splitext(base)[1]
    return ext in CONFIG_EXTENSIONS or base in CONFIG_BASENAMES


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


class _QuotaPauseRequested(Exception):
    pass

def _check(stop_event, pause_event):
    """暂停时阻塞；收到停止信号时抛出异常。"""
    if pause_event:
        pause_event.wait()
    if stop_event and stop_event.is_set():
        raise _StopRequested()

def run_scan(base_url='', scan_type='incremental_audit', full_scan=False,
            stop_event=None, pause_event=None, manual=False, llm_profile_id=None,
            progress_cb=None):
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
        def _report_progress(percent: int, phase: str = 'scanning', message: str = ''):
            if not progress_cb:
                return
            p = max(0, min(100, int(percent)))
            try:
                progress_cb(p, phase, message)
            except Exception:
                pass

        _report_progress(0, 'starting', '准备开始')
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
        include_config_files = app_cfg.get('scan_include_config_files', '0') == '1'

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

        # 流水线：每拉完一个仓库就立即分析并落库，避免“整账号拉完再扫”
        scan_results = []
        suppressed_total = 0
        _quota_paused = False
        source_seen_repos = {}
        source_fetch_ok = set()
        source_fetch_failed = set()
        total_accounts = len(accounts)
        completed_accounts = 0
        current_account_ratio = 0.0

        def _report_account_progress(phase='scanning', message=''):
            denom = total_accounts if total_accounts > 0 else 1
            ratio = (completed_accounts + current_account_ratio) / denom
            # 保留 99% 给最终完成态
            _report_progress(min(99, int(ratio * 100)), phase, message)

        def _source_group(platform: str) -> str:
            return 'gitlab' if platform in ('gitlab', 'tgit', 'codeup') else platform

        def _process_items(items):
            nonlocal suppressed_total, _quota_paused, scan_results
            if not items:
                return

            raw_items = items
            if scan_type == 'full_audit':
                for snapshot in raw_items:
                    try:
                        source = snapshot.get('source', '')
                        repo_name = normalize_repo_name(snapshot.get('repo', ''))
                        if source and repo_name:
                            source_seen_repos.setdefault(source, set()).add(repo_name)
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

            analysis_items = raw_items
            if not include_config_files:
                filtered = []
                skipped_files = 0
                for item in raw_items:
                    files = item.get('files', []) or []
                    keep_files = [f for f in files if not _is_config_file(f.get('filename', ''))]
                    skipped_files += max(0, len(files) - len(keep_files))
                    if keep_files:
                        filtered.append({**item, 'files': keep_files})
                analysis_items = filtered
                if skipped_files:
                    log('info', f'  配置文件已跳过 {skipped_files} 个（系统设置未启用配置文件检测）')

            # 按仓库聚合，同一文件只保留最新版本
            deduped = _dedup_files_by_repo(analysis_items)
            if not deduped:
                return
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
                    raise _QuotaPauseRequested()

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
                # 实时覆盖写入，便于前端在扫描进行中查看最新漏洞
                db.save_findings(scan_id, scan_results)

        for acc in accounts:
            if _quota_paused:
                break
            _check(stop_event, pause_event)
            log('info', f'\n[{acc["platform"]}] {acc["name"]}')
            try:
                platform = acc['platform']
                source_key = _source_group(platform)
                current_account_ratio = 0.0
                _report_account_progress('fetching', f'[{platform}] 拉取仓库中')

                def _on_repo_progress(done, total, repo_name=''):
                    nonlocal current_account_ratio
                    current_account_ratio = (done / total) if total else 1.0
                    _report_account_progress('scanning', f'{repo_name} ({done}/{total})')

                if platform == 'github':
                    items = github_changes(
                        acc['token'],
                        acc.get('owner', ''),
                        scan_since_iso,
                        on_repo=_process_items,
                        on_progress=_on_repo_progress
                    )
                elif platform == 'bitbucket':
                    items = bitbucket_changes(
                        acc['token'],
                        acc.get('owner', ''),
                        scan_since_iso,
                        on_repo=_process_items,
                        on_progress=_on_repo_progress
                    )
                elif platform == 'gitee':
                    items = gitee_changes(
                        acc['token'],
                        acc.get('owner', ''),
                        scan_since_iso,
                        on_repo=_process_items,
                        on_progress=_on_repo_progress
                    )
                elif platform in ('tgit', 'codeup'):
                    _default_urls = {
                        'tgit':   'https://git.code.tencent.com',
                        'codeup': 'https://codeup.aliyun.com',
                    }
                    url = acc.get('url', '').strip() or _default_urls[platform]
                    items = gitlab_changes(
                        acc['token'],
                        url,
                        scan_since_iso,
                        on_repo=_process_items,
                        on_progress=_on_repo_progress
                    )
                else:
                    items = gitlab_changes(
                        acc['token'],
                        acc.get('url', 'https://gitlab.com'),
                        scan_since_iso,
                        on_repo=_process_items,
                        on_progress=_on_repo_progress
                    )
                source_fetch_ok.add(source_key)
                log('info', f'  获取到 {len(items)} 次提交')
                completed_accounts += 1
                current_account_ratio = 0.0
                _report_account_progress('scanning', f'[{platform}] 处理完成')
            except _QuotaPauseRequested:
                _report_account_progress('paused', '额度不足，已暂停')
                break
            except Exception as e:
                source_fetch_failed.add(_source_group(acc['platform']))
                log('error', f'  拉取失败: {e}')
                completed_accounts += 1
                current_account_ratio = 0.0
                _report_account_progress('error', f'[{acc["platform"]}] 拉取失败')
                continue

        if scan_type == 'full_audit' and not _quota_paused:
            for source in sorted(source_fetch_ok):
                if source in source_fetch_failed:
                    log('warning', f'  [{source}] 本轮存在拉取失败，跳过陈旧仓库清理')
                    continue
                existing = sorted(source_seen_repos.get(source, set()))
                deleted = db.cleanup_repo_sync_status(source, existing)
                fs_deleted = cleanup_synced_repos(source, existing)
                if deleted.get('repo_sync_deleted', 0):
                    log('info', f'  [{source}] 已清理失效仓库 {deleted["repo_sync_deleted"]} 个')
                if fs_deleted:
                    log('info', f'  [{source}] 已清理本地失效快照 {fs_deleted} 个')

        if not scan_results:
            log('info', '无新提交，扫描结束')
            db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '')
            syslog.send('info', 'SCAN', f'扫描完成 #{scan_id} [{mode}]: 无新提交')
            _report_progress(100, 'done', '扫描完成')
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
            _report_progress(100, 'done', '扫描完成')

    except _StopRequested:
        log('info', '\n扫描已被手动停止')
        db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '', '', status='stopped')
        syslog.send('info', 'SCAN', f'扫描已停止 #{scan_id} [{mode}]')
        _report_progress(0, 'stopped', '已手动停止')
    except Exception as e:
        log('error', f'\n扫描异常: {e}')
        db.finish_scan(scan_id, 0, {'critical':0,'high':0,'medium':0,'low':0}, '', str(e))
        syslog.send('error', 'SCAN', f'扫描异常 #{scan_id}: {e}')
        _report_progress(0, 'error', f'扫描异常: {e}')

    log('info', f'\n扫描完成 #{scan_id}')
    return scan_id
