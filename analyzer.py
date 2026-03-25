"""LLM 分析模块 —— 支持多 LLM 提供商、并发文件分析、漏洞指纹"""
import json, os, hashlib
import concurrent.futures
import database as db
from openai import OpenAI
import anthropic
from clients.semgrep_scanner import scan_patch as semgrep_scan, is_available as semgrep_ok
from clients.opensca_scanner  import scan_patch as opensca_scan, is_available as opensca_ok

SKIP_EXTENSIONS  = {'.png','.jpg','.jpeg','.gif','.svg','.ico','.webp','.mp4','.mp3',
                    '.wav','.pdf','.zip','.tar','.gz','.lock','.sum'}
AUDIT_EXTENSIONS = {'.js','.ts','.jsx','.tsx','.vue','.html','.css','.py','.go','.java',
                    '.rb','.php','.rs','.cs','.cpp','.c','.sol','.json','.yaml','.yml',
                    '.toml','.env','.sh','.bash','.svelte','.mjs','.cjs','Dockerfile'}

# ── 提供商配置 ────────────────────────────────────────────────────
PROVIDER_CONFIGS = {
    'deepseek':   {'base_url': 'https://api.deepseek.com/v1',
                   'default_model': 'deepseek-chat'},
    'openai':     {'base_url': 'https://api.openai.com/v1',
                   'default_model': 'gpt-4o'},
    'qwen':       {'base_url': 'https://dashscope.aliyuncs.com/compatible-mode/v1',
                   'default_model': 'qwen-max'},
    'zhipu':      {'base_url': 'https://open.bigmodel.cn/api/paas/v4/',
                   'default_model': 'glm-4-plus'},
    'moonshot':   {'base_url': 'https://api.moonshot.cn/v1',
                   'default_model': 'moonshot-v1-32k'},
    'doubao':     {'base_url': 'https://ark.cn-beijing.volces.com/api/v3',
                   'default_model': 'doubao-pro-32k'},
    'gemini':     {'base_url': 'https://generativelanguage.googleapis.com/v1beta/openai/',
                   'default_model': 'gemini-2.0-flash'},
    'openrouter': {'base_url': 'https://openrouter.ai/api/v1',
                   'default_model': 'deepseek/deepseek-chat'},
    'ollama':     {'base_url': 'http://localhost:11434/v1',
                   'default_model': 'llama3.2'},
    'anthropic':  {'base_url': None,
                   'default_model': 'claude-opus-4-6'},
    'minimax':    {'base_url': 'https://api.minimax.chat/v1',
                   'default_model': 'abab6.5s-chat'},
    'baidu':      {'base_url': 'https://qianfan.baidubce.com/v2',
                   'default_model': 'ernie-4.5'},
}

def _ext(filename):
    _, ext = os.path.splitext(filename)
    return ext.lower()

def _find_prompt(filename, prompts):
    """找到最匹配的提示词。自定义提示词（is_default=0）优先；同级别中 id 越大（越新）越优先。"""
    ext  = _ext(filename)
    base = os.path.basename(filename)
    for p in prompts:
        exts = [e.strip() for e in p['extensions'].split(',') if e.strip()]
        if ext in exts or base in exts:
            return p['content']
    return None

def _parse(text):
    text = text.strip()
    if text.startswith('```'):
        text = text.split('\n', 1)[-1]
        if '```' in text:
            text = text.rsplit('```', 1)[0]
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        s, e = text.find('{'), text.rfind('}')
        if s != -1 and e != -1:
            try:
                return json.loads(text[s:e+1])
            except Exception:
                pass
    return {'findings': [], 'summary': 'Failed to parse response'}

def _make_fingerprint(repo, filename, title, line=''):
    """生成漏洞指纹，用于跨扫描去重。"""
    src = f"{repo}:{filename}:{title}:{line}"
    return hashlib.md5(src.encode()).hexdigest()

def build_llm_caller(llm_cfg: dict):
    """
    根据配置构造调用函数 call_fn(prompt) -> str。
    支持 Anthropic SDK 及所有 OpenAI 兼容提供商。
    配置优先级：provider/api_key/model > 旧版 deepseek_api_key / anthropic_api_key。
    返回 None 表示未配置任何 LLM。
    """
    provider = llm_cfg.get('provider', '').strip()
    api_key  = llm_cfg.get('api_key',  '').strip()
    model    = llm_cfg.get('model',    '').strip()
    base_url = llm_cfg.get('base_url', '').strip()

    # 旧版兼容回退
    if not provider:
        if llm_cfg.get('deepseek_api_key', ''):
            provider = 'deepseek'
            api_key  = llm_cfg['deepseek_api_key']
        elif llm_cfg.get('anthropic_api_key', ''):
            provider = 'anthropic'
            api_key  = llm_cfg['anthropic_api_key']

    if not provider:
        return None

    pcfg = PROVIDER_CONFIGS.get(provider, {})
    effective_model = model or pcfg.get('default_model', 'gpt-4o')

    if provider == 'anthropic':
        if not api_key:
            api_key = llm_cfg.get('anthropic_api_key', '')
        if not api_key:
            return None
        client = anthropic.Anthropic(api_key=api_key)
        def call_fn(prompt):
            resp = client.messages.create(
                model=effective_model, max_tokens=2048,
                messages=[{'role': 'user', 'content': prompt}]
            )
            return resp.content[0].text
        return call_fn

    # OpenAI 兼容提供商
    effective_base_url = base_url or pcfg.get('base_url', '')
    effective_key      = api_key or ('ollama' if provider == 'ollama' else '')
    if not effective_key:
        return None

    client = OpenAI(api_key=effective_key, base_url=effective_base_url)
    def call_fn(prompt):
        resp = client.chat.completions.create(
            model=effective_model, temperature=0.1, max_tokens=2048,
            messages=[{'role': 'user', 'content': prompt}]
        )
        return resp.choices[0].message.content
    return call_fn

_SCAN_TYPE_INSTRUCTION = {
    'poison': (
        "\n\nTASK FOCUS: This is a supply chain and code poisoning scan. "
        "Focus EXCLUSIVELY on: malicious code injection, backdoors, "
        "supply chain attacks (typosquatting, dependency confusion, malicious packages), "
        "unexpected outbound network requests, data exfiltration logic, and obfuscated/suspicious code. "
        "Do NOT report general security vulnerabilities (XSS, SQLi, etc.) unless they are part of a supply chain attack."
    ),
    'incremental_audit': (
        "\n\nTASK FOCUS: This is a critical/high severity only audit. "
        "ONLY audit for vulnerability classes that can result in severity 'critical' or 'high' — "
        "such as RCE, SQL injection, authentication bypass, privilege escalation, SSRF, "
        "hardcoded credentials, insecure deserialization, and similar high-impact issues. "
        "Do NOT analyze or report medium or low severity issues at all — skip them entirely. "
        "If no critical or high severity vulnerabilities exist, return an empty findings array."
    ),
    'full_audit': (
        "\n\nTASK FOCUS: This is a comprehensive full audit of the main/master branch. "
        "Report ALL security findings across all severity levels (critical, high, medium, low)."
    ),
}

def _analyze_single_file(filename, patch, commit_message, call_fn, prompts, max_diff_chars,
                         scan_type='full_audit'):
    """分析单个文件，返回 findings 列表。供并发调用。"""
    if len(patch) > max_diff_chars:
        patch = patch[:max_diff_chars] + '\n[truncated]'
    prompt_tpl = _find_prompt(filename, prompts)
    if not prompt_tpl:
        return []
    prompt = prompt_tpl.format(
        filename=filename,
        message=commit_message,
        diff=patch
    )
    task_instruction = _SCAN_TYPE_INSTRUCTION.get(scan_type, '')
    if task_instruction:
        prompt += task_instruction
    try:
        raw = call_fn(prompt)
        result = _parse(raw)
        findings = []
        for f in result.get('findings', []):
            f['filename']     = filename
            f['file_summary'] = result.get('summary', '')
            findings.append(f)
        return findings
    except Exception as e:
        print(f'    [analyzer] {filename} LLM 分析失败: {e}')
        return []

def analyze_commit(commit, llm_cfg=None, max_diff_chars=12000, prompts=None,
                   opensca_token='', semgrep_token='',
                   added_only=False, scan_type='full_audit',
                   # 旧版兼容参数
                   deepseek_key='', anthropic_key=''):
    """
    分析一次提交，返回 findings 列表（每条附带 fingerprint）。

    新调用方式：analyze_commit(commit, llm_cfg={...}, ...)
    旧调用方式（保持兼容）：analyze_commit(commit, deepseek_key, anthropic_key, max_diff, ...)
    """
    # 处理旧版调用 analyze_commit(commit, deepseek_key_str, ...)
    if isinstance(llm_cfg, str):
        deepseek_key = llm_cfg
        llm_cfg = None

    if llm_cfg is None:
        llm_cfg = {}
    if deepseek_key and not llm_cfg.get('provider'):
        llm_cfg = {'deepseek_api_key': deepseek_key, 'anthropic_api_key': anthropic_key}

    if prompts is None:
        prompts = db.get_prompts_for_analysis()

    call_fn = build_llm_caller(llm_cfg)

    # 筛选可分析文件
    # added_only=True：只分析新增文件（status=added），忽略修改/删除
    eligible = [
        (f['filename'], f.get('patch', ''))
        for f in commit.get('files', [])
        if f.get('patch')
           and _ext(f['filename']) not in SKIP_EXTENSIONS
           and (_ext(f['filename']) in AUDIT_EXTENSIONS
                or os.path.basename(f['filename']) in AUDIT_EXTENSIONS)
           and (not added_only or f.get('status') == 'added')
    ]

    repo    = commit.get('repo', '')
    message = commit.get('message', '')
    all_findings = []

    if call_fn:
        # ── LLM 并发分析 ──────────────────────────────────────────
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_map = {
                executor.submit(
                    _analyze_single_file, fname, patch, message,
                    call_fn, prompts, max_diff_chars, scan_type
                ): fname
                for fname, patch in eligible
            }
            for future in concurrent.futures.as_completed(future_map):
                fname = future_map[future]
                try:
                    for f in future.result():
                        # 附加指纹
                        f['fingerprint'] = _make_fingerprint(
                            repo, f['filename'],
                            f.get('title', ''), str(f.get('line', ''))
                        )
                        all_findings.append(f)
                except Exception as e:
                    print(f'    [analyzer] {fname} 并发分析出错: {e}')
    else:
        # ── 无 LLM：semgrep + opensca ─────────────────────────────
        for filename, patch in eligible:
            try:
                if semgrep_ok():
                    for f in semgrep_scan(filename, patch, token=semgrep_token):
                        f['filename'] = filename
                        f['fingerprint'] = _make_fingerprint(repo, filename, f.get('title', ''))
                        all_findings.append(f)
            except Exception as e:
                print(f'    [analyzer] {filename} semgrep 失败: {e}')
            try:
                if opensca_ok():
                    for f in opensca_scan(filename, patch, opensca_token):
                        f['filename'] = filename
                        f['fingerprint'] = _make_fingerprint(repo, filename, f.get('title', ''))
                        all_findings.append(f)
            except Exception as e:
                print(f'    [analyzer] {filename} opensca 失败: {e}')

    return all_findings
