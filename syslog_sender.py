"""Syslog 发送模块，支持 UDP/TCP，线程安全"""
import logging
import logging.handlers
import socket
import threading

_lock    = threading.Lock()
_logger  = None
_handlers = []

FACILITIES = {
    'kern':   logging.handlers.SysLogHandler.LOG_KERN,
    'user':   logging.handlers.SysLogHandler.LOG_USER,
    'mail':   logging.handlers.SysLogHandler.LOG_MAIL,
    'daemon': logging.handlers.SysLogHandler.LOG_DAEMON,
    'auth':   logging.handlers.SysLogHandler.LOG_AUTH,
    'local0': logging.handlers.SysLogHandler.LOG_LOCAL0,
    'local1': logging.handlers.SysLogHandler.LOG_LOCAL1,
    'local2': logging.handlers.SysLogHandler.LOG_LOCAL2,
    'local3': logging.handlers.SysLogHandler.LOG_LOCAL3,
    'local4': logging.handlers.SysLogHandler.LOG_LOCAL4,
    'local5': logging.handlers.SysLogHandler.LOG_LOCAL5,
    'local6': logging.handlers.SysLogHandler.LOG_LOCAL6,
    'local7': logging.handlers.SysLogHandler.LOG_LOCAL7,
}

_LEVEL_MAP = {
    'debug':    logging.DEBUG,
    'info':     logging.INFO,
    'warning':  logging.WARNING,
    'error':    logging.ERROR,
    'critical': logging.CRITICAL,
}


def _parse_facilities(raw) -> list:
    if isinstance(raw, (list, tuple)):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        items = [s.strip() for s in str(raw or '').split(',') if s.strip()]
    if not items:
        return ['local0']
    valid = [x for x in items if x in FACILITIES]
    return valid or ['local0']


def _make_handlers(cfg: dict):
    host     = cfg.get('host', '').strip()
    port     = int(cfg.get('port') or 514)
    protocol = cfg.get('protocol', 'udp')
    facilities = _parse_facilities(cfg.get('facility', 'local0'))
    socktype = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    app_name = cfg.get('app_name', 'code-audit').strip() or 'code-audit'
    handlers = []
    for fac in facilities:
        h = logging.handlers.SysLogHandler(
            address=(host, port),
            facility=FACILITIES.get(fac, logging.handlers.SysLogHandler.LOG_LOCAL0),
            socktype=socktype,
        )
        h.setFormatter(logging.Formatter(f'{app_name}: %(message)s'))
        handlers.append(h)
    return handlers


def reload(cfg: dict):
    """根据配置重新初始化（或关闭）syslog handler，应在配置变更后调用。"""
    global _logger, _handlers
    with _lock:
        for h in _handlers:
            try:
                if _logger:
                    _logger.removeHandler(h)
                h.close()
            except Exception:
                pass
        _handlers = []
        _logger = None

        if cfg.get('enabled') != '1' or not cfg.get('host', '').strip():
            return

        try:
            handlers = _make_handlers(cfg)
            lg = logging.getLogger('_code_audit_syslog')
            lg.handlers.clear()
            for h in handlers:
                lg.addHandler(h)
            lg.setLevel(logging.DEBUG)
            lg.propagate = False
            _handlers = handlers
            _logger  = lg
        except Exception as e:
            print(f'[syslog] 初始化失败: {e}')


def send(level: str, category: str, message: str):
    """异步安全地发送一条 syslog 消息，失败不抛出异常。"""
    with _lock:
        lg = _logger
    if lg is None:
        return
    try:
        lg.log(_LEVEL_MAP.get(level, logging.INFO), f'[{category}] {message}')
    except Exception as e:
        print(f'[syslog] 发送失败: {e}')


def test_send(cfg: dict) -> str | None:
    """
    用给定配置发送一条测试消息。
    返回 None 表示成功，返回错误字符串表示失败。
    """
    host = cfg.get('host', '').strip()
    if not host:
        return '未配置服务器地址'
    try:
        handlers = _make_handlers(cfg)
        lg = logging.getLogger(f'_syslog_test_{id(handlers)}')
        lg.handlers.clear()
        for h in handlers:
            lg.addHandler(h)
        lg.setLevel(logging.INFO)
        lg.propagate = False
        lg.info('[TEST] 代码安全审计平台 Syslog 连接测试')
        for h in handlers:
            h.close()
        return None
    except Exception as e:
        return str(e)
