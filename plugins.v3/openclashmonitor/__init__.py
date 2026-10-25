"""OpenClash 监控插件。

在 MoviePilot 中集中查看 OpenClash（Mihomo 内核）的运行状态、节点与订阅信息，
并监控 LocalDNS 的查询情况、版本更新与上游 DNS 健康状态。

数据来源分三路，全部可独立配置，缺一路不影响其它面板：

1. Clash / Mihomo 外部控制器 API（``http://<路由器>:9090``，Bearer 密钥）：
   运行模式、DNS 配置、代理组与节点延迟、订阅 provider 更新时间、内核版本。
   节点如果来自 proxy-provider，只在 ``/providers/proxies`` 里出现，插件会把两侧合并。
2. OpenClash LuCI API（``http://<路由器>/cgi-bin/luci/admin/services/openclash/``）：
   订阅剩余流量与到期、插件与内核的最新版本、连接数、内存与 CPU。
   跨机访问需要 LuCI 登录态：登录必须带 Referer，且要靠 302 响应里的 Set-Cookie
   拿会话（跟随跳转会丢 cookie），插件同时支持手工粘贴 sysauth cookie。
3. LocalDNS：默认对接 https://github.com/yyhoworks/LocalDNS（状态/统计/上游健康/
   查询日志/进程指标/版本），也兼容 AdGuard Home 的 HTTP API，另有不依赖任何 API
   的 UDP DNS 主动探测（对任意上游服务器测延迟）。
"""

from __future__ import annotations

import base64
import json
import random
import re
import socket
import ssl
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.sdk.logging import logger
from app.sdk.plugin import _PluginBase

try:  # 远程命令（可选能力，宿主缺失时静默降级）
    from app.schemas.types import EventType
    from app.sdk.events import Event, eventmanager
except Exception:  # noqa: BLE001
    EventType = None  # type: ignore
    Event = Any  # type: ignore
    eventmanager = None  # type: ignore

try:  # 通知类型在不同宿主版本下的位置
    from app.schemas.types import NotificationType  # type: ignore
except Exception:  # noqa: BLE001
    try:
        from app.schemas import NotificationType  # type: ignore
    except Exception:  # noqa: BLE001
        NotificationType = None  # type: ignore


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

_UA = "MoviePilot-OpenClashMonitor/0.1.0"
_SNAPSHOT_KEY = "snapshot"
_NOTIFY_KEY = "notified_versions"
_DASHBOARD_KEY = "openclashmonitor"

# Clash / Mihomo 里不属于真实节点的内置代理：优先按 type 判定，名字作为兜底
_BUILTIN_PROXY_TYPES = {
    "direct",
    "reject",
    "rejectdrop",
    "compatible",
    "pass",
    "pass-rule",
    "dns",
    "direct-ip",
}

_BUILTIN_PROXIES = {
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "DIRECT-IP",
    "PASS-RULE",
}

# LocalDNS 查询日志里代表「该域名被拦截」的 domain_set 名称
_BLOCKED_DOMAIN_SETS = {"adguard", "blocked", "blocked_aaaa", "blocked_qtype"}

_DNS_MODE_OPTIONS = [
    {"title": "LocalDNS（yyhoworks，推荐）", "value": "localdns"},
    {"title": "AdGuard Home", "value": "adguard"},
    {"title": "关闭（只用内置 UDP 探测）", "value": "none"},
]

DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "dashboard": True,
    "onlyonce": False,
    "notify": True,
    "clash_url": "http://192.168.1.1:9090",
    "clash_secret": "",
    "luci_url": "http://192.168.1.1",
    "luci_username": "",
    "luci_password": "",
    "luci_cookie": "",
    "dns_mode": "localdns",
    "ld_url": "http://192.168.1.1:19099",
    "ld_github": True,
    "ag_url": "http://192.168.1.1:3000",
    "ag_username": "",
    "ag_password": "",
    "ag_test_upstream": True,
    "dns_probe_targets": "223.5.5.5,119.29.29.29,1.1.1.1",
    "dns_probe_domain": "www.google.com",
    "interval": 10,
    "node_limit": 15,
    "querylog_limit": 20,
    "timeout": 8,
}


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------


def _now_text() -> str:
    """返回可读的本地时间文本。"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_int(value: Any, default: int = 0) -> int:
    """把任意输入尽量转成整数。"""
    try:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """把任意输入尽量转成浮点数。"""
    try:
        if value is None or value == "":
            return default
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _format_size(value: Any) -> str:
    """把字节数格式化为可读体积。"""
    size = _safe_float(value, -1)
    if size < 0:
        return "-"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    if index == 0:
        return f"{int(size)} {units[index]}"
    return f"{size:.2f} {units[index]}"


def _format_uptime(value: Any) -> str:
    """把秒数格式化为「x 天 y 小时」形式。"""
    seconds = _safe_int(value, 0)
    if seconds <= 0:
        return "-"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} 天 {hours} 小时"
    if hours:
        return f"{hours} 小时 {minutes} 分"
    return f"{minutes} 分"


def _dns_mode_from_run_mode(run_mode: str) -> str:
    """OpenClash 的运行模式可以反推 Fake-IP / Redir-Host。

    新版 Mihomo（如 alpha-gbc76c13）不再在 ``/configs`` 里返回 ``dns`` 段，
    因此 enhanced-mode 只能从 LuCI 的 ``run_mode``（fake-ip-tun / redir-host-mix …）里推断。
    """
    text = str(run_mode or "").strip().lower()
    if not text:
        return ""
    if "fake-ip" in text or "fakeip" in text:
        return "fake-ip"
    if "redir-host" in text or "redir_host" in text:
        return "redir-host"
    return ""


def _clean_loading(value: Any) -> str:
    """清理 LuCI 返回的 "loading..." 等占位值。"""
    text = str(value or "").strip()
    if not text or text.lower().startswith("loading"):
        return ""
    if text in ("0", "null", "None"):
        return ""
    return text


def _version_tuple(text: Any) -> Tuple[int, ...]:
    """把版本号解析为可比较的整数元组。"""
    nums = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in nums[:4])


def _is_newer(latest: Any, current: Any) -> bool:
    """判断 latest 是否比 current 新（缺一边则视为未知，返回 False）。"""
    new, cur = _version_tuple(latest), _version_tuple(current)
    if not new or not cur:
        return False
    return new > cur


def _normalize_url(url: str, default_scheme: str = "http") -> str:
    """补全协议头并去掉尾部斜杠。"""
    text = str(url or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    return text.rstrip("/")


def _split_host_port(text: str, default_port: int) -> Tuple[str, int]:
    """拆分 ``host[:port]``；支持 IPv6 方括号写法。"""
    raw = str(text or "").strip()
    if raw.startswith("["):
        end = raw.find("]")
        if end > 0:
            host = raw[1:end]
            rest = raw[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, default_port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if port.isdigit():
            return host, int(port)
    return raw, default_port


def _parse_cookie_header(text: str) -> Dict[str, str]:
    """把 ``a=1; b=2`` 形式的 Cookie 头解析成字典。"""
    jar: Dict[str, str] = {}
    for part in str(text or "").replace("\n", ";").split(";"):
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key, value = key.strip(), value.strip()
        if key:
            jar[key] = value
    return jar


def _payload_of(text: str) -> Any:
    """尽量把响应文本解析成 JSON，失败时返回原始文本。"""
    body = (text or "").strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        pass
    # LuCI 有时会在 JSON 前面带上调试输出，截取最外层结构再试一次
    for opener, closer in (("{", "}"), ("[", "]")):
        start, end = body.find(opener), body.rfind(closer)
        if 0 <= start < end:
            try:
                return json.loads(body[start:end + 1])
            except (ValueError, TypeError):
                continue
    return body


# ---------------------------------------------------------------------------
# HTTP 访问层
# ---------------------------------------------------------------------------

_HTTPX_CACHE: List[Any] = []  # [module] 或 [None]


def _httpx_module() -> Any:
    """优先使用宿主环境里的 httpx / httpx2 同步客户端。"""
    if not _HTTPX_CACHE:
        found = None
        for name in ("httpx", "httpx2"):
            try:
                module = __import__(name)
                found = module
                break
            except Exception:  # noqa: BLE001
                continue
        _HTTPX_CACHE.append(found)
    return _HTTPX_CACHE[0]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止 urllib 自动跟随跳转，保留原始 302 与 Set-Cookie。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _encode_body(body: Any, headers: Dict[str, str], form: bool) -> Optional[bytes]:
    """按需把请求体编码为字节。"""
    if body is None:
        return None
    if isinstance(body, (bytes, bytearray)):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    if form:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return urllib.parse.urlencode(body, doseq=True).encode("utf-8")
    headers["Content-Type"] = "application/json"
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def http_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    body: Any = None,
    form: bool = False,
    timeout: float = 10.0,
    cookies: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> Dict[str, Any]:
    """发起一次 HTTP 请求。

    返回 ``{"status": int|None, "data": Any, "text": str, "error": str|None,
    "cookies": dict}``。始终不抛异常，便于采集流程逐项降级。

    ``allow_redirects=False`` 用于登录这类靠 302 + Set-Cookie 传凭据的接口：
    跟随跳转会丢失 Set-Cookie，最终拿不到会话。
    """
    final_url = str(url or "")
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            joiner = "&" if "?" in final_url else "?"
            final_url = final_url + joiner + urllib.parse.urlencode(clean, doseq=True)

    hdrs: Dict[str, str] = {"User-Agent": _UA, "Accept": "application/json, text/plain, */*"}
    if headers:
        hdrs.update({str(k): str(v) for k, v in headers.items() if v is not None})
    if cookies:
        hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)

    payload = _encode_body(body, hdrs, form)
    result: Dict[str, Any] = {"status": None, "data": None, "text": "", "error": None, "cookies": {}}

    module = _httpx_module()
    if module is not None:
        client_kwargs: Dict[str, Any] = {"timeout": timeout,
                                        "follow_redirects": allow_redirects}
        for extra in ({"verify": False, "trust_env": False}, {"verify": False}, {}):
            try:
                client_kwargs.update(extra)
                with module.Client(**client_kwargs) as client:
                    response = client.request(method, final_url, headers=hdrs, content=payload)
                    result["status"] = int(getattr(response, "status_code", 0) or 0)
                    result["text"] = getattr(response, "text", "") or ""
                    result["cookies"] = _harvest_cookies(getattr(response, "headers", None))
                    result["data"] = _payload_of(result["text"])
                    if result["status"] >= 400:
                        result["error"] = f"HTTP {result['status']}"
                    return result
            except TypeError:
                continue
            except Exception as err:  # noqa: BLE001
                result["error"] = f"{type(err).__name__}: {err}"
                return result

    # 退化到标准库，兼容没有 httpx 的宿主或测试环境
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        request = urllib.request.Request(final_url, data=payload, headers=hdrs, method=method.upper())
        handlers: List[Any] = [urllib.request.HTTPSHandler(context=context)]
        if not allow_redirects:
            handlers.insert(0, _NoRedirectHandler())
        opener = urllib.request.build_opener(*handlers)
        with opener.open(request, timeout=timeout) as response:
            raw = response.read() or b""
            result["status"] = int(getattr(response, "status", 0) or 0)
            result["cookies"] = _harvest_cookies(response.headers)
            result["text"] = raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        result["status"] = int(getattr(err, "code", 0) or 0)
        try:
            raw = err.read() or b""
        except Exception:  # noqa: BLE001
            raw = b""
        result["text"] = raw.decode("utf-8", "replace")
        result["cookies"] = _harvest_cookies(getattr(err, "headers", None))
    except Exception as err:  # noqa: BLE001
        result["error"] = f"{type(err).__name__}: {err}"
        return result

    result["data"] = _payload_of(result["text"])
    if result["status"] and result["status"] >= 400:
        result["error"] = f"HTTP {result['status']}"
    return result


def _harvest_cookies(headers: Any) -> Dict[str, str]:
    """从响应头里提取 Set-Cookie（不依赖 cookie jar）。"""
    jar: Dict[str, str] = {}
    if headers is None:
        return jar
    try:
        items = headers.get_all("Set-Cookie") or []
    except Exception:  # noqa: BLE001
        items = []
    if not items:
        try:
            single = headers.get("Set-Cookie")
            items = [single] if single else []
        except Exception:  # noqa: BLE001
            items = []
    for item in items:
        head = str(item).split(";")[0]
        if "=" in head:
            key, _, value = head.partition("=")
            key, value = key.strip(), value.strip()
            if key:
                jar[key] = value
    return jar


# ---------------------------------------------------------------------------
# DNS 主动探测（不依赖任何第三方 API）
# ---------------------------------------------------------------------------


def _build_dns_query(name: str, qtype: int = 1) -> Tuple[int, bytes]:
    """构造一个最小的 DNS 查询报文。"""
    txid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    labels = []
    for part in str(name or "").rstrip(".").split("."):
        if not part:
            continue
        try:
            encoded = part.encode("idna")
        except Exception:  # noqa: BLE001
            encoded = part.encode("utf-8", "replace")
        labels.append(bytes([len(encoded)]) + encoded)
    question = b"".join(labels) + b"\x00" + struct.pack("!HH", qtype, 1)
    return txid, header + question


def _skip_dns_name(data: bytes, offset: int) -> int:
    """跳过 DNS 报文中的域名（处理压缩指针）。"""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _parse_dns_response(data: bytes, txid: int) -> Dict[str, Any]:
    """解析 DNS 响应，返回 rcode 与 A 记录。"""
    if len(data) < 12:
        return {"ok": False, "error": "响应过短", "answers": [], "rcode": None}
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != txid:
        return {"ok": False, "error": "事务 ID 不匹配", "answers": [], "rcode": None}
    rcode = flags & 0x000F
    offset = 12
    try:
        for _ in range(qdcount):
            offset = _skip_dns_name(data, offset) + 4
        answers: List[str] = []
        for _ in range(ancount):
            offset = _skip_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == 1 and rdlength == 4:
                answers.append(".".join(str(b) for b in rdata))
            elif rtype == 5:
                answers.append("<CNAME>")
    except (struct.error, IndexError):
        return {"ok": False, "error": "响应解析失败", "answers": [], "rcode": rcode}
    return {
        "ok": rcode in (0, 3),  # 3 = NXDOMAIN，服务器本身健康
        "error": None if rcode in (0, 3) else f"rcode={rcode}",
        "answers": answers,
        "rcode": rcode,
    }


def probe_dns(server: str, domain: str, timeout: float = 2.0) -> Dict[str, Any]:
    """向指定 DNS 服务器发一次查询并测量延迟。"""
    host, port = _split_host_port(server, 53)
    item: Dict[str, Any] = {
        "server": str(server),
        "ok": False,
        "latency_ms": None,
        "answers": [],
        "error": None,
    }
    if not host:
        item["error"] = "服务器地址为空"
        return item
    txid, packet = _build_dns_query(domain)
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(max(0.5, float(timeout)))
            sock.sendto(packet, (host, port))
            data, _addr = sock.recvfrom(2048)
    except socket.timeout:
        item["error"] = "超时"
        return item
    except OSError as err:
        item["error"] = f"{type(err).__name__}: {err}"
        return item
    item["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
    parsed = _parse_dns_response(data, txid)
    item["ok"] = bool(parsed.get("ok"))
    item["answers"] = parsed.get("answers") or []
    item["error"] = parsed.get("error")
    return item


# ---------------------------------------------------------------------------
# 插件主体
# ---------------------------------------------------------------------------


class OpenClashMonitor(_PluginBase):
    """监控 OpenClash 与 LocalDNS 的运行状态。"""

    plugin_name = "OpenClash 监控"
    plugin_desc = (
        "集中监控 OpenClash 的运行状态与规则模式、代理组与节点延迟、订阅剩余流量与到期时间、"
        "插件与内核版本更新，以及 LocalDNS 的查询统计、版本更新与上游 DNS 健康状态。"
    )
    plugin_icon = "Moviepilot_A.png"
    plugin_version = "0.2.1"
    plugin_author = "your-name"
    author_url = "https://github.com/your-name"
    plugin_config_prefix = "openclashmonitor_"
    plugin_label = "OpenClash,网络,DNS,监控"
    plugin_order = 30
    auth_level = 1

    # ---- 运行时配置（init_plugin 中按配置赋值） ----
    _enabled: bool = False
    _dashboard: bool = True
    _notify: bool = True
    _clash_url: str = ""
    _clash_secret: str = ""
    _luci_url: str = ""
    _luci_username: str = ""
    _luci_password: str = ""
    _luci_cookie: str = ""
    _dns_mode: str = "none"
    _ld_url: str = ""
    _ld_github: bool = True
    _ag_url: str = ""
    _ag_username: str = ""
    _ag_password: str = ""
    _ag_test_upstream: bool = True
    _dns_probe_targets: str = ""
    _dns_probe_domain: str = "www.google.com"
    _interval: int = 10
    _node_limit: int = 15
    _querylog_limit: int = 20
    _timeout: float = 8.0

    _refreshing: bool = False

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def init_plugin(self, config: Optional[Dict[str, Any]] = None) -> None:
        """按配置初始化运行状态，并安排一次立即采集。"""
        self.stop_service()
        self._refreshing = False
        self.__cookie_jar().clear()

        merged = dict(DEFAULT_CONFIG)
        if isinstance(config, dict):
            merged.update({k: v for k, v in config.items() if k in DEFAULT_CONFIG})
        onlyonce = bool(merged.get("onlyonce"))

        self._enabled = bool(merged.get("enabled"))
        self._dashboard = bool(merged.get("dashboard", True))
        self._notify = bool(merged.get("notify", True))
        self._clash_url = _normalize_url(str(merged.get("clash_url") or ""))
        self._clash_secret = str(merged.get("clash_secret") or "").strip()
        self._luci_url = _normalize_url(str(merged.get("luci_url") or ""))
        self._luci_username = str(merged.get("luci_username") or "").strip()
        self._luci_password = str(merged.get("luci_password") or "")
        self._luci_cookie = str(merged.get("luci_cookie") or "").strip()
        self._dns_mode = str(merged.get("dns_mode") or "none").strip().lower()
        self._ld_url = _normalize_url(str(merged.get("ld_url") or ""))
        self._ld_github = bool(merged.get("ld_github", True))
        self._ag_url = _normalize_url(str(merged.get("ag_url") or ""))
        self._ag_username = str(merged.get("ag_username") or "").strip()
        self._ag_password = str(merged.get("ag_password") or "")
        self._ag_test_upstream = bool(merged.get("ag_test_upstream", True))
        self._dns_probe_targets = str(merged.get("dns_probe_targets") or "").strip()
        self._dns_probe_domain = str(merged.get("dns_probe_domain") or "").strip() or "www.google.com"
        self._interval = max(1, min(_safe_int(merged.get("interval"), 10), 1440))
        self._node_limit = max(1, min(_safe_int(merged.get("node_limit"), 15), 200))
        self._querylog_limit = max(0, min(_safe_int(merged.get("querylog_limit"), 20), 200))
        self._timeout = float(max(3, min(_safe_int(merged.get("timeout"), 8), 60)))

        if not self._enabled:
            return

        # 配置里的「立即运行一次」只在保存时生效一次
        if onlyonce:
            merged["onlyonce"] = False
            try:
                self.update_config(merged)
            except Exception as err:  # noqa: BLE001
                logger.warning(f"OpenClash 监控：回写 onlyonce 失败 {err}")
        self.__schedule_once()

    def get_state(self) -> bool:
        """返回插件是否启用。"""
        return bool(self._enabled)

    def stop_service(self) -> None:
        """撤销一次性任务，释放进程内缓存。"""
        try:
            from app.sdk.scheduler import remove_plugin_once_job

            remove_plugin_once_job(self.__class__.__name__, f"{self.__class__.__name__}Once")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.__cookie_jar().clear()
        except Exception:  # noqa: BLE001
            pass

    def get_service(self) -> List[Dict[str, Any]]:
        """注册周期采集服务。"""
        if not self._enabled:
            return []
        return [
            {
                "id": f"{self.__class__.__name__}.Refresh",
                "name": "OpenClash 监控定时采集",
                "trigger": "interval",
                "func": self.refresh,
                "kwargs": {"minutes": self._interval},
            }
        ]

    # ------------------------------------------------------------------
    # 远程命令
    # ------------------------------------------------------------------

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """注册 ``/openclash`` 远程命令。"""
        if EventType is None:
            return []
        return [
            {
                "cmd": "/openclash",
                "event": EventType.PluginAction,
                "desc": "OpenClash 监控：输出当前状态摘要",
                "category": "插件命令",
                "data": {"action": "openclashmonitor_summary"},
            }
        ]

    def run_command(self, event: Any) -> None:
        """响应 ``/openclash`` 命令。"""
        data = getattr(event, "event_data", None)
        if not isinstance(data, dict) or data.get("action") != "openclashmonitor_summary":
            return
        snap = self.__cached()
        if not snap:
            self.post_message(title="OpenClash 监控", text="暂无数据，请先在插件页面等待一次采集完成。")
            return
        self.post_message(title="OpenClash 监控", text=self.__summary_text(snap))

    if eventmanager is not None and EventType is not None:
        run_command = eventmanager.register(EventType.PluginAction)(run_command)

    # ------------------------------------------------------------------
    # 动态 API
    # ------------------------------------------------------------------

    def get_api(self) -> List[Dict[str, Any]]:
        """注册监控数据查询接口。"""
        return [
            {
                "path": "/snapshot",
                "endpoint": self.api_snapshot,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取最近一次采集的完整快照",
            },
            {
                "path": "/refresh",
                "endpoint": self.api_refresh,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "立即采集一次并返回快照",
            },
            {
                "path": "/nodes",
                "endpoint": self.api_nodes,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取代理组与节点延迟",
            },
            {
                "path": "/subscriptions",
                "endpoint": self.api_subscriptions,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取订阅剩余流量与到期信息",
            },
            {
                "path": "/versions",
                "endpoint": self.api_versions,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取版本与更新状态",
            },
            {
                "path": "/dns",
                "endpoint": self.api_dns,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "获取 LocalDNS 状态、上游健康与查询日志",
            },
            {
                "path": "/probe",
                "endpoint": self.api_probe,
                "methods": ["GET"],
                "auth": "bear",
                "summary": "立即探测上游 DNS 健康状态",
            },
        ]

    def api_snapshot(self) -> Dict[str, Any]:
        """返回最近一次快照。"""
        return self.__cached() or {"timestamp": _now_text(), "errors": ["尚未完成首次采集"]}

    def api_refresh(self) -> Dict[str, Any]:
        """立即采集并返回结果。"""
        return self.refresh() or {}

    def api_nodes(self) -> Dict[str, Any]:
        """返回节点视图。"""
        return (self.__cached() or {}).get("nodes") or {}

    def api_subscriptions(self) -> Dict[str, Any]:
        """返回订阅视图。"""
        return (self.__cached() or {}).get("subscription") or {}

    def api_versions(self) -> Dict[str, Any]:
        """返回版本视图。"""
        return (self.__cached() or {}).get("versions") or {}

    def api_dns(self) -> Dict[str, Any]:
        """返回 DNS 视图。"""
        return (self.__cached() or {}).get("dns") or {}

    def api_probe(self) -> Dict[str, Any]:
        """重新探测上游 DNS。"""
        return {"timestamp": _now_text(), "probe": self.__collect_probe()}

    # ------------------------------------------------------------------
    # 配置表单
    # ------------------------------------------------------------------

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """返回配置表单与默认配置。"""
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(3, {"component": "VSwitch",
                                                "props": {"model": "enabled", "label": "启用插件"}}),
                            self.__form_col(3, {"component": "VSwitch",
                                                "props": {"model": "dashboard", "label": "显示首页仪表板"}}),
                            self.__form_col(3, {"component": "VSwitch",
                                                "props": {"model": "notify",
                                                          "label": "版本更新时通知"}}),
                            self.__form_col(3, {"component": "VSwitch",
                                                "props": {"model": "onlyonce", "label": "保存后立即运行一次"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "clash_url", "label": "Clash API 地址",
                                                          "placeholder": "http://192.168.1.1:9090",
                                                          "hint": "Mihomo 外部控制器地址；留空时尝试用 LuCI 返回的端口自动推断",
                                                          "persistentHint": True}}),
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "clash_secret", "label": "Clash API 密钥",
                                                          "placeholder": "external-controller 的 secret，可留空",
                                                          "type": "password", "persistentHint": True,
                                                          "hint": "留空时尝试使用 LuCI 返回的 dashboard 密钥"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "luci_url", "label": "OpenWrt 路由器地址",
                                                          "placeholder": "http://192.168.1.1",
                                                          "hint": "用于订阅流量与版本更新；无 LuCI 访问时留空，仅用 Clash API",
                                                          "persistentHint": True}}),
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "luci_cookie", "label": "LuCI Cookie（可选）",
                                                          "placeholder": "sysauth_http=xxxxx",
                                                          "hint": "已在浏览器登录路由器时可粘贴 Cookie，优先级高于账号密码",
                                                          "persistentHint": True}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "luci_username", "label": "LuCI 用户名",
                                                          "placeholder": "root"}}),
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "luci_password", "label": "LuCI 密码",
                                                          "type": "password"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(4, {"component": "VSelect",
                                                "props": {"model": "dns_mode", "label": "LocalDNS 类型",
                                                          "items": _DNS_MODE_OPTIONS,
                                                          "hint": "按路由器上实际运行的 DNS 程序选择",
                                                          "persistentHint": True}}),
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "ld_url", "label": "LocalDNS 地址",
                                                          "placeholder": "http://192.168.1.1:19099",
                                                          "persistentHint": True,
                                                          "hint": "LocalDNS 的 API 端口（默认 19099）"}}),
                            self.__form_col(2, {"component": "VSwitch",
                                                "props": {"model": "ld_github",
                                                          "label": "查 GitHub 版本"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(4, {"component": "VTextField",
                                                "props": {"model": "ag_url", "label": "AdGuard Home 地址",
                                                          "placeholder": "http://192.168.1.1:3000"}}),
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "ag_username", "label": "AdGuard 用户名",
                                                          "placeholder": "admin"}}),
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "ag_password", "label": "AdGuard 密码",
                                                          "type": "password"}}),
                            self.__form_col(2, {"component": "VSwitch",
                                                "props": {"model": "ag_test_upstream",
                                                          "label": "上游测速"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "dns_probe_targets",
                                                          "label": "上游 DNS 探测列表",
                                                          "placeholder": "223.5.5.5,119.29.29.29,1.1.1.1",
                                                          "hint": "逗号分隔，支持 host:port；留空则不探测",
                                                          "persistentHint": True}}),
                            self.__form_col(6, {"component": "VTextField",
                                                "props": {"model": "dns_probe_domain",
                                                          "label": "探测使用的域名",
                                                          "placeholder": "www.google.com"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "interval", "label": "采集间隔(分钟)",
                                                          "placeholder": "10"}}),
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "node_limit", "label": "页面展示节点数",
                                                          "placeholder": "15"}}),
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "querylog_limit", "label": "查询日志条数",
                                                          "placeholder": "20"}}),
                            self.__form_col(3, {"component": "VTextField",
                                                "props": {"model": "timeout", "label": "请求超时(秒)",
                                                          "placeholder": "8"}}),
                        ],
                    },
                ],
            }
        ], dict(DEFAULT_CONFIG)

    @staticmethod
    def __form_col(width: int, item: Dict[str, Any]) -> Dict[str, Any]:
        """把表单项包进 VCol。"""
        return {"component": "VCol", "props": {"cols": 12, "md": width}, "content": [item]}

    # ------------------------------------------------------------------
    # 采集主流程
    # ------------------------------------------------------------------

    def refresh(self) -> Optional[Dict[str, Any]]:
        """采集一次并写入插件数据，返回快照。"""
        if self._refreshing:
            return self.__cached()
        self._refreshing = True
        try:
            snapshot = self.__collect()
        except Exception as err:  # noqa: BLE001
            logger.error(f"OpenClash 监控：采集失败 {type(err).__name__}: {err}")
            previous = self.__cached()
            snapshot = dict(previous) if previous else {"clash": {}, "nodes": {}, "subscription": {},
                                                        "versions": {}, "dns": {}, "probe": []}
            snapshot["last_error"] = f"{type(err).__name__}: {err}"
        finally:
            self._refreshing = False

        snapshot["timestamp"] = _now_text()
        try:
            self.save_data(_SNAPSHOT_KEY, snapshot)
        except Exception as err:  # noqa: BLE001
            logger.error(f"OpenClash 监控：保存快照失败 {err}")
        try:
            self.__notify(snapshot)
        except Exception as err:  # noqa: BLE001
            logger.warning(f"OpenClash 监控：发送通知失败 {err}")
        return snapshot

    def __collect(self) -> Dict[str, Any]:
        """逐项采集，单项失败只记录错误。"""
        errors: List[str] = []

        # 1) LuCI：状态决定 Clash API 的兜底地址
        luci_status, err = self.__luci_get("status")
        if err:
            errors.append(f"LuCI 状态：{err}")

        clash_base, clash_secret = self.__resolve_clash(luci_status)

        # 2) Clash / Mihomo
        version_doc, err = self.__clash_get(clash_base, clash_secret, "/version")
        if err:
            errors.append(f"Clash 版本：{err}")
        configs_doc, configs_err = self.__clash_get(clash_base, clash_secret, "/configs")
        if configs_err:
            errors.append(f"Clash 配置：{configs_err}")
        proxies_doc, proxies_err = self.__clash_get(clash_base, clash_secret, "/proxies")
        if proxies_err:
            errors.append(f"代理节点：{proxies_err}")
        providers_doc, _providers_err = self.__clash_get(clash_base, clash_secret, "/providers/proxies")
        connections_doc, _conn_err = self.__clash_get(clash_base, clash_secret, "/connections")

        # 3) LuCI：工具栏（内存/CPU/连接数/流量）与版本
        toolbar_doc, toolbar_err = self.__luci_get("toolbar_show")
        if toolbar_err and not err:
            errors.append(f"LuCI 资源：{toolbar_err}")
        cpu_percent = None
        if isinstance(toolbar_doc, dict):
            cpu_percent = self.__toolbar_cpu(toolbar_doc)
            if cpu_percent is None and _safe_int(toolbar_doc.get("cpu_ticks"), 0) > 0:
                cpu_percent = self.__sample_cpu(toolbar_doc)

        update_doc, update_err = self.__luci_get("update")
        if update_err and not err:
            errors.append(f"版本信息：{update_err}")
        last_version_doc, _lv_err = self.__luci_get("last_version")

        config_doc, _config_err = self.__luci_get("config_name")
        current_config = self.__current_config_name(config_doc)
        sub_doc = None
        if current_config:
            # sub_info_get 会现场去拉订阅链接，明显慢于其他接口，单独放宽超时
            sub_doc, sub_err = self.__luci_get(
                "sub_info_get", {"filename": current_config},
                timeout=max(float(self._timeout or 8) * 3.0, 20.0),
            )
            if sub_err:
                errors.append(f"订阅信息：{sub_err}")

        # 4) DNS
        dns_view, dns_errors = self.__collect_dns(
            configs_doc,
            str((luci_status or {}).get("run_mode") or "") if isinstance(luci_status, dict) else "",
        )
        errors.extend(dns_errors)
        probe = self.__collect_probe()

        snapshot: Dict[str, Any] = {
            "timestamp": _now_text(),
            "clash": self.__build_clash(
                luci_status=luci_status,
                configs_doc=configs_doc,
                toolbar_doc=toolbar_doc,
                version_doc=version_doc,
                connections_doc=connections_doc,
                cpu_percent=cpu_percent,
                clash_base=clash_base,
            ),
            "nodes": self.__build_nodes(proxies_doc, providers_doc),
            "subscription": self.__build_subscription(sub_doc, config_doc, providers_doc),
            "versions": self.__build_versions(update_doc, last_version_doc, version_doc, dns_view),
            "dns": dns_view,
            "probe": probe,
            "errors": errors,
        }
        return snapshot

    # ------------------------------------------------------------------
    # 采集：Clash / Mihomo
    # ------------------------------------------------------------------

    def __resolve_clash(self, luci_status: Any) -> Tuple[str, str]:
        """确定 Clash API 地址与密钥，缺省时用 LuCI 状态推断。"""
        base, secret = self._clash_url, self._clash_secret
        if isinstance(luci_status, dict):
            if not base:
                host = str(luci_status.get("daip") or "").strip()
                port = _safe_int(luci_status.get("cn_port"), 0)
                if host:
                    base = _normalize_url(f"{host}:{port or 9090}")
            if not secret:
                secret = str(luci_status.get("dase") or "").strip()
        return base, secret

    def __clash_get(self, base: str, secret: str, path: str,
                    params: Optional[Dict[str, Any]] = None,
                    timeout: Optional[float] = None) -> Tuple[Any, Optional[str]]:
        """请求 Clash API，返回 (数据, 错误)。"""
        if not base:
            return None, "未配置 Clash API 地址"
        headers = {"Accept": "application/json"}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        result = http_request(
            "GET",
            base + path,
            headers=headers,
            params=params,
            timeout=timeout or self._timeout,
        )
        if result["error"] and result["status"] is None:
            return None, str(result["error"])
        if result["status"] == 401:
            return None, "密钥无效（HTTP 401）"
        if result["status"] != 200:
            return None, f"HTTP {result['status']}"
        return result["data"], None

    @staticmethod
    def __toolbar_cpu(toolbar: Dict[str, Any]) -> Optional[float]:
        """OpenClash v0.46+ 的 toolbar_show 直接返回 0~1 的 CPU 占比。"""
        raw = toolbar.get("cpu")
        if raw in (None, ""):
            return None
        value = _safe_float(raw, -1.0)
        if value < 0:
            return None
        # 少数固件直接给百分数，>1.2 时按百分比理解
        percent = value if value > 1.2 else value * 100.0
        return round(min(percent, 100.0), 1)

    def __sample_cpu(self, first: Dict[str, Any]) -> Optional[float]:
        """两次采样 cpu_ticks，估算 OpenClash 进程 CPU 占用。"""
        ticks1 = _safe_int(first.get("cpu_ticks"), 0)
        count = max(1, _safe_int(first.get("cpu_count"), 1))
        if ticks1 <= 0:
            return None
        started = time.monotonic()
        time.sleep(0.4)
        second, err = self.__luci_get("toolbar_show")
        if err or not isinstance(second, dict):
            return None
        ticks2 = _safe_int(second.get("cpu_ticks"), 0)
        elapsed = max(0.1, time.monotonic() - started)
        if ticks2 < ticks1:
            return None
        hz = 100.0
        try:
            import os as _os

            hz = float(_os.sysconf("SC_CLK_TCK"))
        except Exception:  # noqa: BLE001
            hz = 100.0
        percent = (ticks2 - ticks1) / (hz * elapsed) * 100.0 / count
        return round(min(percent, 100.0 * count), 1)

    def __build_clash(self, *, luci_status: Any, configs_doc: Any, toolbar_doc: Any,
                      version_doc: Any, connections_doc: Any, cpu_percent: Optional[float],
                      clash_base: str) -> Dict[str, Any]:
        """整理 OpenClash 运行状态。"""
        status = luci_status if isinstance(luci_status, dict) else {}
        configs = configs_doc if isinstance(configs_doc, dict) else {}
        toolbar = toolbar_doc if isinstance(toolbar_doc, dict) else {}
        dns_cfg = configs.get("dns") if isinstance(configs.get("dns"), dict) else {}
        tun_cfg = configs.get("tun") if isinstance(configs.get("tun"), dict) else {}

        connections = _safe_int(toolbar.get("connections"), 0)
        if not connections and isinstance(connections_doc, dict):
            items = connections_doc.get("connections")
            if isinstance(items, list):
                connections = len(items)

        return {
            "enabled": bool(_safe_int(status.get("clash"), 1)) if status else True,
            "run_mode": str(status.get("run_mode") or ""),
            "rule_mode": str(status.get("rule_mode") or configs.get("mode") or ""),
            "core_type": str(status.get("core_type") or ""),
            "core_version": str((version_doc or {}).get("version") or "") if isinstance(version_doc, dict) else "",
            "meta": bool((version_doc or {}).get("meta")) if isinstance(version_doc, dict) else None,
            "api_url": clash_base,
            "dns_mode": str(dns_cfg.get("enhanced-mode") or dns_cfg.get("enhanced_mode") or "")
            or _dns_mode_from_run_mode(str(status.get("run_mode") or "")),
            "dns_upstreams": [str(x) for x in (dns_cfg.get("nameserver") or []) if x] if isinstance(
                dns_cfg.get("nameserver"), list) else [],
            "fakeip_range": str(dns_cfg.get("fake-ip-range") or dns_cfg.get("fake_ip_range") or ""),
            "tun": bool(tun_cfg.get("enable")) if tun_cfg else None,
            "sniffer": (bool(configs.get("sniffer", {}).get("enable"))
                        if isinstance(configs.get("sniffer"), dict)
                        else (str(status.get("meta_sniffer") or "") == "1" if status else None)),
            "log_level": str(configs.get("log-level") or ""),
            "connections": connections,
            "up_total": _safe_int(toolbar.get("up_total"), 0),
            "down_total": _safe_int(toolbar.get("down_total"), 0),
            "mem": _safe_int(toolbar.get("mem"), 0),
            "load_avg": str(toolbar.get("load_avg") or ""),
            "cpu_percent": cpu_percent,
        }

    def __build_nodes(self, proxies_doc: Any, providers_doc: Any = None) -> Dict[str, Any]:
        """整理代理组与节点延迟。

        OpenClash 用 proxy-provider 拉订阅时，具体节点**不会**出现在 ``/proxies``
        里，只在 ``/providers/proxies`` 的 ``proxies`` 数组内，所以这里把两侧合并成
        一个节点池再做判定，否则节点数会恒为 0。
        """
        proxies = proxies_doc.get("proxies") if isinstance(proxies_doc, dict) else None
        if not isinstance(proxies, dict) or not proxies:
            return {"groups": [], "nodes": [], "total": 0, "alive": 0,
                    "tested": 0, "avg_delay": None, "sources": []}

        pool: Dict[str, Dict[str, Any]] = {}
        sources: List[str] = []
        providers = providers_doc.get("providers") if isinstance(providers_doc, dict) else None
        if isinstance(providers, dict):
            for provider_name, info in providers.items():
                if not isinstance(info, dict):
                    continue
                nodes_raw = info.get("proxies")
                if not isinstance(nodes_raw, list):
                    continue
                added = 0
                for node in nodes_raw:
                    if not isinstance(node, dict):
                        continue
                    node_name = str(node.get("name") or "").strip()
                    if not node_name or node_name in pool:
                        continue
                    item = dict(node)
                    item.setdefault("provider", str(provider_name))
                    pool[node_name] = item
                    added += 1
                if added:
                    sources.append(f"{provider_name}({added})")

        groups: List[Dict[str, Any]] = []
        node_names: List[str] = []
        seen: set = set()

        def lookup(name: Any) -> Optional[Dict[str, Any]]:
            """在 /proxies 与 provider 池里查找条目。"""
            if not isinstance(name, str):
                return None
            info = proxies.get(name)
            if isinstance(info, dict):
                return info
            item = pool.get(name)
            return item if isinstance(item, dict) else None

        def is_real_node(name: Any) -> bool:
            if not isinstance(name, str) or not name.strip():
                return False
            if name.upper() in _BUILTIN_PROXIES:
                return False
            info = lookup(name)
            if not isinstance(info, dict):
                return False
            if isinstance(info.get("all"), list):
                return False
            kind = str(info.get("type") or "").strip().lower()
            if kind in _BUILTIN_PROXY_TYPES:
                return False
            return True

        for name, item in proxies.items():
            if not isinstance(item, dict):
                continue
            members = item.get("all")
            if not isinstance(members, list):
                continue
            # 组内真实节点：排除内置代理（DIRECT/REJECT…）与嵌套策略组
            member_names: List[str] = []
            for member in members:
                if not is_real_node(member):
                    continue
                member_names.append(member)
                if member not in seen:
                    seen.add(member)
                    node_names.append(member)
            groups.append({
                "name": str(name),
                "type": str(item.get("type") or ""),
                "now": str(item.get("now") or ""),
                "count": len(member_names),
                "alive": sum(1 for m in member_names
                             if self.__node_state(lookup(m) or {})[1] in ("ok", "idle")),
                "members": member_names[:400],
            })

        nodes: List[Dict[str, Any]] = []
        for name in node_names:
            info = lookup(name) or {}
            delay, state = self.__node_state(info)
            nodes.append({
                "name": name,
                "type": str(info.get("type") or ""),
                "provider": str(info.get("provider") or ""),
                "delay": delay,
                "state": state,
            })
        nodes.sort(key=lambda n: (n["state"] not in ("ok", "idle"), n["delay"] or 10 ** 9))
        alive = sum(1 for n in nodes if n["state"] in ("ok", "idle"))
        tested = sum(1 for n in nodes if n["state"] in ("ok", "timeout"))
        delays = [n["delay"] for n in nodes if n["state"] == "ok" and n["delay"]]
        return {
            "groups": groups,
            "nodes": nodes,
            "total": len(nodes),
            "alive": alive,
            "tested": tested,
            "avg_delay": round(sum(delays) / len(delays)) if delays else None,
            "sources": sources,
        }

    @staticmethod
    def __node_state(info: Any) -> Tuple[int, str]:
        """返回 (延迟毫秒, 状态)。

        状态取值：``ok`` 已测速可用、``timeout`` 测速超时、``idle`` 可用但未测速、
        ``down`` 不可用、``unknown`` 内核未给出任何信息。
        """
        if not isinstance(info, dict):
            return 0, "unknown"
        history = info.get("history")
        if isinstance(history, list) and history:
            last = history[-1] if isinstance(history[-1], dict) else {}
            delay = _safe_int(last.get("delay"), 0)
            return delay, ("ok" if delay > 0 else "timeout")
        alive = info.get("alive")
        if isinstance(alive, bool):
            return 0, ("idle" if alive else "down")
        return 0, "unknown"

    def __build_subscription(self, sub_doc: Any, config_doc: Any, providers_doc: Any) -> Dict[str, Any]:
        """整理订阅流量、到期与 provider 更新时间。"""
        items: List[Dict[str, Any]] = []
        providers_raw = sub_doc.get("providers") if isinstance(sub_doc, dict) else None
        if isinstance(providers_raw, dict):
            for name, info in providers_raw.items():
                items.append(self.__sub_item(str(name), info if isinstance(info, dict) else {}))
        elif isinstance(providers_raw, list):
            for entry in providers_raw:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("provider_name") or entry.get("name")
                           or entry.get("filename") or "")
                items.append(self.__sub_item(name, entry))

        update_times: List[Dict[str, Any]] = []
        providers = providers_doc.get("providers") if isinstance(providers_doc, dict) else None
        if isinstance(providers, dict):
            for name, info in providers.items():
                if not isinstance(info, dict):
                    continue
                vehicle = str(info.get("vehicleType") or info.get("vehicle_type") or "")
                # Compatible 是配置内联的 provider，updatedAt 恒为 0001-01-01，没有意义
                if vehicle.strip().lower() == "compatible":
                    continue
                update_times.append({
                    "name": str(name),
                    "vehicle_type": vehicle,
                    "updated_at": str(info.get("updatedAt") or info.get("updated_at") or ""),
                })

        return {
            "current": self.__current_config_name(config_doc),
            "configs": self.__config_list(config_doc),
            "items": items,
            "providers": update_times,
        }

    @staticmethod
    def __config_list(config_doc: Any) -> List[str]:
        """取出 LuCI 返回的配置文件列表（元素可能是 str 或 {"name": ...}）。"""
        if not isinstance(config_doc, dict):
            return []
        raw = config_doc.get("config_name")
        if not isinstance(raw, list):
            for key in ("configs", "list", "all", "files"):
                value = config_doc.get(key)
                if isinstance(value, list):
                    raw = value
                    break
        if not isinstance(raw, list):
            return []
        names: List[str] = []
        for entry in raw:
            if isinstance(entry, str):
                names.append(entry)
            elif isinstance(entry, dict):
                name = entry.get("name") or entry.get("filename") or entry.get("config")
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        return names

    @staticmethod
    def __current_config_name(config_doc: Any) -> str:
        """从 LuCI 的 config_name 响应里取出当前配置文件名。

        实测 OpenClash v0.48 返回
        ``{"config_name": [{"name": "x.yaml"}], "config_path": "x.yaml"}``。
        """
        if not isinstance(config_doc, dict):
            return ""
        for key in ("config_path", "current", "filename", "config_file", "now", "config"):
            value = config_doc.get(key)
            if isinstance(value, str) and value.strip() and value.strip().lower() != "null":
                return value.strip()
        return ""

    @staticmethod
    def __sub_item(name: str, info: Dict[str, Any]) -> Dict[str, Any]:
        """整理单条订阅信息（字段取自 OpenClash /sub_info_get 的实测结构）。"""

        def _text(value: Any) -> str:
            if value is None:
                return ""
            text = str(value).strip()
            return "" if text.lower() in ("", "null", "none") else text

        item_name = _text(info.get("provider_name")) or _text(info.get("name")) or name
        surplus_raw = _text(info.get("surplus"))
        if not surplus_raw:
            surplus = "不支持查询"
        elif surplus_raw.lower() in ("inf", "infinity", "∞", "-1"):
            surplus = "不限额"
        else:
            surplus = surplus_raw

        expire_text = _text(info.get("expire"))
        days_raw = _text(info.get("day_left"))
        if days_raw.lower() in ("∞", "inf", "infinity"):
            days = "长期有效"
        elif days_raw:
            days_value = _safe_int(days_raw, -1)
            if days_value > 0:
                days = f"{days_value} 天"
            elif days_value == 0:
                days = "已过期"
            else:
                days = "未知"
        else:
            days = "未知"
        if days == "未知" and expire_text:
            days = expire_text[:10]

        percent = _safe_float(info.get("percent"), -1)
        return {
            "name": item_name,
            "http_code": _safe_int(info.get("http_code"), 0),
            "surplus": surplus,
            "total": _text(info.get("total")) or "-",
            "used": _text(info.get("used")) or "-",
            "days": days,
            "expire": expire_text or "-",
            "percent": round(percent, 2) if percent >= 0 else None,
        }

    def __build_versions(self, update_doc: Any, last_version_doc: Any,
                         version_doc: Any, dns_view: Dict[str, Any]) -> Dict[str, Any]:
        """整理版本与更新状态。"""
        update = update_doc if isinstance(update_doc, dict) else {}
        latest = last_version_doc if isinstance(last_version_doc, dict) else {}

        plugin_current = _clean_loading(update.get("opcv"))
        core_current = _clean_loading(update.get("coremetacv"))
        if not core_current and isinstance(version_doc, dict):
            core_current = _clean_loading(version_doc.get("version"))
        plugin_latest = _clean_loading(latest.get("oplv"))
        core_latest = _clean_loading(latest.get("corelv"))

        dns_current = str(dns_view.get("version") or "")
        dns_latest = str(dns_view.get("latest_version") or "")

        def _differs(latest_text: str, current_text: str) -> bool:
            """有数字版本号时按版本比较，否则退化成字符串比对。"""
            if not latest_text or not current_text:
                return False
            if _version_tuple(latest_text) and _version_tuple(current_text):
                return _is_newer(latest_text, current_text)
            return latest_text.strip() != current_text.strip()

        return {
            "plugin_current": plugin_current,
            "plugin_latest": plugin_latest,
            # 内核版本形如 alpha-gbc76c13，没有数字段可比，只能字符串比对
            "plugin_update": _differs(plugin_latest, plugin_current),
            "core_current": core_current,
            "core_latest": core_latest,
            "core_update": _differs(core_latest, core_current),
            "dns_current": dns_current,
            "dns_latest": dns_latest,
            "dns_update": bool(dns_view.get("update_available")) or _differs(dns_latest, dns_current),
            "release_branch": str(update.get("release_branch") or ""),
            "core_type_choice": str(update.get("corever") or ""),
        }

    # ------------------------------------------------------------------
    # 采集：LocalDNS
    # ------------------------------------------------------------------

    def __collect_dns(self, configs_doc: Any, run_mode: str = "") -> Tuple[Dict[str, Any], List[str]]:
        """采集 LocalDNS 视图。"""
        errors: List[str] = []
        view: Dict[str, Any] = {
            "provider": self._dns_mode,
            "ok": False,
            "version": "",
            "latest_version": "",
            "queries": None,
            "blocked": None,
            "blocked_percent": None,
            "avg_ms": None,
            "upstream_mode": "",
            "upstreams": [],
            "upstream_health": [],
            "top_domains": [],
            "top_clients": [],
            "querylog": [],
            "clash": {},
            "error": None,
        }

        # Clash 内置 DNS 信息作为兜底/补充，任何模式都有价值
        if isinstance(configs_doc, dict):
            dns_cfg = configs_doc.get("dns") if isinstance(configs_doc.get("dns"), dict) else {}
            view["clash"] = {
                "mode": str(dns_cfg.get("enhanced-mode") or dns_cfg.get("enhanced_mode") or "")
                or _dns_mode_from_run_mode(run_mode),
                "nameserver": [str(x) for x in (dns_cfg.get("nameserver") or []) if x]
                if isinstance(dns_cfg.get("nameserver"), list) else [],
                "fallback": [str(x) for x in (dns_cfg.get("fallback") or []) if x]
                if isinstance(dns_cfg.get("fallback"), list) else [],
                "fakeip_range": str(dns_cfg.get("fake-ip-range") or dns_cfg.get("fake_ip_range") or ""),
                "hosts": bool(dns_cfg.get("use-hosts")),
            }

        if self._dns_mode == "localdns":
            return self.__collect_localdns(view, errors)

        if self._dns_mode != "adguard":
            return view, errors

        if not self._ag_url:
            view["error"] = "未配置 AdGuard Home 地址"
            errors.append("LocalDNS：未配置 AdGuard Home 地址")
            return view, errors

        status_doc, err = self.__agh_get("/control/status")
        if err:
            view["error"] = err
            errors.append(f"AdGuard 状态：{err}")
            return view, errors

        status = status_doc if isinstance(status_doc, dict) else {}
        view["ok"] = True
        view["version"] = str(status.get("version") or "")
        view["protection"] = bool(status.get("protection_enabled"))
        view["running"] = bool(status.get("running"))
        addresses = status.get("dns_addresses")
        view["dns_addresses"] = [str(x) for x in addresses] if isinstance(addresses, list) else []

        stats_doc, stats_err = self.__agh_get("/control/stats")
        if stats_err:
            errors.append(f"AdGuard 统计：{stats_err}")
        elif isinstance(stats_doc, dict):
            queries = _safe_int(stats_doc.get("num_dns_queries"), 0)
            blocked = _safe_int(stats_doc.get("num_blocked_filtering"), 0)
            view["queries"] = queries
            view["blocked"] = blocked
            if queries > 0:
                view["blocked_percent"] = round(blocked * 100.0 / queries, 2)
            avg = _safe_float(stats_doc.get("avg_processing_time"), -1)
            if avg >= 0:
                view["avg_ms"] = round(avg * 1000, 2)
            view["top_domains"] = self.__top_list(stats_doc.get("top_queried_domains"))
            view["top_clients"] = self.__top_list(stats_doc.get("top_clients"))

        dns_info_doc, dns_info_err = self.__agh_get("/control/dns_info")
        if dns_info_err:
            errors.append(f"AdGuard DNS 配置：{dns_info_err}")
        elif isinstance(dns_info_doc, dict):
            view["upstream_mode"] = str(dns_info_doc.get("upstream_mode") or "")
            view["upstreams"] = [str(x) for x in (dns_info_doc.get("upstream_dns") or []) if x] \
                if isinstance(dns_info_doc.get("upstream_dns"), list) else []
            view["bootstrap"] = [str(x) for x in (dns_info_doc.get("bootstrap_dns") or []) if x] \
                if isinstance(dns_info_doc.get("bootstrap_dns"), list) else []

        version_doc, _version_err = self.__agh_get("/control/version")
        if isinstance(version_doc, dict):
            view["latest_version"] = str(version_doc.get("new_version") or "")

        if self._ag_test_upstream and view["upstreams"]:
            health = self.__agh_test_upstream()
            if health:
                view["upstream_health"] = health

        if self._querylog_limit > 0:
            log_doc, log_err = self.__agh_get("/control/querylog", {"limit": self._querylog_limit})
            if log_err:
                errors.append(f"AdGuard 查询日志：{log_err}")
            elif isinstance(log_doc, dict):
                view["querylog"] = self.__querylog_items(log_doc.get("data"), self._querylog_limit)

        return view, errors

    def __collect_localdns(self, view: Dict[str, Any], errors: List[str]) -> Tuple[Dict[str, Any], List[str]]:
        """采集 LocalDNS（github.com/yyhoworks/LocalDNS）的状态、上游健康、查询日志与版本。"""
        view["provider"] = "localdns"
        if not self._ld_url:
            view["error"] = "未配置 LocalDNS 地址"
            errors.append("LocalDNS：未配置 LocalDNS 地址")
            return view, errors

        status_doc, err = self.__ld_get("/api/v1/status")
        if err:
            view["error"] = err
            errors.append(f"LocalDNS 状态：{err}")
            return view, errors
        status = status_doc if isinstance(status_doc, dict) else {}
        view["ok"] = True
        view["running"] = bool(status)
        view["core_version"] = str(status.get("version") or "")
        view["allocator"] = str(status.get("allocator") or "")
        view["listen"] = str(status.get("dns_listen") or "")
        view["api_listen"] = str(status.get("api_listen") or "")
        view["cache_entries"] = _safe_int(status.get("cache_entries"), 0)
        view["rewrite_rules"] = _safe_int(status.get("rewrite_rules"), 0)
        view["adguard_rules"] = _safe_int(status.get("adguard_rules"), 0)
        view["upstream_mode"] = ""

        features = status.get("features") if isinstance(status.get("features"), dict) else {}
        view["features"] = sorted(str(name) for name, on in features.items() if on)

        stats = status.get("stats") if isinstance(status.get("stats"), dict) else {}
        queries = _safe_int(stats.get("total"), 0)
        blocked = _safe_int(stats.get("blocked"), 0)
        view["queries"] = queries
        view["blocked"] = blocked
        view["cache_hits"] = _safe_int(stats.get("cache_hits"), 0)
        view["dns_errors"] = _safe_int(stats.get("errors"), 0)
        view["fakeip"] = _safe_int(stats.get("fakeip"), 0)
        view["domestic"] = _safe_int(stats.get("domestic"), 0)
        view["foreign"] = _safe_int(stats.get("foreign"), 0)
        if queries > 0:
            view["blocked_percent"] = round(blocked * 100.0 / queries, 2)

        # 上游健康：status.upstream_stats 已经带累计成功/失败/超时与延迟总和
        upstream_rows: List[Dict[str, Any]] = []
        latency_sum = 0.0
        latency_count = 0
        raw_upstreams = status.get("upstream_stats")
        if isinstance(raw_upstreams, list):
            for entry in raw_upstreams:
                if not isinstance(entry, dict):
                    continue
                reqs = _safe_int(entry.get("requests"), 0)
                accepted = _safe_int(entry.get("accepted"), 0)
                fails = _safe_int(entry.get("errors"), 0)
                timeouts = _safe_int(entry.get("timeouts"), 0)
                l_sum = _safe_float(entry.get("latency_ms_sum"), 0.0)
                l_cnt = _safe_int(entry.get("latency_count"), 0)
                latency_sum += l_sum
                latency_count += l_cnt
                avg = round(l_sum / l_cnt, 1) if l_cnt > 0 else None
                upstream_rows.append({
                    "server": str(entry.get("addr") or entry.get("tag") or ""),
                    "group": str(entry.get("group") or ""),
                    "protocol": str(entry.get("protocol") or ""),
                    "tag": str(entry.get("tag") or ""),
                    "requests": reqs,
                    "accepted": accepted,
                    "errors": fails,
                    "timeouts": timeouts,
                    "winners": _safe_int(entry.get("winners"), 0),
                    "latency_ms": avg,
                    "ok": bool(reqs > 0 and fails == 0 and timeouts == 0),
                    "error": str(entry.get("last_error") or ""),
                })
        if latency_count > 0:
            view["avg_ms"] = round(latency_sum / latency_count, 2)
        view["upstream_health"] = upstream_rows
        view["upstreams"] = [row["server"] for row in upstream_rows if row["server"]]

        # 上游分组（domestic / foreign / foreign_ecs / proxy）与启用数量
        config_doc, config_err = self.__ld_get("/api/v1/upstream/config")
        if config_err:
            errors.append(f"LocalDNS 上游配置：{config_err}")
        elif isinstance(config_doc, dict):
            groups: List[Dict[str, Any]] = []
            for group, entries in config_doc.items():
                if not isinstance(entries, list):
                    continue
                enabled = sum(1 for e in entries if isinstance(e, dict) and e.get("enabled") is not False)
                groups.append({"name": str(group), "count": len(entries), "enabled": enabled})
            view["upstream_groups"] = groups

        # 查询日志（同时用来算热门域名与最近拦截数）
        if self._querylog_limit > 0:
            log_limit = max(self._querylog_limit, 100)
            log_doc, log_err = self.__ld_get("/api/v1/querylog/entries",
                                             {"page": 1, "limit": log_limit})
            if log_err:
                errors.append(f"LocalDNS 查询日志：{log_err}")
            elif isinstance(log_doc, dict):
                raw_logs = log_doc.get("logs")
                view["querylog"] = self.__ld_querylog(raw_logs, self._querylog_limit)
                counters: Dict[str, int] = {}
                blocked_recent = 0
                if isinstance(raw_logs, list):
                    for entry in raw_logs:
                        if not isinstance(entry, dict):
                            continue
                        name = str(entry.get("query_name") or "")
                        if name:
                            counters[name] = counters.get(name, 0) + 1
                        if str(entry.get("domain_set") or "") in _BLOCKED_DOMAIN_SETS:
                            blocked_recent += 1
                view["blocked_recent"] = blocked_recent
                view["sampled"] = len(raw_logs) if isinstance(raw_logs, list) else 0
                top = sorted(counters.items(), key=lambda kv: kv[1], reverse=True)[:5]
                view["top_domains"] = [{"name": name, "count": count} for name, count in top]

        # /metrics：进程 CPU（两次采样）、内存、运行时长与 Rust 版本
        metrics = self.__ld_metrics()
        if metrics:
            view.update({k: v for k, v in metrics.items() if v is not None})

        # 版本：以 /ui/version.json 为准，再和 GitHub releases 对比
        ui_doc, _ui_err = self.__ld_get("/ui/version.json", timeout=max(self._timeout, 10))
        ui = ui_doc if isinstance(ui_doc, dict) else {}
        ui_version = str(ui.get("uiVersion") or "")
        if ui_version:
            view["version"] = ui_version
            view["ui_version"] = ui_version
        elif view.get("core_version"):
            view["version"] = str(view["core_version"])
        view["release_tag"] = str(ui.get("releaseTag") or "")
        view["channel"] = str(ui.get("channel") or "")
        view["built_at"] = str(ui.get("builtAt") or "")

        if self._ld_github:
            latest = self.__ld_github_latest()
            if latest:
                view["latest_version"] = str(latest.get("ui_version") or "")
                view["latest_tag"] = str(latest.get("tag") or "")
                view["latest_core"] = str(latest.get("core") or "")
                view["latest_published"] = str(latest.get("published_at") or "")
                current_ui = str(view.get("ui_version") or view.get("version") or "")
                if _is_newer(view["latest_version"], current_ui):
                    view["update_available"] = True
                local_core = str(view.get("core_version") or "").upper()
                remote_core = str(view.get("latest_core") or "").upper()
                if local_core and remote_core and local_core != remote_core:
                    view["core_channel_mismatch"] = True

        return view, errors

    def __ld_get(self, path: str, params: Optional[Dict[str, Any]] = None,
                 timeout: Optional[float] = None) -> Tuple[Any, Optional[str]]:
        """请求 LocalDNS API。"""
        if not self._ld_url:
            return None, "未配置 LocalDNS 地址"
        result = http_request(
            "GET",
            self._ld_url + path,
            headers={"Accept": "application/json"},
            params=params,
            timeout=timeout or self._timeout,
        )
        if result["error"] and result["status"] is None:
            return None, str(result["error"])
        if result["status"] == 401:
            return None, "认证失败（HTTP 401）"
        if result["status"] and result["status"] >= 400:
            return None, f"HTTP {result['status']}"
        return result["data"], None

    def __ld_metrics(self) -> Dict[str, Any]:
        """读 /metrics 估算 LocalDNS 进程 CPU、内存与运行时长。"""
        if not self._ld_url:
            return {}
        first = http_request("GET", self._ld_url + "/metrics", timeout=self._timeout)
        text_first = str(first.get("text") or "")
        if first["status"] != 200 or "process_cpu_seconds_total" not in text_first:
            return {}
        sample1 = self.__parse_metrics(text_first)
        started = time.monotonic()
        time.sleep(0.3)
        second = http_request("GET", self._ld_url + "/metrics", timeout=self._timeout)
        sample2 = self.__parse_metrics(str(second.get("text") or "")) if second["status"] == 200 else {}
        elapsed = max(0.1, time.monotonic() - started)

        result: Dict[str, Any] = {}
        cpu1 = _safe_float(sample1.get("cpu_seconds"), -1.0)
        cpu2 = _safe_float(sample2.get("cpu_seconds"), -1.0)
        if cpu1 >= 0 and cpu2 >= cpu1:
            result["cpu_percent"] = round(min((cpu2 - cpu1) / elapsed * 100.0, 100.0), 1)
        mem = _safe_int(sample1.get("resident_bytes"), 0)
        if mem > 0:
            result["mem_bytes"] = mem
        start_time = _safe_int(sample1.get("start_time"), 0)
        if start_time > 0:
            result["uptime_seconds"] = max(0, int(time.time() - start_time))
        if sample1.get("runtime"):
            result["runtime"] = sample1["runtime"]
        if sample1.get("metric_version"):
            result.setdefault("core_version", sample1["metric_version"])
        return result

    @staticmethod
    def __parse_metrics(text: str) -> Dict[str, Any]:
        """从 Prometheus 文本里挑出需要的几个指标。"""
        values: Dict[str, Any] = {}
        for line in str(text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, rest = line.partition(" ")
            value = rest.strip()
            if name == "process_cpu_seconds_total":
                values["cpu_seconds"] = _safe_float(value, 0.0)
            elif name == "process_resident_memory_bytes":
                values["resident_bytes"] = _safe_float(value, 0.0)
            elif name == "process_start_time_seconds":
                values["start_time"] = _safe_float(value, 0.0)
            elif name.startswith("localdns_runtime_info"):
                match = re.search(r'runtime="([^"]+)"', name)
                if match:
                    values["runtime"] = match.group(1)
            elif name.startswith("localdns_info"):
                match = re.search(r'version="([^"]+)"', name)
                if match:
                    values["metric_version"] = match.group(1)
        return values

    def __ld_github_latest(self) -> Optional[Dict[str, Any]]:
        """查 GitHub releases，拿到 LocalDNS 的最新版本。"""
        url = "https://api.github.com/repos/yyhoworks/LocalDNS/releases/latest"
        result = http_request(
            "GET", url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": _UA},
            timeout=max(self._timeout, 12),
        )
        doc = result.get("data") if result["status"] == 200 else None
        if not isinstance(doc, dict):
            return None
        tag = str(doc.get("tag_name") or "").strip()
        if not tag:
            return None
        core, ui_version = "", tag.lstrip("vV")
        match = re.match(r"^([a-z0-9]+)-ui-v(.+)$", tag, re.IGNORECASE)
        if match:
            core, ui_version = match.group(1), match.group(2)
        return {
            "tag": tag,
            "core": core,
            "ui_version": ui_version,
            "published_at": str(doc.get("published_at") or ""),
        }

    @staticmethod
    def __ld_querylog(raw: Any, limit: int) -> List[Dict[str, Any]]:
        """整理 LocalDNS 的查询日志条目。"""
        items: List[Dict[str, Any]] = []
        if not isinstance(raw, list):
            return items
        for entry in raw[: max(1, limit)]:
            if not isinstance(entry, dict):
                continue
            stamp = _safe_float(entry.get("query_time"), 0.0)
            if stamp > 1e12:  # 毫秒时间戳
                stamp = stamp / 1000.0
            time_text = ""
            if stamp > 0:
                time_text = datetime.fromtimestamp(stamp).strftime("%m-%d %H:%M:%S")
            domain_set = str(entry.get("domain_set") or "")
            answers = entry.get("answers") if isinstance(entry.get("answers"), list) else []
            first_answer = ""
            for answer in answers:
                if isinstance(answer, dict) and answer.get("data"):
                    first_answer = str(answer["data"])
                    break
            items.append({
                "time": time_text or "-",
                "domain": str(entry.get("query_name") or "-"),
                "type": str(entry.get("query_type") or "-"),
                "client": str(entry.get("client_ip") or "-"),
                "upstream": domain_set or "-",
                "elapsed": _safe_int(entry.get("duration_ms"), 0),
                "cached": bool(entry.get("cache")),
                "answer": first_answer,
                "result": str(entry.get("response_code") or "-"),
                "status": "拦截" if domain_set in _BLOCKED_DOMAIN_SETS else "放行",
            })
        return items

    def __agh_get(self, path: str, params: Optional[Dict[str, Any]] = None,
                  method: str = "GET", body: Any = None,
                  timeout: Optional[float] = None) -> Tuple[Any, Optional[str]]:
        """请求 AdGuard Home API。"""
        if not self._ag_url:
            return None, "未配置 AdGuard Home 地址"
        headers = {"Accept": "application/json"}
        if self._ag_username or self._ag_password:
            token = base64.b64encode(
                f"{self._ag_username}:{self._ag_password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
        result = http_request(
            method,
            self._ag_url + path,
            headers=headers,
            params=params,
            body=body if body is not None else ({} if method != "GET" else None),
            timeout=timeout or self._timeout,
        )
        if result["status"] == 401:
            return None, "认证失败（HTTP 401），请检查用户名与密码"
        if result["error"] and result["status"] is None:
            return None, str(result["error"])
        if result["status"] and result["status"] >= 400:
            return None, f"HTTP {result['status']}"
        return result["data"], None

    def __agh_test_upstream(self) -> List[Dict[str, Any]]:
        """调用 AdGuard 的上游测速接口。"""
        doc, err = self.__agh_get("/control/test_upstream_dns", method="POST", body={},
                                  timeout=max(self._timeout, 20))
        if err or not isinstance(doc, dict):
            return []
        raw = doc.get("upstreams")
        if not isinstance(raw, list):
            return []
        health: List[Dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            status_text = str(entry.get("status") or "").lower()
            ok = status_text in ("ok", "up", "healthy") or entry.get("ok") is True
            health.append({
                "server": str(entry.get("address") or entry.get("upstream") or entry.get("domain") or ""),
                "ok": ok,
                "latency_ms": entry.get("elapsed") or entry.get("latency") or entry.get("time"),
                "error": None if ok else (str(entry.get("status") or "失败")),
            })
        return health

    @staticmethod
    def __top_list(raw: Any, limit: int = 5) -> List[Dict[str, Any]]:
        """整理 top_xxx 统计数组。"""
        items: List[Dict[str, Any]] = []
        if not isinstance(raw, list):
            return items
        for entry in raw[:limit]:
            if isinstance(entry, dict):
                items.append({
                    "name": str(entry.get("domain") or entry.get("client") or entry.get("name") or ""),
                    "count": _safe_int(entry.get("count"), 0),
                })
        return items

    @staticmethod
    def __querylog_items(raw: Any, limit: int) -> List[Dict[str, Any]]:
        """整理查询日志。"""
        items: List[Dict[str, Any]] = []
        if not isinstance(raw, list):
            return items
        for entry in raw[:limit]:
            if not isinstance(entry, dict):
                continue
            question = entry.get("question") if isinstance(entry.get("question"), dict) else {}
            result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
            reason = str(entry.get("reason") or "")
            filtered = bool(result.get("is_filtered")) or reason.upper() in (
                "FILTERED_BLACK_LIST", "FILTERED_PARENTAL", "FILTERED_SAFE_BROWSING",
                "FILTERED_SAFE_SEARCH", "NOT_FILTERED_BLOCKED_SERVICE",
            )
            items.append({
                "time": str(entry.get("time") or ""),
                "domain": str(question.get("name") or ""),
                "type": str(question.get("type") or ""),
                "client": str(entry.get("client") or ""),
                "upstream": str(entry.get("upstream") or ""),
                "elapsed": str(entry.get("elapsedMs") or ""),
                "status": "拦截" if filtered else "放行",
            })
        return items

    def __collect_probe(self) -> List[Dict[str, Any]]:
        """对配置的上游 DNS 做一次 UDP 探测。"""
        targets = [t.strip() for t in re.split(r"[,;\s]+", self._dns_probe_targets or "") if t.strip()]
        if not targets:
            return []
        results: List[Dict[str, Any]] = []
        for target in targets[:12]:
            results.append(probe_dns(target, self._dns_probe_domain, timeout=2.0))
        return results

    # ------------------------------------------------------------------
    # 通知
    # ------------------------------------------------------------------

    def __notify(self, snapshot: Dict[str, Any]) -> None:
        """版本出现更新时推送一次通知。"""
        if not self._enabled or not self._notify:
            return
        versions = snapshot.get("versions") if isinstance(snapshot.get("versions"), dict) else {}
        updates: List[str] = []
        markers: Dict[str, str] = {}
        if versions.get("core_update"):
            updates.append(f"内核：{versions.get('core_current') or '?'} → {versions.get('core_latest')}")
            markers["core"] = str(versions.get("core_latest") or "")
        if versions.get("plugin_update"):
            updates.append(f"插件：{versions.get('plugin_current') or '?'} → {versions.get('plugin_latest')}")
            markers["plugin"] = str(versions.get("plugin_latest") or "")
        if versions.get("dns_update"):
            updates.append(f"LocalDNS：{versions.get('dns_current') or '?'} → {versions.get('dns_latest')}")
            markers["dns"] = str(versions.get("dns_latest") or "")
        if not updates:
            return

        notified = self.get_data(_NOTIFY_KEY)
        notified = notified if isinstance(notified, dict) else {}
        fresh = {key: value for key, value in markers.items() if notified.get(key) != value}
        if not fresh:
            return

        self.post_message(
            mtype=getattr(NotificationType, "Plugin", None) if NotificationType else None,
            title="OpenClash 有可用更新",
            text="检测到新版本：\n" + "\n".join(updates),
        )
        notified.update(fresh)
        self.save_data(_NOTIFY_KEY, notified)

    # ------------------------------------------------------------------
    # 页面
    # ------------------------------------------------------------------

    def get_page(self) -> Optional[List[dict]]:
        """返回插件详情页。"""
        if not self._enabled:
            return [{"component": "VAlert",
                     "props": {"type": "warning", "variant": "tonal", "class": "mb-3",
                               "title": "插件未启用",
                               "text": "请在配置中启用插件，并至少填写 Clash API 地址或路由器地址。"}}]
        snapshot = self.__cached()
        if not snapshot:
            return [{"component": "VAlert",
                     "props": {"type": "info", "variant": "tonal",
                               "text": "首次采集进行中，请等待几秒后刷新本页。"}}]

        content: List[dict] = [self.__status_alert(snapshot), self.__overview_row(snapshot)]
        for card in (
            self.__version_card(snapshot),
            self.__node_group_card(snapshot),
            self.__node_card(snapshot),
            self.__subscription_card(snapshot),
            self.__dns_card(snapshot),
            self.__probe_card(snapshot),
            self.__querylog_card(snapshot),
        ):
            if card:
                content.append(card)
        return content

    def __status_alert(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """采集状态提示条。"""
        errors = [str(e) for e in (snapshot.get("errors") or []) if e]
        last_error = str(snapshot.get("last_error") or "").strip()
        stamp = str(snapshot.get("timestamp") or "未知")
        if last_error:
            return {"component": "VAlert",
                    "props": {"type": "error", "variant": "tonal", "class": "mb-3",
                              "title": f"最近一次采集异常（{stamp}）", "text": last_error[:300]}}
        if errors:
            return {"component": "VAlert",
                    "props": {"type": "warning", "variant": "tonal", "class": "mb-3",
                              "title": f"部分数据不可用（采集时间 {stamp}）",
                              "text": "；".join(errors)[:400]}}
        return {"component": "VAlert",
                "props": {"type": "success", "variant": "tonal", "class": "mb-3",
                          "title": f"数据正常（采集时间 {stamp}）",
                          "text": "全部数据源采集成功。"}}

    def __overview_row(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """首屏统计卡片。"""
        clash = snapshot.get("clash") or {}
        nodes = snapshot.get("nodes") or {}
        dns = snapshot.get("dns") or {}
        running = clash.get("enabled")
        running_text = "运行中" if running else "已停止"
        total = _safe_int(nodes.get("total"), 0)
        alive = _safe_int(nodes.get("alive"), 0)
        alive_text = f"{alive}/{total}" if total else "-"
        cards = [
            self.__stat_card("OpenClash", running_text, "mdi-shield-check", running),
            self.__stat_card("运行模式", clash.get("run_mode") or "-", "mdi-transit-connection-variant"),
            self.__stat_card("规则模式", clash.get("rule_mode") or "-", "mdi-source-branch"),
            self.__stat_card("核心版本", clash.get("core_version") or "-", "mdi-cube-outline"),
            self.__stat_card("活动连接", str(_safe_int(clash.get("connections"), 0)), "mdi-lan-connect"),
            self.__stat_card("节点在线", alive_text, "mdi-access-point",
                             None if not total else alive == total),
            self.__stat_card("内存占用", _format_size(clash.get("mem")),
                             "mdi-memory",
                             None),
            self.__stat_card("CPU 占用",
                             f"{clash.get('cpu_percent')}%" if clash.get("cpu_percent") is not None else "-",
                             "mdi-speedometer", None),
        ]
        return {"component": "VRow", "content": cards}

    @staticmethod
    def __stat_card(title: str, value: str, icon: str, good: Optional[bool] = None) -> Dict[str, Any]:
        """构造一个统计卡片。"""
        color = "primary"
        if good is True:
            color = "success"
        elif good is False:
            color = "error"
        return {
            "component": "VCol",
            "props": {"cols": 6, "md": 3},
            "content": [
                {"component": "VCard",
                 "props": {"variant": "tonal", "class": "mb-3"},
                 "content": [
                     {"component": "VCardText",
                      "props": {"class": "d-flex align-center"},
                      "content": [
                          {"component": "VIcon",
                           "props": {"icon": icon, "size": 30, "class": "me-3", "color": color}},
                          {"component": "div",
                           "content": [
                               {"component": "div",
                                "props": {"class": "text-caption text-medium-emphasis"},
                                "text": title},
                               {"component": "div",
                                "props": {"class": "text-h6 font-weight-bold", "style": "word-break: break-all;"},
                                "text": value if value else "-"},
                           ]},
                      ]},
                 ]},
            ],
        }

    def __version_card(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """版本与更新对比卡片。"""
        versions = snapshot.get("versions") or {}
        rows = [
            ("OpenClash 插件", versions.get("plugin_current"), versions.get("plugin_latest"),
             bool(versions.get("plugin_update"))),
            ("Meta 内核", versions.get("core_current"), versions.get("core_latest"),
             bool(versions.get("core_update"))),
            ("LocalDNS", versions.get("dns_current"), versions.get("dns_latest"),
             bool(versions.get("dns_update"))),
        ]
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("组件", "当前版本", "最新版本", "状态")]}]},
            {"component": "tbody", "content": []},
        ]
        for name, current, latest, update in rows:
            if update:
                status_cell = {"component": "td", "props": {"class": "text-warning font-weight-medium"},
                               "text": "可更新"}
            elif latest:
                status_cell = {"component": "td", "props": {"class": "text-success"}, "text": "已最新"}
            else:
                status_cell = {"component": "td", "props": {"class": "text-medium-emphasis"},
                               "text": "未知"}
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"}, "text": name},
                     {"component": "td", "text": current or "-"},
                     {"component": "td", "text": latest or "-"},
                     status_cell,
                 ]}
            )
        return self.__table_card("版本与更新", body, cols=12, md=5,
                                 caption="插件与内核的最新版本来自 OpenClash 的 last_version 接口，"
                                         "首次拉取可能显示为空；LocalDNS 的最新版取自 GitHub releases。")

    def __node_group_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """代理组卡片。"""
        nodes = snapshot.get("nodes") or {}
        groups = nodes.get("groups") or []
        if not groups:
            return None
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("策略组", "类型", "当前选择", "节点数", "在线")]}]},
            {"component": "tbody", "content": []},
        ]
        for group in groups[:12]:
            count = _safe_int(group.get("count"), 0)
            alive = _safe_int(group.get("alive"), 0)
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": str(group.get("name") or "-")},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": str(group.get("type") or "-")},
                     {"component": "td", "text": str(group.get("now") or "-")},
                     {"component": "td", "text": str(count)},
                     {"component": "td",
                      "props": {"class": "text-success" if count and alive == count else "text-warning"},
                      "text": f"{alive}/{count}" if count else "-"},
                 ]}
            )
        caption = (f"共 {_safe_int(nodes.get('total'), 0)} 个节点，在线 {_safe_int(nodes.get('alive'), 0)} 个"
                   f"，平均延迟 {nodes.get('avg_delay') or '-'} ms。"
                   "延迟来自内核最近一次测速，未测速的节点显示为未知。")
        return self.__table_card("代理组", body, cols=12, md=7, caption=caption)

    def __node_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """节点延迟卡片。"""
        nodes = snapshot.get("nodes") or {}
        items = nodes.get("nodes") or []
        if not items:
            return None
        limit = max(1, min(self._node_limit, len(items)))
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("节点", "机场", "类型", "延迟", "状态")]}]},
            {"component": "tbody", "content": []},
        ]
        for node in items[:limit]:
            state = str(node.get("state") or "unknown")
            delay = _safe_int(node.get("delay"), 0)
            if state == "ok":
                status_cell = {"component": "td", "props": {"class": "text-success"}, "text": "可用"}
            elif state == "idle":
                status_cell = {"component": "td", "props": {"class": "text-info"}, "text": "未测速"}
            elif state == "timeout":
                status_cell = {"component": "td", "props": {"class": "text-error"}, "text": "超时"}
            elif state == "down":
                status_cell = {"component": "td", "props": {"class": "text-error"}, "text": "不可用"}
            else:
                status_cell = {"component": "td", "props": {"class": "text-medium-emphasis"},
                               "text": "未知"}
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": str(node.get("name") or "-")},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": str(node.get("provider") or "内置/内联")},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": str(node.get("type") or "-")},
                     {"component": "td", "text": f"{delay} ms" if state == "ok" else "-"},
                     status_cell,
                 ]}
            )
        caption = (f"按延迟升序展示前 {limit} 个节点；共 {_safe_int(nodes.get('total'), 0)} 个节点，"
                   f"已测速 {_safe_int(nodes.get('tested'), 0)} 个。")
        sources = nodes.get("sources") or []
        if sources:
            caption += " 节点来源：" + "、".join(str(s) for s in sources[:6])
        return self.__table_card("节点延迟", body, cols=12, md=7, caption=caption)

    def __subscription_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """订阅卡片。"""
        sub = snapshot.get("subscription") or {}
        items = sub.get("items") or []
        if not items:
            return None
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("订阅", "HTTP", "已用", "总量", "剩余",
                                                   "剩余时间", "使用率")]}]},
            {"component": "tbody", "content": []},
        ]
        for item in items[:20]:
            percent = item.get("percent")
            percent_text = f"{percent}%" if isinstance(percent, (int, float)) else "-"
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": str(item.get("name") or "-")},
                     {"component": "td",
                      "props": {"class": "text-success" if _safe_int(item.get("http_code"), 0) == 200
                                else "text-warning"},
                      "text": str(item.get("http_code") or "-")},
                     {"component": "td", "text": str(item.get("used") or "-")},
                     {"component": "td", "text": str(item.get("total") or "-")},
                     {"component": "td", "text": str(item.get("surplus") or "-")},
                     {"component": "td", "text": str(item.get("days") or "-")},
                     {"component": "td", "text": percent_text},
                 ]}
            )
        caption = (f"当前配置：{sub.get('current') or '未知'}。剩余流量与到期时间来自订阅服务商，"
                   "部分机场不提供（显示「不支持查询」）。")
        return self.__table_card("订阅信息", body, cols=12, md=7, caption=caption)

    def __dns_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """LocalDNS 概览卡片。"""
        dns = snapshot.get("dns") or {}
        clash_dns = dns.get("clash") or {}
        if not dns and not clash_dns:
            return None
        rows: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("项目", "值")]}]},
            {"component": "tbody", "content": []},
        ]
        provider = str(dns.get("provider") or "none")
        provider_text = {"localdns": "LocalDNS", "adguard": "AdGuard Home"}.get(
            provider, "内置 UDP 探测")
        pairs: List[Tuple[str, str]] = [("DNS 来源", provider_text)]
        if provider == "localdns":
            version_text = str(dns.get("version") or "-")
            if dns.get("core_version"):
                version_text = f"{version_text}（核心 {dns['core_version']}）"
            pairs.extend([
                ("运行状态", "运行中" if dns.get("ok") else "不可用"),
                ("版本", version_text),
                ("更新通道", str(dns.get("channel") or "-")),
                ("DNS 监听", str(dns.get("listen") or "-")),
                ("API 监听", str(dns.get("api_listen") or "-")),
                ("累计查询", str(dns.get("queries") if dns.get("queries") is not None else "-")),
                ("累计拦截", str(dns.get("blocked") if dns.get("blocked") is not None else "-")),
                ("拦截率", f"{dns.get('blocked_percent')}%" if dns.get("blocked_percent") is not None else "-"),
                ("平均上游延迟", f"{dns.get('avg_ms')} ms" if dns.get("avg_ms") is not None else "-"),
                ("缓存命中", str(dns.get("cache_hits") if dns.get("cache_hits") is not None else "-")),
                ("屏蔽规则", f"{dns.get('adguard_rules')} 条" if dns.get("adguard_rules") is not None else "-"),
                ("缓存条目", str(dns.get("cache_entries") if dns.get("cache_entries") is not None else "-")),
                ("进程 CPU", f"{dns.get('cpu_percent')}%" if dns.get("cpu_percent") is not None else "-"),
                ("进程内存", _format_size(dns.get("mem_bytes")) if dns.get("mem_bytes") else "-"),
                ("运行时长", _format_uptime(dns.get("uptime_seconds"))),
                ("运行时", str(dns.get("runtime") or "-")),
            ])
        elif provider == "adguard":
            pairs.extend([
                ("运行状态", "运行中" if dns.get("running") else ("已停止" if dns.get("ok") else "不可用")),
                ("防护状态", "已开启" if dns.get("protection") else "已关闭"),
                ("版本", str(dns.get("version") or "-")),
                ("上游模式", str(dns.get("upstream_mode") or "-")),
                ("累计查询", str(dns.get("queries") if dns.get("queries") is not None else "-")),
                ("累计拦截", str(dns.get("blocked") if dns.get("blocked") is not None else "-")),
                ("拦截率", f"{dns.get('blocked_percent')}%" if dns.get("blocked_percent") is not None else "-"),
                ("平均耗时", f"{dns.get('avg_ms')} ms" if dns.get("avg_ms") is not None else "-"),
            ])
        if clash_dns:
            pairs.extend([
                ("Clash DNS 模式", str(clash_dns.get("mode") or "-")),
                ("Clash 上游", "、".join(clash_dns.get("nameserver") or []) or "-"),
                ("Fake-IP 段", str(clash_dns.get("fakeip_range") or "-")),
            ])
        if dns.get("error"):
            pairs.append(("错误", str(dns.get("error"))))
        for name, value in pairs:
            rows[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"}, "text": name},
                     {"component": "td", "text": str(value)},
                 ]}
            )

        upstreams = dns.get("upstreams") or []
        health = [x for x in (dns.get("upstream_health") or []) if isinstance(x, dict)]
        is_ld = provider == "localdns"
        if upstreams and not health:
            rows.append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": "上游 DNS 列表"},
                     {"component": "td", "text": "、".join(str(x) for x in upstreams)},
                 ]}
            )
        groups = dns.get("upstream_groups") or []
        if groups:
            rows.append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": "上游分组"},
                     {"component": "td",
                      "text": "、".join(f"{g.get('name')}({g.get('enabled')}/{g.get('count')})"
                                       for g in groups if isinstance(g, dict))},
                 ]}
            )
        up_content: List[Dict[str, Any]] = []
        if upstreams or health:
            head_cols = ("上游 DNS", "分组", "协议", "健康", "延迟", "请求/失败") if is_ld \
                else ("上游 DNS", "健康", "延迟")
            up_rows: List[Dict[str, Any]] = [
                {"component": "thead",
                 "content": [{"component": "tr",
                              "content": [{"component": "th", "text": text}
                                          for text in head_cols]}]},
                {"component": "tbody", "content": []},
            ]
            if health:
                for item in health:
                    ok = bool(item.get("ok"))
                    latency = item.get("latency_ms")
                    latency_text = f"{latency:g} ms" if isinstance(latency, (int, float)) else "-"
                    cells: List[Dict[str, Any]] = [
                        {"component": "td", "props": {"class": "font-weight-medium"},
                         "text": str(item.get("server") or "-")},
                    ]
                    if is_ld:
                        cells.extend([
                            {"component": "td", "text": str(item.get("group") or "-")},
                            {"component": "td", "props": {"class": "text-medium-emphasis"},
                             "text": str(item.get("protocol") or "-")},
                        ])
                    cells.extend([
                        {"component": "td",
                         "props": {"class": "text-success" if ok else "text-error"},
                         "text": "正常" if ok else "异常"},
                        {"component": "td", "text": latency_text},
                    ])
                    if is_ld:
                        failures = _safe_int(item.get("errors"), 0) + _safe_int(item.get("timeouts"), 0)
                        cells.append({"component": "td", "props": {"class": "text-medium-emphasis"},
                                      "text": f"{_safe_int(item.get('requests'), 0)}/{failures}"})
                    up_rows[1]["content"].append({"component": "tr", "content": cells})
            else:
                # 没有测速结果时，把已配置的上游列出来并标注未测试
                for server in upstreams:
                    cells: List[Dict[str, Any]] = [
                        {"component": "td", "props": {"class": "font-weight-medium"},
                         "text": str(server)},
                    ]
                    if is_ld:
                        cells.extend([{"component": "td", "text": "-"},
                                      {"component": "td", "text": "-"}])
                    cells.append({"component": "td",
                                  "props": {"class": "text-medium-emphasis"}, "text": "未测试"})
                    cells.append({"component": "td", "text": "-"})
                    if is_ld:
                        cells.append({"component": "td", "text": "-"})
                    up_rows[1]["content"].append({"component": "tr", "content": cells})
            up_content = [
                {"component": "div", "props": {"class": "text-subtitle-2 mt-4 mb-2"},
                 "text": "上游 DNS 健康"},
                {"component": "VTable", "props": {"density": "compact", "hover": True},
                 "content": up_rows},
            ]
            errors_detail = [item for item in health if str(item.get("error") or "").strip()]
            if errors_detail:
                up_content.append({"component": "div",
                                   "props": {"class": "text-caption text-medium-emphasis mt-2"},
                                   "text": "最近错误：" + "；".join(
                                       f"{item.get('server')} → {item.get('error')}"
                                       for item in errors_detail[:3])})

        top = dns.get("top_domains") or []
        if top:
            up_content.append({"component": "div",
                               "props": {"class": "text-subtitle-2 mt-4 mb-2"},
                               "text": "热门查询域名"})
            up_content.append({"component": "div", "props": {"class": "text-body-2"}, "content": [
                {"component": "div", "text": f"{idx}. {item.get('name')}（{item.get('count')} 次）"}
                for idx, item in enumerate(top[:5], start=1)
            ]})

        if provider == "localdns":
            caption = ("「上游 DNS 健康」取自 LocalDNS 的 upstream_stats 累计统计"
                       "（含请求数/失败数/平均延迟）；下方「主动探测」是插件自己发起的独立校验。")
        elif provider == "adguard":
            caption = ("「上游 DNS 健康」优先使用 AdGuard Home 自带的测速结果；"
                       "若 AdGuard 未返回，可参考下方「主动探测」面板。")
        else:
            caption = "未启用 DNS 接口采集，仅展示 Clash 内置 DNS 与主动探测结果。"
        return self.__table_card("LocalDNS 状态", rows, cols=12, md=6, caption=caption,
                                 extra=up_content)

    def __probe_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """主动探测卡片。"""
        probe = snapshot.get("probe") or []
        if not probe:
            return None
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("服务器", "结果", "延迟", "解析")]}]},
            {"component": "tbody", "content": []},
        ]
        for item in probe:
            ok = bool(item.get("ok"))
            answers = item.get("answers") or []
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": str(item.get("server") or "-")},
                     {"component": "td",
                      "props": {"class": "text-success" if ok else "text-error"},
                      "text": "正常" if ok else f"异常（{item.get('error') or '未知'}）"},
                     {"component": "td",
                      "text": f"{item.get('latency_ms')} ms" if item.get("latency_ms") is not None else "-"},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": ", ".join(str(a) for a in answers[:2]) if answers else "-"},
                 ]}
            )
        caption = (f"由本机直接向各上游 DNS 发 UDP 查询（域名 {self._dns_probe_domain}），"
                   "不依赖任何管理接口；若宿主容器禁止 UDP 出站，这里会全部超时。")
        return self.__table_card("主动 DNS 探测", body, cols=12, md=6, caption=caption)

    def __querylog_card(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """查询日志卡片。"""
        dns = snapshot.get("dns") or {}
        logs = dns.get("querylog") or []
        if not logs:
            return None
        body: List[Dict[str, Any]] = [
            {"component": "thead",
             "content": [{"component": "tr",
                          "content": [{"component": "th", "text": text}
                                      for text in ("时间", "域名", "类型", "客户端", "结果", "耗时", "响应")]}]},
            {"component": "tbody", "content": []},
        ]
        for item in logs[: self._querylog_limit or 20]:
            time_text = str(item.get("time") or "")
            if "T" in time_text:
                time_text = time_text.replace("T", " ")[:19]
            blocked = str(item.get("status") or "") == "拦截"
            elapsed = str(item.get("elapsed") or "")
            body[1]["content"].append(
                {"component": "tr",
                 "content": [
                     {"component": "td", "props": {"class": "text-medium-emphasis"}, "text": time_text or "-"},
                     {"component": "td", "props": {"class": "font-weight-medium"},
                      "text": str(item.get("domain") or "-")},
                     {"component": "td", "text": str(item.get("type") or "-")},
                     {"component": "td", "text": str(item.get("client") or "-")},
                     {"component": "td",
                      "props": {"class": "text-error" if blocked else "text-success"},
                      "text": str(item.get("status") or "-")},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": f"{elapsed} ms" if elapsed not in ("", "None") else "-"},
                     {"component": "td", "props": {"class": "text-medium-emphasis"},
                      "text": str(item.get("result") or "-")},
                 ]}
            )
        provider_text = {"localdns": "LocalDNS", "adguard": "AdGuard Home"}.get(
            str(dns.get("provider") or ""), "DNS 服务")
        return self.__table_card("最近 DNS 查询", body, cols=12, md=12,
                                 caption=f"来自 {provider_text} 的查询日志，按时间倒序；"
                                         "「拦截」依据 LocalDNS 的 domain_set 归类（adguard/blocked 系列）。")

    @staticmethod
    def __table_card(title: str, body: List[Dict[str, Any]], *,
                     cols: int = 12, md: int = 6, caption: Optional[str] = None,
                     extra: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """构造带表格的卡片。"""
        content: List[Dict[str, Any]] = [
            {"component": "VCardTitle", "props": {"class": "text-subtitle-1"}, "text": title},
            {"component": "VTable", "props": {"density": "compact", "hover": True}, "content": body},
        ]
        if caption:
            content.append({"component": "div",
                            "props": {"class": "text-caption text-medium-emphasis mt-2"},
                            "text": caption})
        if extra:
            content.extend(extra)
        return {
            "component": "VCol",
            "props": {"cols": cols, "md": md},
            "content": [
                {"component": "VCard", "props": {"variant": "tonal", "class": "mb-3"},
                 "content": [{"component": "VCardText", "content": content}]},
            ],
        }

    # ------------------------------------------------------------------
    # 仪表板
    # ------------------------------------------------------------------

    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        """返回仪表板元信息。"""
        if not self._enabled or not self._dashboard:
            return []
        return [{"key": _DASHBOARD_KEY, "name": "OpenClash 状态"}]

    def get_dashboard(self, key: str = "", **kwargs: Any) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[dict]]]:
        """返回首页仪表板。"""
        if not self._enabled or not self._dashboard:
            return None
        if key and key != _DASHBOARD_KEY:
            return None
        snapshot = self.__cached()
        cols = {"cols": 12, "md": 6}
        attrs = {"refresh": max(60, self._interval * 60), "border": True, "title": "OpenClash 状态"}
        if not snapshot:
            return cols, attrs, [
                {"component": "VAlert",
                 "props": {"type": "info", "variant": "tonal", "text": "首次采集进行中，稍后自动刷新。"}}
            ]
        clash = snapshot.get("clash") or {}
        nodes = snapshot.get("nodes") or {}
        dns = snapshot.get("dns") or {}
        versions = snapshot.get("versions") or {}
        total = _safe_int(nodes.get("total"), 0)
        alive = _safe_int(nodes.get("alive"), 0)
        content: List[dict] = [
            {"component": "VRow",
             "content": [
                 self.__stat_card("OpenClash", "运行中" if clash.get("enabled") else "已停止",
                                  "mdi-shield-check", bool(clash.get("enabled"))),
                 self.__stat_card("节点在线", f"{alive}/{total}" if total else "-",
                                  "mdi-access-point", None if not total else alive == total),
                 self.__stat_card("活动连接", str(_safe_int(clash.get("connections"), 0)),
                                  "mdi-lan-connect"),
                 self.__stat_card("内存占用", _format_size(clash.get("mem")), "mdi-memory"),
             ]},
        ]
        health_bits: List[str] = []
        if versions.get("core_update"):
            health_bits.append(f"内核可更新：{versions.get('core_current')} → {versions.get('core_latest')}")
        if versions.get("plugin_update"):
            health_bits.append(f"插件可更新：{versions.get('plugin_current')} → {versions.get('plugin_latest')}")
        if versions.get("dns_update"):
            health_bits.append(f"LocalDNS 可更新：{versions.get('dns_current')} → {versions.get('dns_latest')}")
        if dns.get("provider") == "adguard" and dns.get("ok"):
            health_bits.append(
                f"DNS 查询 {dns.get('queries')} 次，拦截 {dns.get('blocked')} 次"
                f"（{dns.get('blocked_percent') or 0}%），平均 {dns.get('avg_ms') or '-'} ms"
            )
        probe = snapshot.get("probe") or []
        if probe:
            ok_count = sum(1 for item in probe if item.get("ok"))
            health_bits.append(f"主动探测：{ok_count}/{len(probe)} 个上游 DNS 正常")
        errors = [str(e) for e in (snapshot.get("errors") or []) if e]
        alert_type = "warning" if (errors or snapshot.get("last_error")) else "success"
        alert_text = ("；".join(errors)[:220] if errors
                      else str(snapshot.get("last_error") or "全部数据源采集成功"))
        content.append(
            {"component": "VAlert",
             "props": {"type": alert_type, "variant": "tonal", "class": "mt-2",
                       "title": f"采集时间 {snapshot.get('timestamp') or '未知'}",
                       "text": alert_text}})
        if health_bits:
            content.append(
                {"component": "div", "props": {"class": "mt-2"},
                 "content": [{"component": "div", "props": {"class": "text-body-2"}, "text": bit}
                             for bit in health_bits]})
        return cols, attrs, content

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------

    def __cached(self) -> Dict[str, Any]:
        """读取快照缓存。"""
        try:
            data = self.get_data(_SNAPSHOT_KEY)
        except Exception as err:  # noqa: BLE001
            logger.warning(f"OpenClash 监控：读取快照失败 {err}")
            return {}
        return data if isinstance(data, dict) else {}

    def __cookie_jar(self) -> Dict[str, str]:
        """实例级 Cookie 容器（避免类属性共享）。"""
        jar = self.__dict__.get("_cookie_jar_data")
        if jar is None:
            jar = {}
            self.__dict__["_cookie_jar_data"] = jar
        return jar

    def __schedule_once(self) -> None:
        """安排一次延迟采集。"""
        try:
            from app.sdk.scheduler import add_plugin_once_job

            add_plugin_once_job(
                plugin_id=self.__class__.__name__,
                job_id=f"{self.__class__.__name__}Once",
                func=self.refresh,
                name="OpenClash 监控首次采集",
                delay_seconds=3,
            )
        except Exception as err:  # noqa: BLE001
            logger.warning(f"OpenClash 监控：安排首次采集失败 {err}")

    def __summary_text(self, snapshot: Dict[str, Any]) -> str:
        """生成远程命令用的文字摘要。"""
        clash = snapshot.get("clash") or {}
        nodes = snapshot.get("nodes") or {}
        dns = snapshot.get("dns") or {}
        versions = snapshot.get("versions") or {}
        lines = [
            f"采集时间：{snapshot.get('timestamp') or '未知'}",
            f"运行状态：{'运行中' if clash.get('enabled') else '已停止'}，"
            f"模式 {clash.get('run_mode') or '-'}，规则 {clash.get('rule_mode') or '-'}",
            f"节点：在线 {_safe_int(nodes.get('alive'), 0)}/{_safe_int(nodes.get('total'), 0)}，"
            f"平均延迟 {nodes.get('avg_delay') or '-'} ms",
            f"连接数：{_safe_int(clash.get('connections'), 0)}，"
            f"内存 {_format_size(clash.get('mem'))}",
        ]
        if versions.get("core_update") or versions.get("plugin_update"):
            lines.append(
                f"可更新：内核 {versions.get('core_current')} → {versions.get('core_latest')}，"
                f"插件 {versions.get('plugin_current')} → {versions.get('plugin_latest')}"
            )
        if dns.get("provider") == "adguard" and dns.get("ok"):
            lines.append(
                f"LocalDNS：查询 {dns.get('queries')} 次，拦截率 {dns.get('blocked_percent') or 0}%"
            )
        errors = [str(e) for e in (snapshot.get("errors") or []) if e]
        if errors:
            lines.append("异常：" + "；".join(errors)[:200])
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LuCI 访问
    # ------------------------------------------------------------------

    def __luci_get(self, action: str, params: Optional[Dict[str, Any]] = None,
                   timeout: Optional[float] = None) -> Tuple[Any, Optional[str]]:
        """请求 OpenClash 的 LuCI 接口，必要时自动登录。"""
        if not self._luci_url:
            return None, "未配置路由器地址"
        url = f"{self._luci_url}/cgi-bin/luci/admin/services/openclash/{action}"
        for attempt in (0, 1):
            result = http_request(
                "GET", url,
                headers={"X-Requested-With": "XMLHttpRequest"},
                params=params,
                timeout=timeout or self._timeout,
                cookies=self.__cookie_jar(),
            )
            if result["cookies"]:
                self.__cookie_jar().update(result["cookies"])
            if result["status"] == 401 or result["status"] == 403:
                if attempt == 0 and self.__luci_login():
                    continue
                return None, f"需要登录（HTTP {result['status']}）"
            if result["error"] and result["status"] is None:
                return None, str(result["error"])

            data = result["data"]
            if isinstance(data, (dict, list)):
                if isinstance(data, dict) and data.get("error"):
                    return None, str(data.get("error"))[:200]
                return data, None

            text = (result["text"] or "").strip()
            lowered = text[:400].lower()
            if "<html" in lowered or "<!doctype" in lowered or "luci" in lowered and "<" in lowered:
                if attempt == 0 and self.__luci_login():
                    continue
                return None, "LuCI 需要登录：请填写用户名密码，或粘贴浏览器里的 sysauth cookie"
            if result["status"] not in (None, 200) and result["status"] >= 400:
                return None, f"HTTP {result['status']}"
            return None, f"响应不是 JSON：{text[:120] or '空响应'}"
        return None, "LuCI 请求失败"

    def __luci_login(self) -> bool:
        """尝试用配置的账号密码（或手工 cookie）建立 LuCI 登录态。"""
        jar = self.__cookie_jar()
        if self._luci_cookie:
            jar.update(_parse_cookie_header(self._luci_cookie))
            if jar:
                return True
        if not (self._luci_username and self._luci_password):
            return bool(jar)
        login_url = f"{self._luci_url}/cgi-bin/luci"
        # LuCI 会校验来源，缺 Referer/Origin 时直接返回登录页（实测 403）
        login_headers = {
            "Referer": f"{self._luci_url}/cgi-bin/luci/",
            "Origin": self._luci_url,
            "X-Requested-With": "XMLHttpRequest",
        }
        for fields in (
            {"luci_username": self._luci_username, "luci_password": self._luci_password},
            {"username": self._luci_username, "password": self._luci_password},
        ):
            result = http_request("POST", login_url, body=fields, form=True,
                                  headers=login_headers, allow_redirects=False,
                                  timeout=self._timeout, cookies=jar)
            if result["cookies"]:
                jar.update(result["cookies"])
            if any(key.startswith("sysauth") for key in jar):
                logger.info("OpenClash 监控：LuCI 登录成功")
                return True
        logger.warning("OpenClash 监控：LuCI 登录失败，请改用 sysauth cookie")
        return bool(jar)
