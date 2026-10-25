"""一键升级 MoviePilot 里的插件，绕开「本地候选」导致的装不生效。

背景：MoviePilot 的 plugin.install 在插件已存在时，会把已安装目录当作本地候选直接同步，
所以反复点安装/更新都提示成功但版本不变。本脚本按下面的顺序兜底：

1. 触发一次插件市场刷新（让市场索引拿到最新版本）
2. 直接 install（带 repo_url）——若版本已正确，结束
3. 否则：uninstall -> 删除 /app/app/plugins/<id> 与 /config/plugins_backup/<id> -> 再 install
4. 再校验版本

用法（默认读环境变量或命令行参数）：
    python devtools/update_mp.py --expect 0.2.0
    python devtools/update_mp.py --plugin SubtitleShield \
        --repo https://github.com/zimo650/MoviePilot-Plugins --expect 0.2.0 \
        --base http://<MoviePilot地址>:3001 --apikey <你的 API 密钥>

只依赖标准库。
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = os.environ.get("MP_BASE", "http://127.0.0.1:3001")
DEFAULT_KEY = os.environ.get("MP_APIKEY", "")
DEFAULT_PLUGIN = "SubtitleShield"
DEFAULT_REPO = "https://github.com/zimo650/MoviePilot-Plugins"

_CONTEXT = ssl.create_default_context()
_CONTEXT.check_hostname = False
_CONTEXT.verify_mode = ssl.CERT_NONE


def call(base, apikey, method, path, params=None, body=None, timeout=60.0):
    url = base.rstrip("/") + path
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    data = None
    headers = {"Accept": "application/json", "X-API-KEY": apikey}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CONTEXT) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8", "replace")
        try:
            return err.code, json.loads(raw)
        except ValueError:
            return err.code, raw
    except Exception as err:  # noqa: BLE001
        return 0, {"error": str(err)}


def installed_version(base, apikey, plugin_id):
    """返回「已安装」那份的版本。

    MoviePilot 的 /api/v1/plugin/ 会同时返回市场条目（is_local=False）与本地已装条目
    （is_local=True）；按 id 取第一条会把市场版本误当成已装版本，所以优先挑 is_local 的那份。
    """
    status, data = call(base, apikey, "GET", "/api/v1/plugin/", params={"query": plugin_id, "count": 50})
    items = data if isinstance(data, list) else (data or {}).get("data") or []
    local, any_installed = None, None
    for item in items:
        if str(item.get("id", "")).lower() != plugin_id.lower():
            continue
        if item.get("is_local"):
            local = item.get("plugin_version")
        elif item.get("installed") and any_installed is None:
            any_installed = item.get("plugin_version")
    return local or any_installed


def market_version(base, apikey, plugin_id):
    status, data = call(base, apikey, "GET", "/api/v1/plugin/",
                        params={"state": "market", "query": plugin_id, "count": 50, "force": "true"})
    items = data if isinstance(data, list) else (data or {}).get("data") or []
    for item in items:
        if str(item.get("id", "")).lower() == plugin_id.lower():
            return item.get("plugin_version")
    return None


def remove_dir(base, apikey, path):
    status, data = call(base, apikey, "POST", "/api/v1/storage/delete",
                        body={"path": path, "storage": "local", "type": "dir"})
    code = (data or {}).get("code") if isinstance(data, dict) else None
    ok = status == 200 and code in (0, None)
    print(f"  删除 {path}: {'OK' if ok else '跳过/失败'} {'' if ok else str(data)[:120]}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description="一键升级 MoviePilot 插件（绕开本地候选）")
    parser.add_argument("--plugin", default=DEFAULT_PLUGIN)
    parser.add_argument("--repo", default=DEFAULT_REPO)
    parser.add_argument("--expect", default="", help="期望安装到的版本号，例如 0.2.0")
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--apikey", default=DEFAULT_KEY)
    parser.add_argument("--wait", type=int, default=45, help="市场刷新后等待秒数")
    parser.add_argument("--force-clean", action="store_true", help="跳过第一次直接安装，直接按清理流程重装")
    args = parser.parse_args()

    if not args.apikey:
        print("缺少 API 密钥：用 --apikey 或环境变量 MP_APIKEY 提供")
        return 2

    pid = args.plugin
    print(f"目标插件 {pid}，MoviePilot {args.base}")

    print("1) 触发插件市场刷新")
    call(args.base, args.apikey, "GET", "/api/v1/system/runscheduler", params={"jobid": "plugin_market_refresh"})
    deadline = time.time() + args.wait
    latest = None
    while time.time() < deadline:
        latest = market_version(args.base, args.apikey, pid)
        if latest:
            break
        time.sleep(5)
    print(f"   市场里的版本：{latest or '未知'}")

    current = installed_version(args.base, args.apikey, pid)
    print(f"   当前已安装版本：{current or '未安装'}")

    want = args.expect or latest
    if want and current == want and not args.force_clean:
        print(f"已经是 {want}，无需升级")
        return 0

    if not args.force_clean:
        print("2) 先试直接安装（带 repo_url）")
        call(args.base, args.apikey, "GET", f"/api/v1/plugin/install/{pid}",
             params={"repo_url": args.repo, "force": "true"})
        time.sleep(8)
        current = installed_version(args.base, args.apikey, pid)
        print(f"   安装后版本：{current or '未知'}")
        if want and current == want:
            print("✔ 直接安装已生效" if current else "")
            return 0

    print("3) 走清理流程：卸载 → 删目录 → 重装")
    call(args.base, args.apikey, "DELETE", f"/api/v1/plugin/{pid}")
    time.sleep(3)
    lower = pid.lower()
    remove_dir(args.base, args.apikey, f"/app/app/plugins/{lower}")
    remove_dir(args.base, args.apikey, f"/config/plugins_backup/{lower}")
    print("   重新安装")
    call(args.base, args.apikey, "GET", f"/api/v1/plugin/install/{pid}",
         params={"repo_url": args.repo, "force": "true"})
    time.sleep(10)
    current = installed_version(args.base, args.apikey, pid)
    print(f"   安装后版本：{current or '未知'}")
    if want and current == want:
        print(f"✔ 已升级到 {want}")
        print("提示：下载完成事件钩子在插件加载时注册，重启一次 MoviePilot 后生效")
        return 0
    print(f"✘ 版本仍是 {current or '未知'}，期望 {want or '最新'}；可稍后再试（市场缓存可能需要几分钟）")
    return 1


if __name__ == "__main__":
    sys.exit(main())
