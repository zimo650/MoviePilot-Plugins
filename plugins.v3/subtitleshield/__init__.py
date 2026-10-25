"""字幕规范化（SubtitleShield）

MoviePilot 原生在整理时会按文件名把字幕改成 ``视频名.chi.zh-cn.srt`` / ``视频名.zh-tw.srt``，
但它只看文件名：文件名没有语言标识时（例如发布组常见的中文字幕 ``xxx.ass``），字幕会被改名成
``视频名.srt``，Emby 显示为“未知语言”；已经入库的历史字幕也不会再被规范化。

本插件补上这四点（不重复 MoviePilot 已有的下载/整理/硬链接能力）：

1. 内容级简繁判定：文件名优先，缺失时读字幕正文，用常用简繁字对做比例判定；
2. 历史库规范化：扫描媒体库目录，把已有字幕统一为 MoviePilot 的命名规范；
3. 简繁共存：同一视频的简中与繁中同时保留（``.chi.zh-cn`` + ``.zh-tw``）；
4. 精确刷新：改完按条目调用 Emby ``/Library/Media/Updated``，并可叠加库扫描。

默认 ``dry_run``，只在页面与报告里给出计划，确认后再放开写入。
"""

import base64
import os
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib import request as urlrequest
from urllib.parse import quote, urlencode
import ssl

import json

try:  # MoviePilot V3 SDK
    from app.sdk.plugin import _PluginBase
    from app.sdk.logging import logger
    from app.sdk.scheduler import add_plugin_once_job, remove_plugin_once_job
    from app.sdk.events import eventmanager
except Exception:  # pragma: no cover - 仅用于本地脱离宿主运行
    class _PluginBase:  # type: ignore
        pass

    class _Logger:  # type: ignore
        def info(self, *a, **k):
            print("[info]", *a)

        def warning(self, *a, **k):
            print("[warn]", *a)

        def error(self, *a, **k):
            print("[error]", *a)

        def debug(self, *a, **k):
            print("[debug]", *a)

    logger = _Logger()
    add_plugin_once_job = None
    remove_plugin_once_job = None
    eventmanager = None

try:
    from app.schemas.types import EventType
except Exception:  # pragma: no cover
    try:
        from app.schemas import EventType  # type: ignore
    except Exception:
        EventType = None  # type: ignore

try:
    from app.schemas.types import NotificationType
except Exception:  # pragma: no cover
    try:
        from app.schemas import NotificationType  # type: ignore
    except Exception:
        NotificationType = None  # type: ignore

try:
    from app.schemas.types import NotificationChannel
except Exception:  # pragma: no cover
    try:
        from app.schemas.types import MessageChannel as NotificationChannel  # type: ignore
    except Exception:
        NotificationChannel = None  # type: ignore


class SubtitleShield(_PluginBase):
    # 插件元数据
    plugin_name = "字幕规范化"
    plugin_desc = "按内容判定简繁、把字幕统一成 MoviePilot 命名规范、简繁共存，并按条目刷新 Emby"
    plugin_icon = "Moviepilot_A.png"
    plugin_version = "0.1.3"
    plugin_author = "zimo650"
    author_url = "https://github.com/zimo650"
    plugin_config_prefix = "subtitleshield_"
    plugin_order = 30
    auth_level = 1

    # 运行时状态
    _enabled = False
    _notify = True
    _onlyonce = False
    _dashboard = True
    _media_roots = ""
    _scan_cron = "0 4 * * *"
    _dry_run = True
    _auto_apply = False
    _limit = 10
    _tag_style = "mp"
    _keep_both = True
    _default_sub = "zh-cn"
    _prefer_format = "ass,srt,ssa,vtt,sup"
    _content_detect = True
    _min_chars = 20
    _emby_enabled = False
    _emby_url = ""
    _emby_apikey = ""
    _emby_refresh_mode = "item"
    _emby_path_map = ""
    _emby_touch = True
    _timeout = 10
    _max_depth = 4
    _max_files = 200000

    def init_plugin(self, config: dict = None):
        config = config or {}
        self._enabled = bool(config.get("enabled", False))
        self._notify = bool(config.get("notify", True))
        self._dashboard = bool(config.get("dashboard", True))
        self._onlyonce = bool(config.get("onlyonce", False))
        self._media_roots = str(config.get("media_roots") or "")
        self._scan_cron = str(config.get("scan_cron") or "0 4 * * *").strip() or "0 4 * * *"
        self._dry_run = bool(config.get("dry_run", True))
        self._auto_apply = bool(config.get("auto_apply", False))
        self._limit = max(1, min(_safe_int(config.get("limit"), 10), 500))
        self._tag_style = str(config.get("tag_style") or "mp")
        self._keep_both = bool(config.get("keep_both", True))
        self._default_sub = str(config.get("default_sub") or "zh-cn").strip().lower()
        self._prefer_format = str(config.get("prefer_format") or "ass,srt,ssa,vtt,sup")
        self._content_detect = bool(config.get("content_detect", True))
        self._min_chars = max(1, min(_safe_int(config.get("min_chars"), 20), 10000))
        self._emby_enabled = bool(config.get("emby_enabled", False))
        self._emby_url = _norm_url(str(config.get("emby_url") or ""))
        self._emby_apikey = str(config.get("emby_apikey") or "")
        self._emby_refresh_mode = str(config.get("emby_refresh_mode") or "item")
        self._emby_path_map = str(config.get("emby_path_map") or "")
        self._emby_touch = bool(config.get("emby_touch", True))
        self._timeout = max(3, min(_safe_int(config.get("timeout"), 10), 120))
        self._max_depth = max(1, min(_safe_int(config.get("max_depth"), 4), 12))
        self._max_files = max(100, min(_safe_int(config.get("max_files"), 200000), 1000000))

        if self._onlyonce:
            logger.info(f"{self.plugin_name}：立即执行一次规范化")
            self._onlyonce = False
            self.__update_config()
            self.__schedule_once()

    def get_state(self) -> bool:
        return self._enabled

    def stop_service(self):
        try:
            if remove_plugin_once_job:
                remove_plugin_once_job(plugin_id=self.__class__.__name__,
                                       job_id=f"{self.__class__.__name__}Once")
        except Exception as e:
            logger.debug(f"{self.plugin_name}：移除一次性任务失败 {e}")

    def get_service(self) -> List[Dict[str, Any]]:
        if not self._enabled:
            return []
        job = {"id": f"{self.__class__.__name__}.Scan", "name": f"{self.plugin_name}定时扫描",
               "func": self.scan_and_apply, "kwargs": {}}
        trigger = self.__cron_trigger(self._scan_cron)
        if trigger is not None:
            job["trigger"] = trigger
        else:
            job["trigger"] = "interval"
            job["kwargs"] = {"minutes": 1440}
        return [job]

    # ------------------------------------------------------------------ 表单

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        return [
            {
                "component": "VForm",
                "content": [
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(12, {"component": "VAlert", "props": {"type": "info", "variant": "tonal",
                                                                              "text": "首次使用请保持「只预览不写入」开启，先看计划表，确认无误再关闭它执行真实改名。"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._enabled, "label": "启用插件",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._dry_run, "label": "只预览不写入",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._auto_apply, "label": "定时任务自动执行",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._onlyonce, "label": "立即运行一次",
                                                                             "density": "compact"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._notify, "label": "发送通知",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._dashboard, "label": "显示仪表板",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._keep_both, "label": "简繁共存",
                                                                             "density": "compact"}}),
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._content_detect, "label": "读内容判定",
                                                                             "density": "compact"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(12, {"component": "VTextarea", "props": {
                                "modelValue": self._media_roots, "rows": 2, "label": "媒体库目录（每行或用逗号分隔）",
                                "placeholder": "/video/downloads/link/movie\n/video/downloads/link/tv",
                                "hint": "填 MoviePilot 容器内可见的媒体库路径；建议只填库根目录，插件会递归扫描"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(4, {"component": "VTextField", "props": {"modelValue": self._scan_cron, "label": "定时表达式",
                                                                                "placeholder": "0 4 * * *",
                                                                                "hint": "cron 五段式：分 时 日 月 周"}}),
                            self.__col(2, {"component": "VTextField", "props": {"modelValue": self._limit, "label": "每轮最多处理",
                                                                                "type": "number", "hint": "试跑建议 10"}}),
                            self.__col(2, {"component": "VTextField", "props": {"modelValue": self._max_depth, "label": "递归深度",
                                                                                "type": "number"}}),
                            self.__col(4, {"component": "VSelect", "props": {
                                "modelValue": self._tag_style, "label": "语言标签风格",
                                "items": _TAG_STYLE_OPTIONS, "hint": "mp = MoviePilot 原生（.chi.zh-cn / .zh-tw）"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(3, {"component": "VTextField", "props": {"modelValue": self._default_sub, "label": "默认字幕语言",
                                                                                "hint": "匹配时加 .default 前缀，如 zh-cn"}}),
                            self.__col(3, {"component": "VTextField", "props": {"modelValue": self._prefer_format, "label": "格式优先级",
                                                                                "hint": "ass,srt,ssa,vtt,sup"}}),
                            self.__col(2, {"component": "VSwitch", "props": {"modelValue": self._auto_apply, "label": "自动执行",
                                                                             "density": "compact",
                                                                             "hint": "定时任务是否直接改名（建议先关）"}}),
                            self.__col(2, {"component": "VTextField", "props": {"modelValue": self._min_chars, "label": "最少字符",
                                                                                "type": "number"}}),
                            self.__col(2, {"component": "VTextField", "props": {"modelValue": self._timeout, "label": "超时(秒)",
                                                                                "type": "number"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(3, {"component": "VSwitch", "props": {"modelValue": self._emby_enabled, "label": "刷新 Emby",
                                                                             "density": "compact"}}),
                            self.__col(5, {"component": "VTextField", "props": {"modelValue": self._emby_url,
                                                                                "label": "Emby 地址",
                                                                                "placeholder": "http://192.168.1.1:8096"}}),
                            self.__col(4, {"component": "VTextField", "props": {"modelValue": self._emby_apikey,
                                                                                "label": "Emby API Key", "type": "password"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(4, {"component": "VSelect", "props": {
                                "modelValue": self._emby_refresh_mode, "label": "刷新方式",
                                "items": _EMBY_MODE_OPTIONS,
                                "hint": "item = 只刷新改动条目；library = 库扫描；both = 两者"}}),
                        ],
                    },
                    {
                        "component": "VRow",
                        "content": [
                            self.__col(8, {"component": "VTextarea", "props": {
                                "modelValue": self._emby_path_map, "rows": 2, "label": "路径映射（MoviePilot 路径:Emby 路径）",
                                "placeholder": "/video/downloads/link/movie:/data/movie\n/video/downloads/link/tv:/data/tv",
                                "hint": "容器路径和 Emby 的不一致时必须填，否则 Emby 收不到改动通知"}}),
                            self.__col(4, {"component": "VSwitch", "props": {
                                "modelValue": self._emby_touch, "label": "更新视频时间戳",
                                "density": "compact",
                                "hint": "改字幕名后 Emby 不会自动重新扫描，需要动一下视频文件时间"}}),
                        ],
                    },
                ],
            },
            {
                "component": "VRow",
                "content": [
                    self.__col(12, {"component": "VAlert", "props": {
                        "type": "warning", "variant": "tonal",
                        "text": "改名只影响字幕文件名，不会动视频内容；同语言重复字幕只提示、不删除。"}}),
                ],
            },
        ], {
            "enabled": self._enabled, "notify": self._notify, "onlyonce": self._onlyonce,
            "dashboard": self._dashboard, "media_roots": self._media_roots, "scan_cron": self._scan_cron,
            "dry_run": self._dry_run, "auto_apply": self._auto_apply, "limit": self._limit,
            "tag_style": self._tag_style, "keep_both": self._keep_both, "default_sub": self._default_sub,
            "prefer_format": self._prefer_format, "content_detect": self._content_detect,
            "min_chars": self._min_chars,
            "emby_enabled": self._emby_enabled, "emby_url": self._emby_url, "emby_apikey": self._emby_apikey,
            "emby_refresh_mode": self._emby_refresh_mode,
            "emby_path_map": self._emby_path_map, "emby_touch": self._emby_touch,
            "timeout": self._timeout,
            "max_depth": self._max_depth,
        }

    @staticmethod
    def __col(width: int, item: Dict[str, Any]) -> Dict[str, Any]:
        return {"component": "VCol", "props": {"cols": 12, "md": width}, "content": [item]}

    # ------------------------------------------------------------- 扫描 / 计划

    def scan_and_apply(self) -> Dict[str, Any]:
        """定时任务入口：先扫描出计划，再按配置决定是否真的写入。"""
        plan = self.build_plan()
        result: Dict[str, Any] = {"scan": plan.get("summary", {}), "apply": None}
        if not self._dry_run and self._auto_apply and plan.get("items"):
            result["apply"] = self.apply_plan(plan)
        self.save_data("last_plan", plan)
        report = {"timestamp": _now(), "scan": plan.get("summary", {}),
                  "apply": result.get("apply"), "errors": plan.get("errors", [])}
        self.save_data("last_report", report)
        if self._notify:
            self.__notify_report(report)
        return result

    def build_plan(self) -> Dict[str, Any]:
        roots = self.__roots()
        errors: List[str] = []
        if not roots:
            return {"timestamp": _now(), "roots": [], "summary": {"roots": 0, "videos": 0, "subtitles": 0,
                                                                  "pending": 0, "skipped": 0}, "items": [],
                    "kept": [], "errors": ["未配置媒体库目录"]}

        videos: List[Dict[str, Any]] = []
        subs: List[Dict[str, Any]] = []
        scanned_files = 0
        for root in roots:
            if not os.path.isdir(root):
                errors.append(f"目录不存在：{root}")
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                depth = len(Path(dirpath).relative_to(root).parts)
                dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIRS]
                if depth >= self._max_depth:
                    dirnames[:] = []
                for name in filenames:
                    scanned_files += 1
                    if scanned_files > self._max_files:
                        errors.append(f"文件数超过上限 {self._max_files}，已提前结束扫描")
                        break
                    ext = os.path.splitext(name)[1].lower()
                    full = os.path.join(dirpath, name)
                    if ext in _VIDEO_EXTS:
                        videos.append({"path": full, "dir": dirpath, "name": name,
                                       "stem": os.path.splitext(name)[0], "key": _pair_key(name)})
                    elif ext in _SUB_EXTS:
                        subs.append({"path": full, "dir": dirpath, "name": name,
                                     "stem": os.path.splitext(name)[0], "ext": ext,
                                     "size": _safe_size(full)})
                if scanned_files > self._max_files:
                    break

        sub_index: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for sub in subs:
            sub_index.setdefault((sub["dir"], _pair_key(sub["name"])), []).append(sub)

        prefer = [f".{x.strip().lower().lstrip('.')}" for x in self._prefer_format.split(",") if x.strip()]
        items: List[Dict[str, Any]] = []
        kept: List[Dict[str, Any]] = []
        duplicates: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for video in videos:
            candidates = list(sub_index.get((video["dir"], video["key"]), []))
            # 补充：文件名主干完全一致但 key 不同的情况
            if not candidates:
                for sub in subs:
                    if sub["dir"] == video["dir"] and _stem_linked(video["stem"], sub["name"]):
                        candidates.append(sub)
            if not candidates:
                continue
            decided: List[Dict[str, Any]] = []
            for sub in candidates:
                lang, source, conf = self.__detect_language(sub)
                target, default_tag = self.__target_name(video["stem"], lang, sub["ext"])
                decided.append({"sub": sub, "lang": lang, "source": source, "confidence": conf,
                                "target": target, "default": default_tag})
            # 同一语言只留一份（格式优先 + 体积最大优先）；简繁默认各留一份
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for item in decided:
                grouped.setdefault(item["lang"], []).append(item)
            if not self._keep_both and grouped:
                keep_lang = "zh_cn" if "zh-cn" in self._default_sub else ""
                if keep_lang not in grouped:
                    keep_lang = "zh_cn" if "zh_cn" in grouped else sorted(grouped.keys())[0]
                for other_lang in [k for k in grouped if k != keep_lang]:
                    for item in grouped[other_lang]:
                        skipped.append({"video": video["name"], "subtitle": item["sub"]["name"],
                                        "lang_label": _LANG_LABELS.get(other_lang, other_lang),
                                        "reason": f"已关闭简繁共存，保留 {_LANG_LABELS.get(keep_lang, keep_lang)}"})
                grouped = {keep_lang: grouped[keep_lang]}
            for lang, group in grouped.items():
                group.sort(key=lambda x: (_fmt_rank(x["sub"]["ext"], prefer), -x["sub"]["size"]))
                for idx, item in enumerate(group):
                    sub = item["sub"]
                    if lang == "unknown":
                        skipped.append({"video": video["name"], "subtitle": sub["name"],
                                        "lang_label": "未识别",
                                        "reason": f"语言未识别（{item['source']}），保持原样"})
                        continue
                    need = os.path.basename(item["target"]) != sub["name"]
                    entry = {
                        "video": video["name"], "dir": video["dir"], "subtitle": sub["name"],
                        "lang": lang, "lang_label": _LANG_LABELS.get(lang, lang),
                        "source": item["source"], "confidence": item["confidence"],
                        "target": os.path.basename(item["target"]), "need": need,
                    }
                    if idx > 0:
                        duplicates.append({**entry, "reason": "同语言重复，未处理"})
                        continue
                    if need:
                        items.append(entry)
                    else:
                        kept.append(entry)

        items.sort(key=lambda x: (x["dir"], x["video"]))
        summary = {"roots": len(roots), "videos": len(videos), "subtitles": len(subs),
                   "pending": len(items), "kept": len(kept),
                   "duplicates": len(duplicates), "skipped": len(skipped)}
        return {"timestamp": _now(), "roots": roots, "summary": summary, "items": items,
                "kept": kept, "duplicates": duplicates, "skipped": skipped, "errors": errors}

    def apply_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        limit = self._limit
        done: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []
        touched_dirs = set()
        count = 0
        for item in plan.get("items", []):
            if count >= limit:
                break
            src = os.path.join(item["dir"], item["subtitle"])
            dst = os.path.join(item["dir"], item["target"])
            if not os.path.isfile(src):
                failed.append({**item, "reason": "源文件不存在"})
                continue
            if os.path.abspath(src) == os.path.abspath(dst):
                continue
            if os.path.exists(dst):
                failed.append({**item, "reason": "目标已存在，跳过"})
                continue
            try:
                os.rename(src, dst)
                done.append({**item, "ok": True})
                touched_dirs.add(item["dir"])
                count += 1
                if self._emby_touch:
                    self.__touch_video(item)
                logger.info(f"{self.plugin_name}：{item['subtitle']} -> {item['target']}")
            except Exception as e:
                failed.append({**item, "reason": str(e)})
        refresh = self.__refresh_emby(sorted(touched_dirs)) if touched_dirs else None
        result = {"timestamp": _now(), "applied": len(done), "failed": len(failed),
                  "done": done, "errors": failed, "emby": refresh}
        self.save_data("last_apply", result)
        return result

    # ------------------------------------------------------------- 语言判定

    def __detect_language(self, sub: Dict[str, Any]) -> Tuple[str, str, str]:
        lang, source, conf = _lang_from_name(sub["name"])
        if conf == "high":
            return lang, source, conf
        content: Tuple[str, str, str] = ("unknown", "未识别", "none")
        if self._content_detect:
            try:
                content = self.__detect_from_content(sub["path"])
            except Exception as e:
                logger.debug(f"{self.plugin_name}：读取 {sub['name']} 失败 {e}")
                content = ("unknown", "读取失败", "none")
        if content[0] != "unknown":
            # 正文证据优先于 zh-Hans / zh-Hant 这类弱标识（实测站内抽流常标错）
            return content
        if lang != "unknown":
            return lang, source, conf
        return content

    def __detect_from_content(self, path: str) -> Tuple[str, str, str]:
        raw = b""
        with open(path, "rb") as f:
            raw = f.read(512 * 1024)
        text = _decode_text(raw)
        text = _strip_subtitle_markup(text)
        text = re.sub(r"[A-Za-z0-9]+", "", text)
        simp = trad = kana = 0
        for ch in text:
            if ch in _SIMP_SET:
                simp += 1
            elif ch in _TRAD_SET:
                trad += 1
            elif _is_kana(ch):
                kana += 1
        total = simp + trad
        if total < self._min_chars:
            if kana >= self._min_chars:
                return "ja", "内容含假名", "medium"
            return "unknown", f"中文字符不足({total})", "none"
        ratio = trad / total if total else 0.0
        if ratio >= 0.75:
            return "zh_tw", f"内容繁体 {ratio:.0%}", "high"
        if ratio <= 0.25:
            return "zh_cn", f"内容简体 {1 - ratio:.0%}", "high"
        # 混合：按多数派给出结论，但标注置信度低
        if ratio > 0.5:
            return "zh_tw", f"内容偏繁 {ratio:.0%}", "low"
        return "zh_cn", f"内容偏简 {1 - ratio:.0%}", "low"

    def __target_name(self, video_stem: str, lang: str, ext: str) -> Tuple[str, bool]:
        tag = _TAG_MP.get(lang, "")
        if self._tag_style == "chs_cht":
            tag = _TAG_CHS.get(lang, tag)
        if not tag:
            return f"{video_stem}{ext}", False
        default = bool(self._default_sub) and self._default_sub in tag.lower()
        name = f"{video_stem}{'.default' if default else ''}.{tag}{ext}"
        return name, default

    # ------------------------------------------------------------- Emby

    def __map_emby_path(self, path: str) -> str:
        """把 MoviePilot 侧路径翻译成 Emby 侧路径（容器挂载点通常不同）。"""
        if not self._emby_path_map:
            return path
        candidates: List[Tuple[str, str]] = []
        for chunk in re.split(r"[,;\n]+", self._emby_path_map):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "=>" in chunk:
                src, dst = chunk.split("=>", 1)
                candidates.append((src, dst))
                continue
            # 兼容 src:dst 与 src=dst；逐字符尝试切分，最后按前缀匹配度取最优，
            # 这样 Windows 盘符里的冒号（C:\）不会被误当成分隔符。
            for idx, ch in enumerate(chunk):
                if ch in ":=":
                    candidates.append((chunk[:idx], chunk[idx + 1:]))
        best_src = ""
        best_dst = ""
        for raw_src, raw_dst in candidates:
            src = raw_src.strip().replace("\\", "/").rstrip("/")
            dst = raw_dst.strip().replace("\\", "/").rstrip("/")
            probe = path.replace("\\", "/")
            if not src or not dst or not probe.startswith(src):
                continue
            if len(src) > len(best_src):
                best_src, best_dst = src, dst
        if not best_src:
            return path
        return best_dst + path.replace("\\", "/")[len(best_src):]

    def __touch_video(self, item: Dict[str, Any]) -> None:
        """动一下视频文件的时间戳，逼迫 Emby 重新探测外挂字幕。"""
        video_path = os.path.join(item["dir"], item["video"])
        try:
            if os.path.isfile(video_path):
                os.utime(video_path, None)
        except Exception as e:
            logger.debug(f"{self.plugin_name}：更新时间戳失败 {video_path} {e}")

    def __refresh_emby(self, dirs: List[str]) -> Optional[Dict[str, Any]]:
        if not (self._emby_enabled and self._emby_url):
            return None
        mode = self._emby_refresh_mode
        out: Dict[str, Any] = {"mode": mode, "updated": 0, "scanned": 0, "error": ""}
        headers = {"Content-Type": "application/json"}
        if self._emby_apikey:
            headers["X-Emby-Token"] = self._emby_apikey
            headers["Authorization"] = f'MediaBrowser Token="{self._emby_apikey}"'
        if mode in ("item", "both") and dirs:
            updates = [{"Path": self.__map_emby_path(d), "UpdateType": "Modified"} for d in dirs]
            res = _http_json("POST", f"{self._emby_url}/Library/Media/Updated", headers=headers,
                             payload={"Updates": updates}, timeout=self._timeout)
            if res.get("ok"):
                out["updated"] = len(updates)
            else:
                out["error"] = res.get("error") or f"HTTP {res.get('status')}"
        if mode in ("library", "both"):
            res = _http_json("POST", f"{self._emby_url}/Library/Refresh", headers=headers,
                             payload=None, timeout=self._timeout)
            if res.get("ok"):
                out["scanned"] = 1
            else:
                out["error"] = (out["error"] + "; " if out["error"] else "") + (res.get("error") or "库刷新失败")
        return out

    # ------------------------------------------------------------- 页面

    def get_page(self) -> Optional[List[dict]]:
        plan = self.__plan_data()
        report = self.get_data("last_report") or {}
        apply_result = self.get_data("last_apply") or {}
        content: List[dict] = []
        summary = plan.get("summary", {})
        content.append({"component": "VRow", "content": [
            self.__stat_card("扫描目录", summary.get("roots", 0), "mdi-folder-search"),
            self.__stat_card("视频", summary.get("videos", 0), "mdi-filmstrip"),
            self.__stat_card("字幕", summary.get("subtitles", 0), "mdi-subtitles"),
            self.__stat_card("待规范化", summary.get("pending", 0), "mdi-file-rename"),
        ]})
        content.append({"component": "VRow", "content": [
            self.__stat_card("已合规", summary.get("kept", 0), "mdi-check-decagram"),
            self.__stat_card("重复字幕", summary.get("duplicates", 0), "mdi-content-duplicate"),
            self.__stat_card("已处理", apply_result.get("applied", 0), "mdi-check"),
            self.__stat_card("失败", apply_result.get("failed", 0), "mdi-alert-circle"),
        ]})

        mode = "只预览（不写入）" if self._dry_run else "会真实改名"
        content.append({"component": "VRow", "content": [
            self.__col(12, {"component": "VAlert", "props": {
                "type": "info" if self._dry_run else "warning", "variant": "tonal",
                "text": f"当前模式：{mode} · 标签风格：{'MoviePilot 原生' if self._tag_style == 'mp' else 'chs/cht'} · "
                        f"简繁共存：{'开' if self._keep_both else '关'} · 上次扫描：{plan.get('timestamp') or '尚未扫描'}"}}),
        ]})

        rows = [[it["video"], it["subtitle"], it["lang_label"], f"{it['confidence']}（{it['source']}）",
                 it["target"], "改名"] for it in plan.get("items", [])[:50]]
        content.append(self.__table_card("待规范化清单", ("视频", "当前字幕", "判定", "依据", "目标名", "动作"),
                                         rows, md=12, caption=f"最多展示 50 条；共 {summary.get('pending', 0)} 条待处理"))

        dup_rows = [[it["video"], it["subtitle"], it["lang_label"], it.get("reason", "")]
                    for it in plan.get("duplicates", [])[:20]]
        if dup_rows:
            content.append(self.__table_card("同语言重复（不处理）", ("视频", "字幕", "判定", "说明"),
                                             dup_rows, md=6, caption="同一语言保留格式最好的一份，其余仅提示"))

        skip_rows = [[it["video"], it["subtitle"], it.get("reason", "")]
                     for it in plan.get("skipped", [])[:20]]
        if skip_rows:
            content.append(self.__table_card("已跳过", ("视频", "字幕", "原因"), skip_rows, md=6))

        done_rows = [[it["video"], it["subtitle"], it["target"]] for it in apply_result.get("done", [])[:30]]
        content.append(self.__table_card("最近已处理", ("视频", "原字幕", "新字幕"), done_rows, md=6,
                                         caption="来自上一次真实写入"))

        err_rows = [[it.get("subtitle", ""), it.get("reason", "")] for it in apply_result.get("errors", [])[:20]]
        content.append(self.__table_card("失败与跳过", ("字幕", "原因"), err_rows, md=6))

        if report.get("errors"):
            content.append({"component": "VRow", "content": [
                self.__col(12, {"component": "VAlert", "props": {"type": "warning", "variant": "tonal",
                                                                 "text": "扫描提示：" + "；".join(report["errors"][:6])}})]})
        return content

    def get_dashboard_meta(self) -> Optional[List[Dict[str, str]]]:
        if not self._dashboard:
            return None
        return [{"key": "subtitleshield", "name": "字幕规范化"}]

    def get_dashboard(self, key: str = "", **kwargs) -> Optional[Tuple[Dict[str, Any], Dict[str, Any], List[dict]]]:
        if key and key != "subtitleshield":
            return None
        plan = self.__plan_data()
        summary = plan.get("summary", {})
        widgets: List[dict] = [{"component": "VRow", "content": [
            self.__stat_card("视频", summary.get("videos", 0), "mdi-filmstrip"),
            self.__stat_card("字幕", summary.get("subtitles", 0), "mdi-subtitles"),
            self.__stat_card("待规范化", summary.get("pending", 0), "mdi-file-rename"),
            self.__stat_card("已合规", summary.get("kept", 0), "mdi-check-decagram"),
        ]}]
        widgets.append({"component": "VAlert", "props": {
            "type": "info" if self._dry_run else "warning", "variant": "tonal",
            "text": f"{'只预览' if self._dry_run else '可写入'} · 上次扫描 {plan.get('timestamp') or '未扫描'} · "
                    f"待处理 {summary.get('pending', 0)} 条"}})
        return {"cols": 12, "md": 6}, {"refresh": 30, "title": "字幕规范化"}, widgets

    @staticmethod
    def __stat_card(title: str, value: Any, icon: str) -> Dict[str, Any]:
        return {"component": "VCol", "props": {"cols": 6, "md": 3}, "content": [
            {"component": "VCard", "props": {"variant": "tonal", "class": "mb-3"}, "content": [
                {"component": "VCardText", "content": [
                    {"component": "VIcon", "props": {"icon": icon, "size": "small"}},
                    {"component": "div", "props": {"class": "text-h6"}, "text": str(value)},
                    {"component": "div", "props": {"class": "text-caption"}, "text": title},
                ]},
            ]},
        ]}

    @staticmethod
    def __table_card(title: str, headers: Tuple[str, ...], rows: List[List[Any]],
                     *, md: int = 6, caption: str = "") -> Dict[str, Any]:
        head = {"component": "thead", "content": [
            {"component": "tr", "content": [{"component": "th", "text": h} for h in headers]}]}
        body_rows = []
        for row in rows:
            body_rows.append({"component": "tr", "content": [
                {"component": "td", "props": {"class": "text-caption"}, "text": str(c)} for c in row]})
        body = {"component": "tbody", "content": body_rows}
        inner: List[dict] = []
        if title:
            inner.append({"component": "VCardTitle", "text": title})
        inner.append({"component": "VCardText", "content": [
            {"component": "VTable", "props": {"density": "compact", "hover": True}, "content": [head, body]}]})
        if caption:
            inner.append({"component": "VCardText", "props": {"class": "text-caption"}, "text": caption})
        return {"component": "VCol", "props": {"cols": 12, "md": md},
                "content": [{"component": "VCard", "props": {"variant": "tonal", "class": "mb-3"}, "content": inner}]}

    # ------------------------------------------------------------- API

    def get_api(self) -> List[Dict[str, Any]]:
        return [
            {"path": "/status", "endpoint": self.api_status, "methods": ["GET"], "auth": "bear",
             "summary": "读取最近一次扫描与处理结果"},
            {"path": "/scan", "endpoint": self.api_scan, "methods": ["POST"], "auth": "bear",
             "summary": "扫描媒体库并生成规范化计划"},
            {"path": "/apply", "endpoint": self.api_apply, "methods": ["POST"], "auth": "bear",
             "summary": "按计划执行真实改名"},
            {"path": "/refresh_emby", "endpoint": self.api_refresh_emby, "methods": ["POST"], "auth": "bear",
             "summary": "把已规范化的条目重新推给 Emby（更新视频时间戳 + 通知目录改动）"},
            {"path": "/report", "endpoint": self.api_report, "methods": ["GET"], "auth": "apikey",
             "summary": "外部集成：返回最近一次报告"},
        ]

    def api_status(self) -> Dict[str, Any]:
        return {"enabled": self._enabled, "dry_run": self._dry_run,
                "plan": self.__plan_data().get("summary", {}),
                "last_report": self.get_data("last_report"),
                "last_apply": self.get_data("last_apply")}

    def api_scan(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = payload or {}
        if payload.get("limit"):
            self._limit = max(1, min(_safe_int(payload.get("limit"), self._limit), 500))
        plan = self.build_plan()
        self.save_data("last_plan", plan)
        return {"summary": plan["summary"], "items": plan["items"][:50], "errors": plan["errors"]}

    def api_apply(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = payload or {}
        if payload.get("limit"):
            self._limit = max(1, min(_safe_int(payload.get("limit"), self._limit), 500))
        plan = self.get_data("last_plan") or self.build_plan()
        if self._dry_run and not payload.get("confirm"):
            return {"ok": False, "message": "当前处于只预览模式，请先关闭 dry_run 或传 confirm=true", "plan": plan.get("summary")}
        result = self.apply_plan(plan)
        self.save_data("last_report", {"timestamp": _now(), "scan": plan.get("summary", {}),
                                       "apply": result, "errors": plan.get("errors", [])})
        if self._notify:
            self.__notify_report(self.get_data("last_report"))
        return result

    def api_report(self) -> Dict[str, Any]:
        return self.get_data("last_report") or {"message": "尚未运行"}

    def api_refresh_emby(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = payload or {}
        touch = bool(payload.get("touch", True))
        return self.refresh_emby_all(touch=touch)

    def refresh_emby_all(self, touch: bool = True) -> Dict[str, Any]:
        """把已经规范化的目录重新推给 Emby：可选更新视频时间戳，再通知目录改动。"""
        dirs: List[str] = []
        touched = 0
        for root in self.__roots():
            if not os.path.isdir(root):
                continue
            for current, sub_dirs, files in os.walk(root):
                sub_dirs[:] = [d for d in sub_dirs if d not in _SKIP_DIRS]
                if os.path.basename(current) in _SKIP_DIRS:
                    continue
                subs = [f for f in files if os.path.splitext(f)[1].lower() in _SUB_EXTS]
                if not any(_NORMALIZED_RE.search(f) for f in subs):
                    continue
                dirs.append(current)
                if not touch:
                    continue
                for name in files:
                    if os.path.splitext(name)[1].lower() not in _VIDEO_EXTS:
                        continue
                    try:
                        os.utime(os.path.join(current, name), None)
                        touched += 1
                    except Exception as e:
                        logger.debug(f"{self.plugin_name}：更新时间戳失败 {name} {e}")
        dirs = sorted(set(dirs))
        res = self.__refresh_emby(dirs) if dirs else None
        out = {"timestamp": _now(), "dirs": len(dirs), "touched": touched, "emby": res}
        self.save_data("last_refresh", out)
        logger.info(f"{self.plugin_name}：已刷新 Emby，目录 {len(dirs)} 个，时间戳更新 {touched} 个")
        return out

    # ------------------------------------------------------------- 命令

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        if EventType is None:
            return []
        return [
            {"cmd": "/subtitleguard", "event": EventType.PluginAction, "desc": "查看字幕规范化状态与待处理数量",
             "category": "插件命令", "data": {"action": "subtitleshield_status"}},
            {"cmd": "/subtitleguard_scan", "event": EventType.PluginAction,
             "desc": "扫描媒体库（可加数量，如 /subtitleguard_scan 10）", "category": "插件命令",
             "data": {"action": "subtitleshield_scan"}},
            {"cmd": "/subtitleguard_apply", "event": EventType.PluginAction,
             "desc": "执行真实改名（可加数量，如 /subtitleguard_apply 10）", "category": "插件命令",
             "data": {"action": "subtitleshield_apply"}},
            {"cmd": "/subtitleguard_refresh", "event": EventType.PluginAction,
             "desc": "把已规范化的条目重新推给 Emby（更新视频时间戳 + 目录改动通知）", "category": "插件命令",
             "data": {"action": "subtitleshield_refresh"}},
        ]

    def run_command(self, event: Any) -> None:
        data = getattr(event, "event_data", None) or {}
        action = str(data.get("action") or "")
        if not action.startswith("subtitleshield_"):
            return
        name = action[len("subtitleshield_"):]
        arg = str(data.get("arg_str") or data.get("text") or "").strip()
        if name == "status":
            plan = self.__plan_data()
            s = plan.get("summary", {})
            text = (f"字幕规范化：{'只预览' if self._dry_run else '可写入'}\n"
                    f"视频 {s.get('videos', 0)} · 字幕 {s.get('subtitles', 0)} · 待处理 {s.get('pending', 0)} · "
                    f"已合规 {s.get('kept', 0)}\n上次扫描：{plan.get('timestamp') or '尚未扫描'}")
            self.__message("字幕规范化状态", text)
            return
        if name == "scan":
            if arg:
                self._limit = max(1, min(_safe_int(arg, self._limit), 500))
            plan = self.build_plan()
            self.save_data("last_plan", plan)
            s = plan["summary"]
            self.__message("字幕扫描完成",
                           f"视频 {s['videos']} · 字幕 {s['subtitles']} · 待规范化 {s['pending']} · 已合规 {s['kept']}")
            return
        if name == "apply":
            if arg:
                self._limit = max(1, min(_safe_int(arg, self._limit), 500))
            plan = self.get_data("last_plan") or self.build_plan()
            if self._dry_run:
                self.__message("字幕规范化未执行", "当前是只预览模式，请先在插件设置里关闭「只预览不写入」。")
                return
            result = self.apply_plan(plan)
            self.__message("字幕规范化完成",
                           f"改名 {result['applied']} 条，失败 {result['failed']} 条"
                           + (f"，Emby：{result.get('emby')}" if result.get("emby") else ""))
            return
        if name == "refresh":
            if not self._emby_enabled:
                self.__message("Emby 未启用", "请先在插件设置里打开「刷新 Emby」并填好地址与 API Key。")
                return
            res = self.refresh_emby_all(touch=True)
            self.__message("Emby 刷新完成",
                           f"目录 {res['dirs']} 个 · 时间戳更新 {res['touched']} 个 · Emby：{res.get('emby')}")
            return

    # ------------------------------------------------------------- 内部

    def __plan_data(self) -> Dict[str, Any]:
        plan = self.get_data("last_plan")
        if isinstance(plan, dict) and plan.get("summary") is not None:
            return plan
        return {"summary": {}, "items": [], "kept": [], "timestamp": "", "errors": []}

    def __roots(self) -> List[str]:
        out: List[str] = []
        for part in re.split(r"[\n,;]+", self._media_roots or ""):
            part = part.strip()
            if not part:
                continue
            if part not in out:
                out.append(part)
        return out

    def __cron_trigger(self, expr: str) -> Any:
        if not expr:
            return None
        try:
            from importlib import import_module

            cron_cls = None
            for mod_name in ("app.sdk.scheduler", "apscheduler.triggers.cron"):
                try:
                    mod = import_module(mod_name)
                    cron_cls = getattr(mod, "CronTrigger", None)
                    if cron_cls:
                        break
                except Exception:
                    continue
            if cron_cls is None:
                logger.warning(f"{self.plugin_name}：宿主缺少 CronTrigger，定时扫描改为每天一次")
                return None
            return cron_cls.from_crontab(expr)
        except Exception as e:
            logger.warning(f"{self.plugin_name}：cron 表达式无效 {expr}（{e}），改为每天一次")
            return None

    def __schedule_once(self) -> None:
        if not add_plugin_once_job:
            self.scan_and_apply()
            return
        try:
            add_plugin_once_job(plugin_id=self.__class__.__name__,
                                job_id=f"{self.__class__.__name__}Once",
                                func=self.scan_and_apply, name=self.plugin_name, delay_seconds=3)
        except Exception as e:
            logger.error(f"{self.plugin_name}：创建一次性任务失败 {e}")

    def __update_config(self) -> None:
        try:
            self.update_config({
                "enabled": self._enabled, "notify": self._notify, "onlyonce": False,
                "dashboard": self._dashboard, "media_roots": self._media_roots, "scan_cron": self._scan_cron,
                "dry_run": self._dry_run, "auto_apply": self._auto_apply, "limit": self._limit,
                "tag_style": self._tag_style, "keep_both": self._keep_both, "default_sub": self._default_sub,
                "prefer_format": self._prefer_format, "content_detect": self._content_detect,
                "min_chars": self._min_chars,
                "emby_enabled": self._emby_enabled, "emby_url": self._emby_url,
                "emby_apikey": self._emby_apikey, "emby_refresh_mode": self._emby_refresh_mode,
                "timeout": self._timeout, "max_depth": self._max_depth,
            })
        except Exception as e:
            logger.warning(f"{self.plugin_name}：保存配置失败 {e}")

    def __message(self, title: str, text: str) -> None:
        try:
            mtype = getattr(NotificationType, "Plugin", None) if NotificationType else None
            self.post_message(mtype=mtype, title=title, text=text)
        except Exception as e:
            logger.warning(f"{self.plugin_name}：发送消息失败 {e}")

    def __notify_report(self, report: Dict[str, Any]) -> None:
        try:
            s = report.get("scan") or {}
            a = report.get("apply") or {}
            lines = [f"视频 {s.get('videos', 0)} · 字幕 {s.get('subtitles', 0)} · 待规范化 {s.get('pending', 0)}"]
            if a:
                lines.append(f"本次改名 {a.get('applied', 0)} 条，失败 {a.get('failed', 0)} 条")
                if a.get("emby"):
                    lines.append(f"Emby：{a['emby']}")
            else:
                lines.append("当前为只预览模式，未写入文件")
            self.__message("字幕规范化报告", "\n".join(lines))
        except Exception as e:
            logger.warning(f"{self.plugin_name}：发送报告失败 {e}")


# --------------------------------------------------------------------- 常量

_SKIP_DIRS = {"@eaDir", "#recycle", "System Volume Information", ".git", "__pycache__", ".Trash"}

_VIDEO_EXTS = {".mkv", ".mp4", ".avi", ".ts", ".m2ts", ".mov", ".wmv", ".flv", ".webm", ".rmvb", ".iso", ".m4v"}
_SUB_EXTS = {".srt", ".ass", ".ssa", ".vtt", ".sub", ".idx", ".sup", ".smi", ".lrc"}
# 已规范化的字幕名（本插件产出的目标名）
_NORMALIZED_RE = re.compile(r"(?:\.default)?\.(?:chi\.zh-cn|zh-tw|chs|cht)\.[a-z0-9]+$", re.I)

_TAG_STYLE_OPTIONS = [{"title": "MoviePilot 原生（.chi.zh-cn / .zh-tw）", "value": "mp"},
                      {"title": "chs / cht", "value": "chs_cht"}]
_EMBY_MODE_OPTIONS = [{"title": "只刷新改动条目（item）", "value": "item"},
                      {"title": "库扫描（library）", "value": "library"},
                      {"title": "两者都做（both）", "value": "both"}]

_TAG_MP = {"zh_cn": "chi.zh-cn", "zh_tw": "zh-tw", "ja": "ja", "en": "eng", "bilingual": "chi.zh-cn"}
_TAG_CHS = {"zh_cn": "chs", "zh_tw": "cht", "ja": "ja", "en": "en", "bilingual": "chs"}
_LANG_LABELS = {"zh_cn": "简体中文", "zh_tw": "繁体中文", "ja": "日语", "en": "英语",
                "bilingual": "中英双语", "unknown": "未识别"}

_NAME_PATTERNS = [
    ("zh_tw", re.compile(r"(?i)(zh[-_.]?tw|zh_tw|cht\b|big5|繁|台灣|台湾|tc\b)")),
    ("zh_cn", re.compile(r"(?i)(zh[-_.]?cn|zh_cn|chi\.zh|chs\b|gb\b|简|简体|sc\b)")),
    ("ja", re.compile(r"(?i)(\bja\b|\bjpn\b|japanese|日文|日语|日語|日字幕)")),
    ("en", re.compile(r"(?i)(\beng\b|\benglish\b|英文|英语|英語)")),
]

# 弱标识：站内抽流常用 zh-Hans / zh-Hant，实测经常标错，正文能判出来时以正文为准
_SOFT_NAME_PATTERNS = [
    ("zh_tw", re.compile(r"(?i)(zh[-_.]?hant|hant\b)")),
    ("zh_cn", re.compile(r"(?i)(zh[-_.]?hans|hans\b)")),
]

# 常用简繁字对（左简右繁），用于内容判定
_SIMP_TRAD_PAIRS = (
    "这這 说說 时時 会會 个個 们們 为為 国國 门門 问問 间間 关關 开開 后後 里裡 发發 现現 学學 "
    "对對 过過 还還 让讓 将將 从從 给給 与與 无無 边邊 动動 务務 车車 长長 马馬 鸟鳥 鱼魚 "
    "书書 画畫 听聽 见見 电電 话話 语語 读讀 写寫 记記 认認 识識 论論 议議 试試 谁誰 请請 "
    "谢謝 变變 应應 该該 实實 际際 际際 类類 总總 数數 据據 统統 计計 结結 果實 务務 员員 "
    "单單 双雙 张張 条條 极極 术術 业業 东東 两兩 严嚴 丧喪 丰豐 临臨 义義 乌烏 乐樂 乔喬 "
    "习習 乡鄉 买買 乱亂 争爭 亏虧 产產 亿億 仅僅 仓倉 仪儀 价價 众眾 优優 伟偉 传傳 伤傷 "
    "侦偵 侧側 储儲 儿兒 兰蘭 兴興 养養 兽獸 内內 军軍 农農 冲沖 决決 况況 冻凍 净淨 减減 "
    "凤鳳 划劃 则則 刚剛 创創 别別 剂劑 劝勸 办辦 势勢 勋勳 医醫 华華 协協 单單 卖賣 卫衛 "
    "厂廠 历歷 压壓 厌厭 县縣 参參 双雙 发發 变變 叶葉 号號 叹嘆 吓嚇 吗嗎 员員 哪 响響 "
    "启啟 呜嗚 员員 哑啞 唤喚 啰囉 喷噴 嘱囑 团團 园園 围圍 图圖 圆圓 圣聖 场場 坏壞 块塊 "
    "坚堅 坝壩 坟墳 垄壟 垒壘 垦墾 埋 堕墮 墙牆 壮壯 声聲 壳殼 处處 备備 复復 够夠 头頭 "
    "夹夾 夺奪 奋奮 奖獎 妆妝 妇婦 妈媽 娱娛 婴嬰 媳 嫌 孙孫 宁寧 宝寶 审審 宪憲 宫宮 宽寬 "
    "宾賓 对對 寻尋 导導 寿壽 将將 尔爾 尘塵 尽盡 层層 屡屢 属屬 岛島 岂豈 岁歲 岂 岗崗 "
    "币幣 帅帥 师師 帐帳 带帶 帮幫 幸 广廣 庆慶 库庫 应應 废廢 开開 异異 弃棄 弥彌 弯彎 "
    "归歸 当當 录錄 彻徹 径徑 徕徠 忆憶 忏懺 忧憂 怀懷 态態 怜憐 总總 恋戀 恳懇 恶惡 恼惱 "
    "悦悅 悬懸 惊驚 惧懼 惨慘 惩懲 惫憊 惭慚 惯慣 愿願 慑懾 懒懶 戏戲 战戰 户戶 扑撲 执執 "
    "扩擴 扫掃 扬揚 扰擾 抚撫 抛拋 抢搶 护護 报報 担擔 拟擬 拢攏 拣揀 拥擁 拨撥 择擇 挂掛 "
    "挥揮 捞撈 损損 换換 据據 掳擄 掺摻 掷擲 揽攬 撑撐 撵攆 擞擻 敌敵 敛斂 数數 斋齋 斗鬥 "
    "斩斬 断斷 无無 旧舊 时時 旷曠 昙曇 显顯 晒曬 晓曉 晕暈 暂暫 术術 机機 杀殺 杂雜 权權 "
    "条條 来來 杨楊 极極 构構 枢樞 枪槍 枫楓 柜櫃 标標 栈棧 栏欄 树樹 样樣 桥橋 档檔 桧檜 "
    "梦夢 检檢 棂欞 楼樓 楼 榄欖 榈櫚 榉櫸 槚檟 槛檻 槟檳 槠櫧 横橫 樯檣 橥櫫 橹櫓 橼櫞 檩檁 "
    "欢歡 欤歟 欧歐 歼殲 殁 殇殤 残殘 殒殞 殓殮 殚殫 殡殯 殴毆 毁毀 毂轂 毕畢 毙斃 毡氈 "
)

_SIMP_SET = set()
_TRAD_SET = set()
for _pair in _SIMP_TRAD_PAIRS.replace("\n", " ").split():
    if len(_pair) == 2:
        _SIMP_SET.add(_pair[0])
        _TRAD_SET.add(_pair[1])
del _SIMP_TRAD_PAIRS


# --------------------------------------------------------------------- 工具

def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def _safe_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def _norm_url(url: str) -> str:
    url = (url or "").strip()
    while url.endswith("/"):
        url = url[:-1]
    return url


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _stem_linked(video_stem: str, sub_name: str) -> bool:
    base = os.path.splitext(sub_name)[0]
    if base == video_stem:
        return True
    short = min(len(video_stem), len(base))
    if short < 6:
        return False
    return video_stem[:short].lower() == base[:short].lower()


_SE_RE = re.compile(r"(?i)\bS(\d{1,2})[ ._-]?E(\d{1,3})\b")
_EP_RE = re.compile(r"(?i)\b(\d{1,2})x(\d{2,3})\b")
_YEAR_RE = re.compile(r"(?:^|[.\s_\[(])((?:19|20)\d{2})(?:[.\s_\])]|$)")
_STRIP_TOKENS = re.compile(
    r"(?i)(2160p|1080p|720p|480p|4k|uhd|bluray|blu-ray|web-?dl|webrip|hdtv|hdr|dv|hevc|x265|x264|h264|"
    r"aac|ac3|ddp?5[.\s]?1|dts(-hd)?(ma)?|truehd|atmos|remux|proper|repack|10bit|8bit|multi|chs|cht|eng)")


def _pair_key(filename: str) -> str:
    """把视频/字幕名归一成配对键：剧集用 SxxExx，电影用标题+年份。"""
    base = os.path.splitext(filename)[0]
    m = _SE_RE.search(base) or _EP_RE.search(base)
    if m:
        season = int(m.group(1))
        episode = int(m.group(2))
        return f"S{season:02d}E{episode:02d}"
    cleaned = _STRIP_TOKENS.sub(" ", base)
    cleaned = re.sub(r"[\[\](){}._-]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    year = ""
    ym = _YEAR_RE.search(base)
    if ym:
        year = ym.group(1)
    return f"{cleaned}|{year}"


def _fmt_rank(ext: str, prefer: List[str]) -> int:
    try:
        return prefer.index(ext)
    except ValueError:
        return len(prefer)


def _lang_from_name(name: str) -> Tuple[str, str, str]:
    """文件名判语种：强标识（chs/cht/zh-cn/简/繁）优先，弱标识（zh-Hans/zh-Hant）留给正文覆盖。"""
    text = name.lower()
    for lang, pattern in _NAME_PATTERNS:
        if pattern.search(text):
            return lang, f"文件名含 {lang} 标识", "high"
    for lang, pattern in _SOFT_NAME_PATTERNS:
        if pattern.search(text):
            return lang, f"文件名含 {lang} 中文标识（弱）", "low"
    return "unknown", "文件名无语言标识", "none"


def _decode_text(raw: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "gb18030", "big5", "utf-8"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="ignore")


def _strip_subtitle_markup(text: str) -> str:
    text = re.sub(r"\{[^}]*\}", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"(?im)^\s*(dialogue|comment|format|style)[:：].*$", " ", text)
    text = re.sub(r"(?m)^\s*\d+\s*$", " ", text)
    text = re.sub(r"(?m)^\s*\d{2}:\d{2}:\d{2}[,.]\d{3}\s*-->.*$", " ", text)
    return text


def _is_kana(ch: str) -> bool:
    code = ord(ch)
    return 0x3040 <= code <= 0x30FF


_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


def _http_json(method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
               payload: Optional[Dict[str, Any]] = None, timeout: float = 10.0) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": False, "status": 0, "data": None, "error": ""}
    data = None
    hdrs = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(url=url, data=data, headers=hdrs, method=method.upper())
    try:
        with urlrequest.urlopen(req, timeout=timeout, context=_SSL_CONTEXT) as resp:
            out["status"] = resp.status
            body = resp.read()
            out["ok"] = 200 <= resp.status < 300
            if body:
                try:
                    out["data"] = json.loads(body.decode("utf-8", "ignore"))
                except Exception:
                    out["text"] = body.decode("utf-8", "ignore")[:500]
    except Exception as e:
        out["error"] = str(e)
    return out
