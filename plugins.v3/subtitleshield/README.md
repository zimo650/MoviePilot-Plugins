# 字幕规范化（SubtitleShield）

把已经下载到媒体库的外挂字幕统一成 MoviePilot 原生风格的命名，并在缺失语言标签时用**字幕正文**判断简体/繁体。

MoviePilot 自己只在整理时按**文件名**识别语种（`transhandler.py` 的 `__rename_subtitles`）：文件名里没有 `zh-cn`/`zh-tw`/`chs`/`cht`/`简体`/`繁体` 等标记时，产出的就是 `视频名.srt`，Emby 只能显示「未知语言」。而站点字幕、字幕组成品、第三方插件写入的字幕经常就是这样——所以需要一个「事后统一」的工具。

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 内容级简繁判定 | 文件名优先（`zh-cn`/`chi.zh`/`chs`/`gb`/`简` → 简中，`zh-tw`/`cht`/`big5`/`繁` → 繁中，`ja`/`eng` 同理）；`zh-Hans`/`zh-Hant` 这类站内抽流标签只当**弱标识**，正文能判出简繁时以正文为准；正文判定会读 UTF-8/UTF-16/GB18030/Big5 编码，用简繁字对统计比例，并记录判定依据与置信度 |
| 不误伤未知语种 | 语言确实识别不出来时**不改名**，只在「已跳过」里提示，避免把仅有的一点标签信息改丢 |
| 与视频同名 | 目标名严格用「视频去扩展名 + 语言标签 + 原扩展名」，例：`Show S01E01 1080p.WEB-DL.default.chi.zh-cn.ass` |
| 跨主干名配对 | 字幕与视频的主干名不一致（例如视频 `1080p.BluRay.AVC`、字幕 `1080p.BluRay.x265`）也能配对：优先用 `SxxExx` / `1x02` 归一，其次才用「标题+年份」 |
| 简繁共存 | 默认两份都保留（`.chi.zh-cn` + `.zh-tw`），可关闭只留默认语言 |
| 不碰视频 | 只重命名字幕文件，视频、nfo、图片、mediainfo 一律不动 |
| 同语言去重 | 同一语言有多份字幕（或目标文件已存在）时，默认只提示、不改名，避免目标重名互相覆盖；打开 `dedupe_duplicates` 后只保留格式最优的一份（默认优先 `ass`，并优先 `.default`），其余真实删除，并在页面/计划里单列「将删除的多余字幕」 |
| Emby 刷新 | 支持条目级（`POST /Library/Media/Updated`）、库级（`POST /Library/Refresh`）或两者 |
| 定时与试跑 | `dry_run` 默认开启（只出计划不改文件），`limit` 默认 10 条，可先用少量样本验证 |
| 历史库批量 | 扫描媒体库目录（不是下载目录），把历史遗留的不规范字幕一起统一 |
| 下载完成即处理 | 订阅 MoviePilot 的 `TransferComplete` / `SubtitleTransferComplete` 事件：整理完成或字幕落盘后，只对事件涉及的目录做一次规范化并刷新 Emby（`event_enabled` 可关） |

命名风格可切换：`tag_style=mp`（默认，`chi.zh-cn`/`zh-tw`，与 MoviePilot 一致）、`tag_style=chs_cht`（`chs`/`cht`）。

## 安装

1. MoviePilot → 设置 → 插件市场，添加仓库 `https://github.com/zimo650/MoviePilot-Plugins`（已添加过可跳过）。
2. 刷新市场，搜索「字幕规范化」或插件 ID `SubtitleShield`，安装并启用。

## 升级（重要）

MoviePilot 的 `plugin.install` 在插件已存在时，会把**已安装目录本身**当成“本地候选”去同步，于是反复提示「安装成功」但版本不变（市场索引里的 `has_update` 是 true 也没用）。要真正升级，按下面顺序做一次：

1. 插件管理里先 **卸载** SubtitleShield；
2. 删除容器内这两个目录（可用 MoviePilot 的文件管理/`storage` 接口，或进容器 `rm -rf`）：
   - `/app/app/plugins/subtitleshield`
   - `/config/plugins_backup/subtitleshield`
3. 回到插件市场点安装（`plugin.install` 带上仓库地址 `repo_url`），装完确认版本号；
4. 重启一次 MoviePilot，让下载完成事件的钩子重新注册。

本仓库附带 `devtools/update_mp.py` 把这套流程串成一条命令（市场刷新 → 安装 → 校验版本 → 不符则自动卸载并清理目录后重装）。

## 配置项

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `media_roots` | 空 | 要扫描的媒体库目录，多个用英文逗号分隔，例：`/video/downloads/link/movie,/video/downloads/link/tv` |
| `scan_cron` | `0 4 * * *` | 定时扫描的 cron（五段式）；宿主缺少 CronTrigger 时自动退化为每 24 小时 |
| `dry_run` | 开 | 只生成计划不改文件；关闭后才会真正重命名 |
| `limit` | 10 | 单次最多处理多少条字幕（试跑用） |
| `event_enabled` | 开 | 整理完成 / 字幕落盘完成后，立即规范化事件涉及的那个目录（只处理新入库内容）。事件处理同样遵守 `dry_run` 与 `auto_apply`：两者都允许写入时才真正改名，否则只记录计划 |
| `tag_style` | `mp` | `mp`：`chi.zh-cn`/`zh-tw`；`chs`：`chs`/`cht` |
| `keep_both` | 开 | 简体与繁体都保留；关闭时只留默认语言 |
| `default_sub` | `zh-cn` | 命中的语言前面加 `.default` 前缀（与 MoviePilot 的 `DEFAULT_SUB` 一致） |
| `prefer_format` | `ass,srt,ssa,vtt,sup` | 同一语言多格式时的优先级 |
| `dedupe_duplicates` | 关 | 同一语言有多份字幕时，只保留格式最优的一份，其余**真实删除**（默认关闭，只在页面提示）；删除不可恢复，建议先看计划 |
| `dedupe_keep_default` | 开 | 去重时优先保留带 `.default` 的那份（与 `default_sub` 配合） |
| `max_files` | 200000 | 单次扫描最多遍历多少个文件（防止超大库把任务拖住） |
| `auto_apply` | 关 | 定时扫描时是否自动执行改名（关闭时定时任务只生成计划） |
| `content_detect` | 开 | 文件名没线索时读正文判断简繁 |
| `min_chars` | 20 | 正文有效字符数少于此值不做内容判定 |
| `emby_enabled` / `emby_url` / `emby_apikey` | 空 | Emby 地址与 API Key |
| `emby_refresh_mode` | `item` | `item` 条目级、`library` 库级、`both` 两者 |
| `emby_path_map` | 空 | 路径映射，MoviePilot 容器路径 → Emby 看到的路径，一行一条或多条用逗号分隔，例：`/video/downloads/link/movie:/data/movie,/video/downloads/link/tv:/data/tv`。两个容器的挂载点不同时必须填，否则 Emby 收到的是它不认识的路径 |
| `emby_touch` | 开 | 改名后 `utime` 更新一次视频文件时间戳：Emby 的增量扫描只看媒体文件的变化，不动视频就不会重新探测外挂字幕 |
| `max_depth` | 4 | 目录递归深度 |
| `timeout` | 10 | HTTP 超时（秒） |
| `notify` | 开 | 扫描/执行结果推送到 MoviePilot 通知渠道 |
| `dashboard` | 开 | 是否提供仪表板卡片 |

## 远程命令

| 命令 | 说明 |
| --- | --- |
| `/subtitleguard` | 查看上次扫描摘要 |
| `/subtitleguard_scan [n]` | 生成计划（只读，不改文件），可选覆盖条数 |
| `/subtitleguard_apply [n]` | 按计划真正改名；`dry_run` 未关闭时会拒绝并提示 |
| `/subtitleguard_refresh` | 把已规范化的条目重新推给 Emby（更新视频时间戳 + 通知目录改动），用于历史改名后 Emby 仍显示旧语言 |

## REST API

路径前缀 `/api/v1/plugin/SubtitleShield`：

| 方法 | 路径 | 鉴权 | 说明 |
| --- | --- | --- | --- |
| GET | `/status` | bear | 最近一次扫描摘要与配置状态 |
| POST | `/scan` | bear | 生成计划（body 可带 `limit`） |
| POST | `/apply` | bear | 执行计划；`dry_run` 未关闭时需 body 带 `confirm: true` |
| POST | `/refresh_emby` | bear | 把已规范化的目录重新推给 Emby；body 可带 `touch: false` 只通知不改时间戳 |
| GET | `/report` | apikey | 生成文本报告（便于脚本或通知使用） |

## 页面

所有卡片统一成同一套样式（同一图标位置、同一标题字号、同一间距，宽度只用 3/4/6/12 四档），空表也会给出占位文案，不会出现半张空卡片。页面包含：

- 8 张统计卡：扫描目录、视频数、字幕数、待规范化、已合规、同语言重复、已处理、失败。
- 模式提示：当前是否只预览、单次上限、命名风格、删多余同语言是否开启。
- **待规范化清单**：视频 / 当前字幕 / 判定语言 / 依据 / 目标文件名 / 动作。
- **将删除的多余字幕**（`dedupe_duplicates` 开启时）或**同语言重复（仅提示）**。
- **已跳过**、**最近已处理**、**失败与跳过**。

## 已知限制

1. 只处理**已存在**的外挂字幕，不负责下载字幕（下载请用 MoviePilot 内置字幕或字幕类插件）。
2. 语言判定依赖简繁字对表，纯英文/日文字幕只在文件名有线索时归类；正文判定置信度低时会标注 `low`。
3. `keep_both` 关闭后，被丢弃的语言只会进「已跳过」列表，不会自动删除文件。
4. `dry_run` 默认开启，首次使用请先 `/subtitleguard_scan` 看计划，确认无误再关掉试跑少量。
5. Emby 条目级刷新依赖 Emby 允许 `POST /Library/Media/Updated`；部分旧版本可用库级刷新替代。
6. **Emby 侧要看到新语言标签，`emby_path_map` 必须填对**：MoviePilot 容器里是 `/video/downloads/link/...`，Emby 容器里往往是 `/data/movie/...`，路径对不上时 Emby 收不到改动；同时建议保持 `emby_touch` 开启，否则只改字幕文件名不会触发 Emby 重新探测。
7. 重命名是**原地改名**，不改变文件内容；如需回退，请以扫描计划里的「当前字幕」列为准手工改回。
8. 下载完成事件的注册发生在插件加载时，**安装或升级插件后需要重启一次 MoviePilot（或重载插件）**钩子才会挂上；事件只处理 `media_roots` 范围内的目录。
9. `dedupe_duplicates` 打开后删除是**真实删除、不可恢复**；第一次用建议先保持关闭看一轮计划，确认删的是多余副本再打开。
10. 升级不走「点安装/更新」就会一直装回旧版本（MoviePilot 会把已装目录当本地候选），请按上面「升级」一节的步骤操作。
