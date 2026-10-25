# MoviePilot 插件仓库（zimo650）

个人维护的 [MoviePilot V3](https://github.com/jxxghp/MoviePilot) 插件仓库。

## 插件列表

| 插件 ID | 名称 | 版本 | 说明 |
| --- | --- | --- | --- |
| `OpenClashMonitor` | OpenClash 监控 | 0.4.0 | 在 MoviePilot 里监控 OpenClash（Mihomo/Clash Meta）与 LocalDNS 的运行状态、节点与订阅、上游 DNS 健康、查询日志与版本更新；支持页面内嵌 zashboard、一键切换代理组、定时报告推送 Telegram/QQ/企业微信、趋势曲线与异常提醒 |
| `SubtitleShield` | 字幕规范化 | 0.1.5 | 统一媒体库外挂字幕命名：文件名优先、正文兜底判断简繁，重命名成与视频同名并带 `chi.zh-cn`/`zh-tw` 标签，支持简繁共存、同语言去重提示、历史库批量规范化、下载完成即处理与 Emby 条目/库刷新 |

---

# OpenClash 监控

在 MoviePilot 里集中查看 OpenWrt（iStoreOS / OpenWrt）上 OpenClash（Mihomo / Clash Meta 内核）与 LocalDNS 的运行状况。

已在真实设备验证：iStoreOS + OpenClash `v0.48.002` + Mihomo `alpha-gbc76c13` + LocalDNS `FJGOE / 2026.10.23.2`。

## 能监控什么

| 分类 | 内容 | 数据来源 |
| --- | --- | --- |
| 运行状态 | 运行/停止、运行模式（fake-ip / redir-host / tun 等）、规则模式（rule/global/direct）、CPU、负载、内存、活动连接数、累计上下行 | LuCI `status` + `toolbar_show`，缺失时回退 Clash API |
| 节点信息 | 策略组列表、每组当前选择、成员数、在线数；每个节点的机场来源、类型、最新延迟、状态（正常/超时/未测速/离线） | Clash API `/proxies` + `/providers/proxies` |
| 订阅信息 | 每个配置文件的订阅 HTTP 状态、已用/总量/剩余流量、剩余天数、使用率 | LuCI `sub_info_get` + `config_name` |
| 版本更新 | OpenClash 插件版本、Meta 内核版本，与上游最新版对比并标注「可更新」 | LuCI `update` + `last_version` |
| LocalDNS | 运行状态、核心与 UI 版本、更新通道、监听地址、累计查询、拦截量与拦截率、缓存命中、屏蔽规则数、进程 CPU/内存/运行时长 | LocalDNS `/api/v1/status` + `/metrics` |
| 上游 DNS 健康 | 按分组（domestic / foreign / foreign_ecs / proxy）列出每个上游的协议、请求数、失败数、超时数、平均延迟、最近一次错误 | LocalDNS `/api/v1/status` 的 `upstream_stats` |
| 查询日志 | 最近查询的时间、域名、类型、客户端、拦截/放行、耗时、响应码 | LocalDNS `/api/v1/querylog/entries` |
| 主动探测 | 由 MoviePilot 直接向指定上游 DNS 发 UDP 查询，测量真实延迟与解析结果 | 内置 UDP 客户端，不依赖任何接口 |
| 趋势曲线 | 节点在线数/总数、拦截率与上游平均延迟的历史曲线（按小时聚合） | 每次采集写入快照的 `trend` 字段 |
| 异常提醒 | 采集失败、节点掉线比例超阈值、某条上游 DNS 连续失败、订阅即将到期或已过期 | 采集结果 + 通知渠道 |
| 一键操作 | 启动/停止/重启 OpenClash、切换规则模式、切换策略组节点、清理 DNS/Fake-IP 缓存、关闭全部连接、切换配置文件 | 远程命令 + REST API（页面只读，见下文） |
| 内嵌面板 | 插件页里直接嵌入 zashboard，可在面板里切代理组、看连接与延迟 | zashboard 地址 + iframe（`html` 节点） |
| 页面快捷切换 | 不用打开 zashboard，直接在插件页点按钮切规则模式、切策略组节点 | 页面 `events.click` → `POST /action_web` |
| 定时报告 | 按 cron 把状态/节点/订阅/版本/DNS/告警汇总推送到 Telegram、QQ 或企业微信 | 调度任务 + `post_message(channel=...)` |
| Clash 内置 DNS | enhanced-mode（fake-ip/redir-host）、nameserver、fallback、fake-ip-range | Clash API `/configs` |

> 三路数据源互相独立：**Clash API 是必须的**（节点、运行状态、Clash DNS 都靠它）；**LuCI 是可选的**（只有订阅流量和插件/内核版本需要它）；**LocalDNS 也是可选的**（查询日志、上游健康与版本）。缺哪一路，其余部分照常工作，页面上会明确提示缺失原因。

## 安装

```bash
cd /path/to/MoviePilot-Plugins
cp -r openclashmonitor plugins.v3/
```

重启 MoviePilot，在「插件」里找到「OpenClash 监控」安装/启用即可。
如果要发布到插件市场，还需要把本目录 `package.v3.json` 里的 `OpenClashMonitor` 条目合并进仓库根目录的索引文件。

## 配置

| 配置项 | 说明 |
| --- | --- |
| 启用插件 | 定时采集开关 |
| 显示首页仪表板 | 是否在首页展示监控面板 |
| 版本更新时通知 | 内核/插件/LocalDNS 有新版本时发一条通知（同一版本只发一次） |
| Clash API 地址 | 形如 `http://192.168.1.1:9090`。留空时尝试用 LuCI 返回的 IP + `cn_port` 自动推断 |
| Clash API 密钥 | `external-controller` 的 `secret`。留空时尝试用 LuCI `status` 里的 `dase`（老版本 OpenClash） |
| 路由器地址 | 形如 `http://192.168.1.1`，用于订阅流量与版本更新。没有 LuCI 访问时留空 |
| LuCI Cookie | 已登录浏览器里复制 `sysauth_http=...`，优先级高于账号密码 |
| LuCI 用户名 / 密码 | 用于自动登录，需路由器允许 `/cgi-bin/luci` 外部访问 |
| LocalDNS 类型 | `localdns`（yyhoworks 的 LocalDNS，推荐）/ `adguard`（AdGuard Home）/ `none` |
| LocalDNS 地址 | 形如 `http://192.168.1.1:19099`（LocalDNS 默认 API 端口 19099） |
| 从 GitHub 检查版本 | 是否读取 LocalDNS 的 GitHub releases 与本地版本比较 |
| AdGuard 地址 / 用户名 / 密码 | 形如 `http://192.168.1.1:3000`，走 Basic Auth（仅 `dns_mode=adguard` 时使用） |
| AdGuard 上游测速 | 是否调用 `test_upstream_dns`（会向上游真实发包，耗时约数秒） |
| 主动探测目标 | 逗号分隔，如 `223.5.5.5,119.29.29.29,1.1.1.1`；支持 `host:port` |
| 主动探测域名 | 探测时查询的域名，默认 `www.google.com` |
| 采集间隔 | 分钟，默认 10 |
| 节点显示上限 | 页面上最多列多少个节点，默认 15（总数仍按实际数量统计） |
| 查询日志条数 | 最多展示多少条查询日志，默认 20 |
| 请求超时 | 秒，默认 8 |
| 启用一键操作 | 关闭后所有操作命令与 `/action` 接口都会被拒绝 |
| 趋势保留天数 | 趋势点保留多少天，默认 7（按小时聚合，最多 336 点） |
| 启用异常提醒 | 关闭后只在页面展示告警，不推送通知 |
| 掉线比例阈值(%) | 节点掉线超过该比例时告警，默认 60 |
| 上游失败次数阈值 | 单条上游累计失败/超时达到该次数时告警，默认 3 |
| 订阅到期提醒(天) | 剩余天数小于等于该值时告警，默认 7（0 表示已过期也告警） |
| 告警冷却(分钟) | 同一条告警在多久内不重复推送，默认 180 |
| zashboard 面板地址 | 形如 `http://192.168.1.1:7116/`；留空则不显示内嵌面板 |
| 面板高度(px) | 内嵌 iframe 的高度，默认 760 |
| 启用定时报告 | 按 cron 主动推送监控报告 |
| 定时表达式 | 五段式 cron（分 时 日 月 周），默认 `0 9 * * *` |
| 通知渠道 | Telegram / QQ / 企业微信，可多选；留空跟随 MoviePilot 默认路由 |
| 报告节点数 | 报告里列出最快的几个节点，默认 5 |

### 一键操作、趋势与异常提醒

Vuetify 详情页是只读渲染，所以「一键操作」通过**远程命令**和**REST API** 触发，页面上有一张说明卡列出全部用法：

| 操作 | 远程命令 | API body |
| --- | --- | --- |
| 重启 / 启动 / 停止 | `/openclash_restart`、`/openclash_start`、`/openclash_stop` | `{"action":"restart","confirm":true}` |
| 切换规则模式 | `/openclash_rule rule`（`rule`/`global`/`direct`） | `{"action":"rule","value":"global"}` |
| 切换节点 | `/openclash_node 组名 节点名` | `{"action":"node","group":"节点选择","value":"香港 01"}` |
| 清理 DNS/Fake-IP 缓存 | `/openclash_flush` | `{"action":"flush"}` |
| 关闭全部连接 | — | `{"action":"close","confirm":true}` |
| 切换配置文件 | — | `{"action":"switch_config","value":"config.yaml","confirm":true}` |

```bash
curl -X POST "http://<MoviePilot地址>:3000/api/v1/plugin/OpenClashMonitor/action?apikey=<你的API密钥>" \
  -H "Content-Type: application/json" \
  -d '{"action":"rule","value":"global"}'
```

`restart`、`stop`、`switch_config`、`close` 属于破坏性操作，必须显式带 `confirm: true`；操作成功后插件会自动重新采集一次。

趋势：每采集一次就往快照 `trend` 里写一个点（同小时覆盖），页面用两张折线图展示「在线节点/节点总数」和「拦截率 %/上游平均延迟 ms」。

异常提醒：命中阈值时发通知（同一告警在冷却期内只发一次），同时页面上以红/黄告警条展示；告警状态存 7 天。

### zashboard 面板与页面快捷切换

插件页里直接内嵌 zashboard（`http://<你的zashboard地址>`），可以在里面切代理组、看连接与延迟；如果浏览器或反向代理禁止 iframe 嵌入，页面上有「在新窗口打开」按钮。

面板下方还有一组纯页面按钮（不需要打开 zashboard）：

- 一行「规则模式」按钮，点击即切换 `rule` / `global` / `direct`；
- 每个策略组（在线数最多的前 4 组）列出最快 8 个节点，点一下就把该组切到该节点，当前选中项高亮。

这些按钮调用的是 `POST /action_web`（`auth: "bear"`，用登录态鉴权，所以在浏览器里点即可），动作与 `/action` 一致但 `rule`/`node`/`flush`/`flush_smart` 无需再带 `confirm`；`restart`、`stop` 之类的破坏性操作仍只在 `/action` 里提供并要求 `confirm`。配置里关掉「启用一键操作」后，这组按钮与所有操作接口都会消失/被拒绝。

### 定时报告

在配置里打开「启用定时报告」并填 cron（默认 `0 9 * * *`，五段式：分 时 日 月 周），插件会注册一个调度任务，按点把当次报告推到通知渠道：

- 通知渠道可选 Telegram、QQ、企业微信，可多选；留空则走 MoviePilot 的默认通知路由（哪个渠道开了「插件」消息就发哪个）。
- 报告内容：运行状态、连接/内存/CPU/负载、节点在线率与最快的若干节点、订阅流量与到期、三个组件的版本更新、LocalDNS 统计与上游异常、主动探测结果、当前告警。
- 页面上有「立即发送报告」按钮，等价于 `POST /report`；不依赖定时开关，可以随时手动发一条。
- 也可以发远程命令：`/openclash_report` 发一条到默认渠道，`/openclash_report_channels telegram,qq` 临时指定渠道。

## 定时任务

| 任务 | 触发 | 说明 |
| --- | --- | --- |
| `OpenClashMonitor.Refresh` | `interval`（采集间隔） | 采集一次并写入快照、趋势、告警 |
| `OpenClashMonitor.Report` | `cron`（定时表达式） | 仅在「启用定时报告」时注册 |

### 关于节点来源（重要）

订阅型机场的节点**不会**出现在 Mihomo 的 `/proxies` 里：那里只有策略组和内置代理（`DIRECT`/`REJECT`/`直连`/`拒绝`/…）。
真实节点在 `/providers/proxies` 的每个 provider 的 `proxies` 数组里（`机场一号` 173 个、`机场2号` 122 个、`红杏云` 68 个…）。插件会把两侧合并成节点池，
所以节点列表里的「机场」列能看出每个节点来自哪个 provider；`/proxies` 里没有的成员也能正确计入策略组的在线数。

> 判断「是不是真实节点」用的是 `type` 字段（`Direct`/`Reject`/`RejectDrop`/`Compatible`/`Pass`/`PassRule`/`Dns` 都算内置），
> 不是名字名单——所以中文的「直连」「拒绝」也能正确排除。

### 关于「LocalDNS」

路由器上的 DNS 实现常见有几种，本插件对它们的支持程度不同：

- **LocalDNS（github.com/yyhoworks/LocalDNS）**：全部功能可用——状态、统计、上游健康、查询日志、进程指标、版本更新。
  上游健康来自它自己的统计（`upstream_stats`），比主动测速更贴近真实流量。
- **AdGuard Home**：查询日志、拦截率、上游模式、上游测速 → 功能可用，但上游健康需要在页面上手动点一次测速（`ag_test_upstream`）。
- **Clash/Mihomo 内置 DNS**：不需要额外配置，插件总会展示 enhanced-mode、上游 nameserver、fake-ip 段。
- **dnsmasq / SmartDNS / mosdns**：没有统一 HTTP API，插件只做「主动 UDP 探测」来判定上游是否健康；查询日志取不到。

### 关于 LocalDNS 版本更新

LocalDNS 没有自带的「检查更新」接口，插件用两个来源比对：

- 本地：`GET /ui/version.json` → `uiVersion`、`backendVersion`（核心代号，如 `FJGOE`）、`releaseTag`。
- 远端：`https://api.github.com/repos/yyhoworks/LocalDNS/releases/latest` 的 tag，规则是 `<核心代号小写>-ui-v<UI版本>`（如 `fjgoe-ui-v2026.10.23.2`）。

UI 版本按语义化版本比较；核心代号不同时会在页面上额外提示「通道不一致」。

## 对外 API

全部 `GET`（最后三个为 `POST`），路径前缀 `/api/v1/plugin/OpenClashMonitor`：

| 路径 | 说明 |
| --- | --- |
| `/snapshot` | 最近一次采集的完整快照 |
| `/refresh` | 立即采集一次并返回快照 |
| `/nodes` | 节点与策略组 |
| `/subscriptions` | 订阅流量与到期 |
| `/versions` | 版本对比结果 |
| `/dns` | LocalDNS 与上游 DNS 健康 |
| `/probe` | 立即重新探测上游 DNS |
| `/trend` | 趋势曲线数据（节点、拦截率、上游延迟） |
| `/alerts` | 当前告警列表 |
| `POST /action` | 执行一键操作（`auth: apikey`，body 见上） |
| `POST /action_web` | 页面按钮用的一键操作（`auth: bear`，`rule`/`node`/`flush`/`flush_smart` 免 `confirm`） |
| `POST /report` | 立即发送报告（`auth: bear`，body 可带 `{"channels":["telegram"]}` 临时指定渠道） |

Telegram / 微信命令：`/openclash` 返回运行状态摘要、`/openclash_trend` 返回最近趋势、`/openclash_report` 立即发一条报告，
另有 `/openclash_restart`、`/openclash_start`、`/openclash_stop`、`/openclash_rule`、`/openclash_flush`、`/openclash_node`、`/openclash_report_channels`。

## 已知限制

1. **跨机访问 LuCI 需要登录**：登录请求必须带 `Referer: http://<路由器>/cgi-bin/luci/`，否则返回 403；
   且成功时是 `302 + Set-Cookie`，跟随跳转会丢掉会话 Cookie。插件已按此实现（`luci_username`/`luci_password` 与 `username`/`password` 两种字段名都会尝试），
   仍失败时请手工粘贴 `sysauth_http=...` Cookie。
2. **订阅剩余流量依赖 OpenClash 自己的解析**：`sub_info_get` 里 `surplus`/`expire`/`day_left` 可能是字符串 `"null"`
   （该机场不提供流量或到期信息），插件会显示「不支持查询」/「未知」。
3. **CPU 与内存是采样值**：OpenClash 新版 `toolbar_show` 直接给出 `cpu`（0~1 小数）与 `mem`，插件据此换算；
   老版本只有 `cpu_ticks` 时退化为两次采样求差，误差在数百毫秒级。LocalDNS 的 CPU 也是两次采样 `/metrics` 求差。
4. **主动 DNS 探测使用 UDP/53**：如果上游只支持 DoH/DoT，请把 `tls://`、`https://` 形式的地址留给 LocalDNS/AdGuard，
   不要放进主动探测列表。
5. **新版 Mihomo 的 `/configs` 可能不再带 `dns` 段**（如 `alpha-gbc76c13`）：此时 `enhanced-mode`、上游 `nameserver`、
   fake-ip 段都取不到，插件改为按 LuCI `run_mode`（`fake-ip` / `redir-host`）推断 DNS 模式，上游列表请以 LocalDNS 面板为准。
6. **订阅信息接口较慢**：`sub_info_get` 会现场请求机场的订阅链接，插件给它 3 倍超时（至少 20s），
   首轮采集可能比其他分区慢几秒。
7. **一键操作会真实改变路由器状态**：重启/停止 OpenClash、关闭全部连接、切换配置文件会短暂断网，
   请确认后再执行；不确定时先把「启用一键操作」关掉。
8. **趋势数据存在插件数据目录里**：MoviePilot 重装或清理 `plugin_data` 会丢失历史点，重新采集后会从头累积。
9. **内嵌面板受浏览器/X-Frame-Options 影响**：zashboard 本身允许 iframe，但如果你在前面加了带 `X-Frame-Options: DENY`
   的反向代理，面板会空白，请用「在新窗口打开」。
10. **定时报告依赖宿主的 CronTrigger**：APScheduler 缺失时插件只会在日志里告警并退化为只能手动发报告。
    报告走 MoviePilot 的「插件」消息类型，请确认对应渠道的插件消息开关是打开的。
---

# 字幕规范化

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
| 同语言去重提示 | 同一语言有多份字幕时只提示、不改名，避免目标重名互相覆盖 |
| Emby 刷新 | 支持条目级（`POST /Library/Media/Updated`）、库级（`POST /Library/Refresh`）或两者 |
| 定时与试跑 | `dry_run` 默认开启（只出计划不改文件），`limit` 默认 10 条，可先用少量样本验证 |
| 历史库批量 | 扫描媒体库目录（不是下载目录），把历史遗留的不规范字幕一起统一 |
| 下载完成即处理 | 订阅 MoviePilot 的 `TransferComplete` / `SubtitleTransferComplete` 事件：整理完成或字幕落盘后，只对事件涉及的目录做一次规范化并刷新 Emby（`event_enabled` 可关） |

命名风格可切换：`tag_style=mp`（默认，`chi.zh-cn`/`zh-tw`，与 MoviePilot 一致）、`tag_style=chs_cht`（`chs`/`cht`）。

## 安装

1. MoviePilot → 设置 → 插件市场，添加仓库 `https://github.com/zimo650/MoviePilot-Plugins`（已添加过可跳过）。
2. 刷新市场，搜索「字幕规范化」或插件 ID `SubtitleShield`，安装并启用。

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

插件页包含：

- 8 张统计卡：扫描目录、视频数、字幕数、待规范化、已合规、重复字幕、已处理、失败。
- 模式提示：当前是否只预览、单次上限、命名风格。
- **待规范化清单**：视频 / 当前字幕 / 判定语言 / 依据 / 目标文件名 / 动作。
- **同语言重复**（只提示）、**已跳过**、**最近已处理**、**失败与跳过**。

## 已知限制

1. 只处理**已存在**的外挂字幕，不负责下载字幕（下载请用 MoviePilot 内置字幕或字幕类插件）。
2. 语言判定依赖简繁字对表，纯英文/日文字幕只在文件名有线索时归类；正文判定置信度低时会标注 `low`。
3. `keep_both` 关闭后，被丢弃的语言只会进「已跳过」列表，不会自动删除文件。
4. `dry_run` 默认开启，首次使用请先 `/subtitleguard_scan` 看计划，确认无误再关掉试跑少量。
5. Emby 条目级刷新依赖 Emby 允许 `POST /Library/Media/Updated`；部分旧版本可用库级刷新替代。
6. **Emby 侧要看到新语言标签，`emby_path_map` 必须填对**：MoviePilot 容器里是 `/video/downloads/link/...`，Emby 容器里往往是 `/data/movie/...`，路径对不上时 Emby 收不到改动；同时建议保持 `emby_touch` 开启，否则只改字幕文件名不会触发 Emby 重新探测。
7. 重命名是**原地改名**，不改变文件内容；如需回退，请以扫描计划里的「当前字幕」列为准手工改回。
8. 下载完成事件的注册发生在插件加载时，**安装或升级插件后需要重启一次 MoviePilot（或重载插件）**钩子才会挂上；事件只处理 `media_roots` 范围内的目录。
