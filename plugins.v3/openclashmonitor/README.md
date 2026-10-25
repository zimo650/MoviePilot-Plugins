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

全部 `GET`，路径前缀 `/api/v1/plugin/OpenClashMonitor`：

| 路径 | 说明 |
| --- | --- |
| `/snapshot` | 最近一次采集的完整快照 |
| `/refresh` | 立即采集一次并返回快照 |
| `/nodes` | 节点与策略组 |
| `/subscriptions` | 订阅流量与到期 |
| `/versions` | 版本对比结果 |
| `/dns` | LocalDNS 与上游 DNS 健康 |
| `/probe` | 立即重新探测上游 DNS |

Telegram / 微信命令：`/openclash` 返回一段运行状态摘要。

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
