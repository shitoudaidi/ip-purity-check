---
name: ip-purity-check
version: 1.0.0
description: 本地自托管的「IP 纯净度检测」工具，检测出口 IP、地理位置、运营商/ASN、风险（代理/数据中心/VPN）、WebRTC 泄露、浏览器指纹、出口一致性与 DNS 泄露。零依赖，使用免费公开 API（ipwho.is / ip-api.com / api.ipify.org）。当用户要「查我的 IP」「检测 IP 泄露」「IP 纯净度」「whatismyip / 指纹检测 / WebRTC 泄露」时使用。
---

# IP Purity Check（IP 纯净度检测）

本地自托管版 IP 纯净度检测工具。无需任何 API 密钥，全部使用免费公开数据源 + 浏览器端实测。

## 适用场景
- 用户想"查我的真实 IP / 我在哪 / 我的运营商是什么"
- 用户想"检测我有没有 IP 泄露 / WebRTC 泄露 / DNS 泄露"
- 用户想"检测这个 IP 是不是代理 / 数据中心 / VPN"
- 用户想"看我的浏览器指纹"
- 用户提到 whatismyip、ipleak、browserleaks 等站点

## 实现原理
本工具由两部分组成：
1. **服务端检测**
   - IP 地理/ASN/ISP：`/api/info/ip-basic`（调用 `ipwho.is` 做地理/ASN/ISP/时区富集）。
   - IP 风险：`/api/info/ip-risk`（调用 `ip-api.com` 获取 proxy/hosting/mobile 标记，叠加启发式规则）。
   - IP 泄露（出口一致性）：服务端看到的 IP vs 浏览器回显的出口 IP vs WebRTC 暴露的 IP 三方比对。
2. **浏览器端检测**
   - WebRTC 泄露：`RTCPeerConnection` + STUN，正则提取 ICE 候选里的 IPv4/IPv6，分类 public/private（`app/public/app.js` 的 `detectWebRTC`）。
   - 浏览器指纹：FingerprintJS v3。
   - 出口一致性：对比"服务端看到的 IP" vs "浏览器回显的出口 IP" vs "WebRTC 暴露的 IP"。

> 关键点：真正"监测出用户真实出口 IP"的价值来自**服务端读取请求 IP**。本地访问时请求来自 127.0.0.1，因此前端用 `api.ipify.org` 自行发现出口 IP；当把本工具**部署到公网**后，服务端读取的即是访客真实出口 IP。`/api/echo` 已预留该能力。

## 运行方式（Agent 执行步骤）
本工具自带零依赖 Node 服务（`app/server.js`，Node 18+，使用内置 http + 全局 fetch）。

1. 用受管 Node 启动服务（后台运行）：
   ```
   /Users/mac/.workbuddy/binaries/node/versions/22.22.2-6/bin/node /Users/mac/.workbuddy/skills/ip-purity-check/app/server.js
   ```
   端口默认 8787，可用 `PORT=xxxx` 环境变量覆盖。
2. 验证后端可用（可选）：
   - `curl http://localhost:8787/api/echo`
   - `curl "http://localhost:8787/api/info/ip-risk?ip=8.8.8.8"`
3. 打开 `http://localhost:8787/` 即可看到检测面板。可用 `agent-browser` 截图给用户看，或直接用 `present_files` 以 `http://localhost:8787/` 形式预览。

## 文件结构
```
ip-purity-check/
├── SKILL.md
└── app/
    ├── server.js            # 零依赖 Node 服务（IP 提取 + 免费 API 富集 + 风险判定）
    └── public/
        ├── index.html       # 检测面板
        ├── style.css
        └── app.js           # 前端逻辑：WebRTC 泄露 / 指纹 / 多出口比对 / Leaflet 地图
```

## API 路由
| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/echo` | 返回服务端看到的请求 IP 与关键请求头 |
| GET | `/api/info/ip-basic?ip=` | 地理 + ASN + ISP 富集 |
| GET | `/api/info/ip-risk?ip=` | 风险分(0-100) + 判定 + 标记(proxy/hosting/VPN_LIKELY…) |
| GET | `/api/info/asn/botclass?ip=` | ASN + 人机/自动化判定 |

## 局限与可扩展
- 免费 API 有速率限制（ip-api.com 约 45 次/分钟），批量检测需节流。
- "严谨 DNS 泄露"需自有域名记录各解析器出口，本工具以"多出口一致性"作近似指标（已在 UI 注明）。
- 若要更接近商业"IP 纯净度评分"，可后续接入 AbuseIPDB / Scamalytics / IPQualityScore（需密钥）。
- 部署到公网后，`/api/echo` 读取的即是访客真实出口 IP，泄露检测更权威。
