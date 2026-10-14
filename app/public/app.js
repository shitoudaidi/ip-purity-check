/* IP Purity Check — frontend logic */
"use strict";

const $ = (id) => document.getElementById(id);

/* ---------- WebRTC leak detection ---------- */
function detectWebRTC(opts = {}) {
  const iceServers = opts.iceServers || [
    { urls: "stun:stun.cloudflare.com:3478" },
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun.chat.bilibili.com:3478" },
    { urls: "stun:stun.miwifi.com:3478" },
  ];
  const timeout = typeof opts.timeout === "number" ? opts.timeout : 2500;
  const onlyPublic = !!opts.onlyPublic;
  const ipv4Re = /(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})/g;
  const ipv6Re = /(?:^|[\s:,\(\)"])((?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|fe80:(?:[:0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::1)(?=$|[\s,;\)\"])/g;

  function isLocal(host) {
    return /\.local\b/i.test(host);
  }
  function classifyV4(c) {
    const e = c.split(".").map((s) => parseInt(s, 10));
    const f = (e[0] << 24 >>> 0) + (e[1] << 16) + (e[2] << 8) + e[3];
    const inRange = (s, o) => f >= s && f <= o;
    const a = (s, o, l, d) => (s << 24 >>> 0) + (o << 16) + (l << 8) + d;
    if (c === "127.0.0.1") return "loopback";
    if (inRange(a(10, 0, 0, 0), a(10, 255, 255, 255))) return "private";
    if (inRange(a(172, 16, 0, 0), a(172, 31, 255, 255))) return "private";
    if (inRange(a(192, 168, 0, 0), a(192, 168, 255, 255))) return "private";
    if (inRange(a(169, 254, 0, 0), a(169, 254, 255, 255))) return "link-local";
    if (inRange(a(100, 64, 0, 0), a(100, 127, 255, 255))) return "carrier-grade-NAT";
    return "public";
  }
  function classifyV6(c) {
    const e = c.toLowerCase();
    if (e === "::1") return "loopback";
    if (e.startsWith("fe80:")) return "link-local";
    if (/^fc|^fd/i.test(e)) return "unique-local";
    if (/^::ffff:/.test(e)) return "ipv4-mapped";
    return "global";
  }

  return new Promise((resolve) => {
    const ipv4 = new Set();
    const ipv6 = new Set();
    const mdns = new Set();
    const raw = [];
    const classified = [];
    let done = false;
    const pc = new RTCPeerConnection({ iceServers });
    const finish = () => {
      if (done) return;
      done = true;
      try { pc.close(); } catch (e) {}
      resolve({ ipv4, ipv6, mdns, raw, classified });
    };

    function parse(cand) {
      if (!cand || typeof cand !== "string" || raw.includes(cand)) return;
      raw.push(cand);
      if (isLocal(cand)) {
        (cand.match(/\b[a-z0-9-]{6,}\.local\b/gi) || []).forEach((m) => mdns.add(m));
      }
      Array.from(cand.matchAll(ipv4Re)).map((m) => m[0]).forEach((n) => {
        const cat = classifyV4(n);
        if (!onlyPublic || cat === "public") {
          if (!ipv4.has(n)) { ipv4.add(n); classified.push({ ip: n, family: "IPv4", category: cat }); }
        }
      });
      Array.from(cand.matchAll(ipv6Re)).map((m) => m[1] || m[0]).forEach((n) => {
        const clean = n.replace(/^\[|\]$/g, "");
        const cat = classifyV6(clean);
        if (!onlyPublic || cat === "global") {
          if (!ipv6.has(clean)) { ipv6.add(clean); classified.push({ ip: clean, family: "IPv6", category: cat }); }
        }
      });
    }

    pc.onicecandidate = (e) => {
      if (!e || !e.candidate) { setTimeout(finish, 0); return; }
      parse(e.candidate.candidate || "");
    };
    try { pc.createDataChannel && pc.createDataChannel("webrtc-detect"); } catch (e) {}
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => {});
    setTimeout(finish, timeout);
  });
}

/* ---------- helpers ---------- */
async function getJson(url, ms = 8000) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(url, { signal: c.signal });
    if (!r.ok) return null;
    const ct = r.headers.get("content-type") || "";
    return ct.includes("json") ? await r.json() : await r.text();
  } catch (e) { return null; }
  finally { clearTimeout(t); }
}
function tag(ip) { return `<span class="tag-ip">${ip}</span>`; }
function row(k, v) { return `<div class="k">${k}</div><div class="v">${v}</div>`; }

/* ---------- multi-echo sources (for leak / DNS consistency) ---------- */
const ECHO_SRC = [
  { name: "ipify", url: "https://api.ipify.org?format=json", pick: (d) => (typeof d === "object" ? d.ip : null) },
  { name: "ipwho.is", url: "https://ipwho.is/", pick: (d) => (d && d.ip ? d.ip : null) },
  { name: "icanhazip", url: "https://icanhazip.com/", pick: (d) => (typeof d === "string" ? d.trim() : null) },
  { name: "ifconfig.me", url: "https://ifconfig.me/ip", pick: (d) => (typeof d === "string" ? d.trim() : null) },
];

async function collectEchoIps() {
  const out = [];
  await Promise.all(ECHO_SRC.map(async (s) => {
    const d = await getJson(s.url);
    const ip = s.pick(d);
    if (ip) out.push({ source: s.name, ip });
  }));
  return out;
}

/* ---------- main ---------- */
async function main() {
  // 1) server-seen IP (authoritative when deployed)
  const echo = await getJson("/api/echo");
  const serverIp = echo ? echo.ip : null;

  // 2) client egress IP + geo (direct)
  const clientGeo = await getJson("https://ipwho.is/");
  const clientIp = clientGeo && clientGeo.ip ? clientGeo.ip : (serverIp || null);

  // 3) enriched + risk from our backend
  const [basic, risk, asn] = await Promise.all([
    getJson(`/api/info/ip-basic?ip=${clientIp}`),
    getJson(`/api/info/ip-risk?ip=${clientIp}`),
    getJson(`/api/info/asn/botclass?ip=${clientIp}`),
  ]);

  // 4) WebRTC
  const webrtc = await detectWebRTC();
  const webrtcPublic = webrtc.classified.filter((c) => c.category === "public" || c.category === "global").map((c) => c.ip);
  const webrtcPrivate = webrtc.classified.filter((c) => c.category === "private" || c.category === "link-local" || c.category === "loopback").map((c) => c.ip);

  // 5) multi-echo
  const echoIps = await collectEchoIps();
  const echoSet = [...new Set(echoIps.map((e) => e.ip))];

  // ---- headline ----
  const leak = webrtcPublic.length > 0 && !webrtcPublic.includes(clientIp);
  $("headline").innerHTML = `出口 IP：${tag(clientIp)} ｜ WebRTC 泄露：${leak ? '<span class="row-bad">是</span>' : '<span class="row-ok">否</span>'}`;

  // ---- geo card ----
  if (basic && basic.geo) {
    const g = basic.geo;
    const conn = g.connection || {};
    $("geo-body").innerHTML =
      row("IP", tag(g.ip)) +
      row("位置", `${g.flag || ""} ${g.country || "-"} ${g.region || ""} ${g.city || ""}`) +
      row("经纬度", g.latitude != null ? `${g.latitude}, ${g.longitude}` : "-") +
      row("运营商", conn.isp || "-") +
      row("ASN", conn.asn ? `AS${conn.asn}` : "-") +
      row("组织", conn.org || "-") +
      row("时区", g.timezone || "-");
    if (g.latitude != null) {
      const map = L.map("map").setView([g.latitude, g.longitude], 4);
      L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution: "© OpenStreetMap" }).addTo(map);
      L.marker([g.latitude, g.longitude]).addTo(map).bindPopup(`${g.ip}<br>${g.city}, ${g.country}`);
    }
  } else {
    $("geo-body").innerHTML = `<span class="muted">地理信息获取失败</span>`;
  }

  // ---- risk card ----
  if (risk) {
    $("risk-score").textContent = `${risk.score} / 100`;
    $("risk-score").style.color = risk.score >= 70 ? "var(--bad)" : risk.score >= 35 ? "var(--warn)" : "var(--ok)";
    const b = [];
    if (risk.flags.length === 0) b.push(`<span class="badge ok">清洁</span>`);
    risk.flags.forEach((f) => b.push(`<span class="badge bad">${f}</span>`));
    if (risk.mobile) b.push(`<span class="badge warn">MOBILE</span>`);
    $("risk-badges").innerHTML = b.join("");
    $("risk-body").innerHTML =
      row("判定", risk.verdict) +
      row("Proxy", risk.proxy ? '<span class="row-bad">是</span>' : "否") +
      row("数据中心", risk.hosting ? '<span class="row-bad">是</span>' : "否") +
      row("ASN", asn && asn.asn ? `AS${asn.asn}` : "-");
  }

  // ---- webrtc card ----
  {
    const items = webrtc.classified.length
      ? webrtc.classified.map((c) => `${tag(c.ip)} <span class="muted">(${c.family} · ${c.category})</span>`).join("<br>")
      : '<span class="muted">未发现候选（已禁用 WebRTC 或严格隐私设置）</span>';
    const leakNote = webrtcPublic.length > 0 && !webrtcPublic.includes(clientIp)
      ? `<div class="row-bad" style="margin-top:8px">⚠ 检测到与出口 IP 不同的公网地址，WebRTC 已泄露真实网络！</div>`
      : `<div class="row-ok" style="margin-top:8px">✓ 未暴露与出口 IP 不同的公网地址</div>`;
    $("webrtc-body").innerHTML = items + leakNote;
  }

  // ---- leak / consistency card ----
  {
    const lines = [];
    lines.push(row("服务端看到", serverIp && serverIp !== "127.0.0.1" ? tag(serverIp) : `<span class="muted">${serverIp}（本地访问，部署后生效）</span>`));
    lines.push(row("浏览器出口", tag(clientIp)));
    lines.push(row("WebRTC 公网", webrtcPublic.length ? webrtcPublic.map(tag).join(" ") : '<span class="muted">无</span>'));
    const consistent = echoSet.length <= 1;
    lines.push(row("多源一致性", consistent ? '<span class="row-ok">一致</span>' : `<span class="row-bad">不一致：${echoSet.join(", ")}</span>`));
    $("leak-body").innerHTML = lines.join("");
  }

  // ---- fingerprint card ----
  {
    let fpText = '<span class="muted">指纹库加载中…</span>';
    $("fp-body").innerHTML = fpText;
    try {
      if (window.FingerprintJS) {
        const fp = await window.FingerprintJS.load();
        const res = await fp.get();
        $("fp-body").innerHTML =
          row("Fingerprint", `<span class="tag-ip">${res.visitorId}</span>`) +
          row("置信度", (res.confidence && (res.confidence.score * 100).toFixed(1) + "%") || "-") +
          row("组件数", res.components ? Object.keys(res.components).length : "-");
      } else {
        $("fp-body").innerHTML = '<span class="muted">FingerprintJS CDN 不可用</span>';
      }
    } catch (e) {
      $("fp-body").innerHTML = `<span class="muted">指纹采集失败：${e.message}</span>`;
    }
  }

  // ---- DNS leak card ----
  {
    const details = echoIps.map((e) => row(e.source, tag(e.ip))).join("");
    const consistent = echoSet.length <= 1;
    const note = consistent
      ? `<div class="row-ok" style="margin-top:8px">✓ 各回显源出口一致，未见 DNS 出口分裂迹象</div>`
      : `<div class="row-bad" style="margin-top:8px">⚠ 不同回显源返回了不同出口 IP，存在 DNS / 路由分裂</div>`;
    const limitation = `<div class="muted" style="margin-top:6px;font-size:12px">说明：严谨的 DNS 泄露需服务端记录各 DNS 解析器出口，本工具以多出口一致性作为近似指标。</div>`;
    $("dns-body").innerHTML = details + note + limitation;
  }
}

main().catch((e) => {
  document.body.insertAdjacentHTML("afterbegin", `<div style="padding:12px;background:#fdeaec;color:#ef4d56">检测出错：${e.message}</div>`);
});
