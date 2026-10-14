#!/usr/bin/env node
/**
 * IP Purity Check — local backend
 * Zero dependencies (Node built-in http + global fetch, Node 18+).
 *
 * IP geolocation / risk enrichment built on free, key-less public APIs:
 *   - ipwho.is   -> geolocation / ASN / ISP / timezone
 *   - ip-api.com -> proxy / hosting / mobile risk flags
 *
 * Routes:
 *   GET /                       -> dashboard (public/index.html)
 *   GET /api/echo               -> the IP this server sees for the request + headers
 *   GET /api/info/ip-basic?ip=  -> geo + ASN + ISP (enriched)
 *   GET /api/info/ip-risk?ip=   -> risk score + VPN/Proxy/Datacenter/Tor heuristics
 *   GET /api/info/asn/botclass?ip= -> ASN + automation/bot heuristic
 *
 * When accessed over localhost the request IP is 127.0.0.1, so the browser
 * discovers its own public IP via client-side echo and passes it as ?ip=.
 * When the app is DEPLOYED publicly, the server-side read becomes the
 * authoritative egress IP seen by the server.
 */

const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8787;
const PUBLIC_DIR = path.join(__dirname, "public");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
  });
  res.end(body);
}

// Extract the real client IP from the request.
function getRequestIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return xff.split(",")[0].trim();
  if (req.headers["x-real-ip"]) return String(req.headers["x-real-ip"]).trim();
  let ip = req.socket.remoteAddress || "";
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (ip === "::1") ip = "127.0.0.1";
  return ip;
}

async function fetchJson(url, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "ip-purity-check/1.0" } });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Enrich an IP with geo + ASN + ISP via free APIs.
async function enrichIp(ip) {
  const [who, api] = await Promise.all([
    fetchJson(`https://ipwho.is/${ip}`),
    fetchJson(`http://ip-api.com/json/${ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,mobile,query`),
  ]);

  const geo = who && who.success ? who : null;
  const risk = api && api.status === "success" ? api : null;

  return {
    ip,
    geo: geo
      ? {
          ip: geo.ip,
          type: geo.type,
          continent: geo.continent,
          continent_code: geo.continent_code,
          country: geo.country,
          country_code: geo.country_code,
          region: geo.region,
          city: geo.city,
          latitude: geo.latitude,
          longitude: geo.longitude,
          postal: geo.postal,
          timezone: geo.timezone ? geo.timezone.id : null,
          flag: geo.flag ? geo.flag.emoji : null,
          connection: geo.connection || null,
        }
      : null,
    risk: risk
      ? {
          proxy: !!risk.proxy,
          hosting: !!risk.hosting,
          mobile: !!risk.mobile,
          isp: risk.isp || (geo && geo.connection && geo.connection.isp) || null,
          as: risk.as || (geo && geo.connection && `AS${geo.connection.asn} ${geo.connection.org}`) || null,
        }
      : null,
    sources: {
      ipwho_is: !!geo,
      ip_api_com: !!risk,
    },
  };
}

// Derive a purity/risk verdict from the free signals.
function deriveRisk(enriched) {
  const r = enriched.risk || {};
  const flags = [];
  let score = 0; // 0 = clean, 100 = very risky

  if (r.proxy) {
    flags.push("PROXY");
    score += 45;
  }
  if (r.hosting) {
    flags.push("DATACENTER");
    score += 30;
  }
  if (r.mobile) {
    flags.push("MOBILE");
  }
  const isp = (r.isp || "").toLowerCase();
  const asn = (r.as || "").toLowerCase();
  const vpnHints = ["vpn", "proxy", "tunnel", "nova", "surfshark", "nord", "expressvpn", "datacamp", "m247", "hydra", "total", "privatelayer"];
  if (vpnHints.some((h) => isp.includes(h) || asn.includes(h))) {
    flags.push("VPN_LIKELY");
    score += 35;
  }
  // Pure residential ISP hint => cleaner
  const residentialHints = ["telecom", "comcast", "verizon", "at&t", "deutsche telekom", "chinanet", "unicom", "cmcc", "jio", "broadband", "cable"];
  if (residentialHints.some((h) => isp.includes(h)) && !r.hosting && !r.proxy) {
    score = Math.max(0, score - 25);
  }
  score = Math.max(0, Math.min(100, score));

  let verdict = "干净 (Clean)";
  if (score >= 70) verdict = "高风险 (High Risk)";
  else if (score >= 35) verdict = "疑似代理/数据中心 (Suspect)";
  else if (score > 0) verdict = "轻度风险 (Low Risk)";

  return { score, verdict, flags };
}

function serveStatic(req, res, urlPath) {
  let rel = urlPath === "/" ? "/index.html" : urlPath;
  const filePath = path.join(PUBLIC_DIR, path.normalize(rel));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: "forbidden" });
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      sendJson(res, 404, { error: "not found" });
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream" });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const p = u.pathname;

  try {
    if (p === "/api/echo") {
      return sendJson(res, 200, {
        ip: getRequestIp(req),
        headers: {
          "x-forwarded-for": req.headers["x-forwarded-for"] || null,
          "x-real-ip": req.headers["x-real-ip"] || null,
          "user-agent": req.headers["user-agent"] || null,
          "accept-language": req.headers["accept-language"] || null,
        },
        note: "When accessed over localhost this is 127.0.0.1. Deploy publicly to capture the real visitor egress IP.",
      });
    }

    if (p === "/api/info/ip-basic") {
      const ip = u.searchParams.get("ip") || getRequestIp(req);
      if (!ip || ip === "127.0.0.1" || ip === "::1") {
        return sendJson(res, 400, { error: "no public IP; pass ?ip= or deploy publicly" });
      }
      const enriched = await enrichIp(ip);
      return sendJson(res, 200, enriched);
    }

    if (p === "/api/info/ip-risk") {
      const ip = u.searchParams.get("ip") || getRequestIp(req);
      if (!ip || ip === "127.0.0.1" || ip === "::1") {
        return sendJson(res, 400, { error: "no public IP; pass ?ip= or deploy publicly" });
      }
      const enriched = await enrichIp(ip);
      const risk = deriveRisk(enriched);
      return sendJson(res, 200, {
        ip,
        score: risk.score,
        verdict: risk.verdict,
        flags: risk.flags,
        proxy: enriched.risk ? enriched.risk.proxy : null,
        hosting: enriched.risk ? enriched.risk.hosting : null,
        mobile: enriched.risk ? enriched.risk.mobile : null,
      });
    }

    if (p === "/api/info/asn/botclass") {
      const ip = u.searchParams.get("ip") || getRequestIp(req);
      if (!ip || ip === "127.0.0.1" || ip === "::1") {
        return sendJson(res, 400, { error: "no public IP; pass ?ip= or deploy publicly" });
      }
      const enriched = await enrichIp(ip);
      const asn = enriched.geo && enriched.geo.connection ? enriched.geo.connection.asn : null;
      const org = enriched.geo && enriched.geo.connection ? enriched.geo.connection.org : null;
      const ua = req.headers["user-agent"] || "";
      const botHint = /bot|crawl|spider|slurp|headless|python|curl|go-http|axios|okhttp/i.test(ua);
      return sendJson(res, 200, {
        ip,
        asn,
        org,
        class: botHint ? "AUTOMATED" : "LIKELY_HUMAN",
        botHint,
        userAgent: ua,
      });
    }

    if (p.startsWith("/api/")) {
      return sendJson(res, 404, { error: "unknown endpoint" });
    }

    return serveStatic(req, res, p);
  } catch (e) {
    return sendJson(res, 500, { error: String(e && e.message ? e.message : e) });
  }
});

server.listen(PORT, () => {
  console.log(`[ip-purity-check] listening on http://localhost:${PORT}`);
});
