/**
 * FRAUD-X Shield — Enterprise Background Service Worker  v3.0
 * ============================================================
 * 22-section enterprise AI-powered cybersecurity protection.
 *
 * §1  Real-time payment page detection
 * §2  Real-time URL fraud analysis (XGBoost/RF/threat intel)
 * §3  Advanced threat intelligence (backend relay)
 * §4  Payment gateway legitimacy verification
 * §12 Transaction velocity monitoring
 * §13 Background silent fraud monitoring + offline cache
 * §14 Real-time WebSocket communication
 * §19 Performance optimization (debounce, cache, lazy scan)
 * §20 Enterprise security (context menu, OS notifications, CSP)
 * §21 Admin dashboard integration
 */

"use strict";

const VERSION     = "3.0.0";
const DEFAULT_API = "http://localhost:8000";

// ── Cache & in-flight state ───────────────────────────────────
const CACHE     = new Map();           // url → {result, ts}
const CACHE_TTL = 5 * 60_000;
const SCANNING  = new Set();
const PAY_SCAN  = new Set();

// ── Tab state ─────────────────────────────────────────────────
const TAB_PAYMENT = new Map();
const TAB_RISK    = new Map();         // tabId → {score, level}

// ── §12 Velocity monitoring ───────────────────────────────────
// domain → [timestamp, ...]  (sliding window)
const VELOCITY     = new Map();
const VEL_WINDOW   = 60_000;          // 1-minute window
const VEL_WARN     = 6;              // pages/min → suspicious
const VEL_CRITICAL = 12;             // pages/min → high risk

// ── §13 Offline phishing cache ────────────────────────────────
const PHISH_CACHE = new Set();
let   PHISH_TS    = 0;
const PHISH_TTL   = 3_600_000;       // refresh hourly

// ── §14 WebSocket ─────────────────────────────────────────────
let _ws       = null;
let _wsDelay  = 3000;
const WS_MAX  = 30_000;

// ── Skip list ─────────────────────────────────────────────────
const SKIP_HOSTS = new Set([
  "localhost","127.0.0.1","0.0.0.0",
  "google.com","www.google.com","accounts.google.com",
  "github.com","raw.githubusercontent.com",
  "chrome.google.com",
]);

// ════════════════════════════════════════════════════════════════
// API helper
// ════════════════════════════════════════════════════════════════

function getAPI() {
  return new Promise(resolve =>
    chrome.storage.sync.get({ fraudx_api_url: DEFAULT_API }, d =>
      resolve((d.fraudx_api_url || DEFAULT_API).replace(/\/$/, ""))
    )
  );
}

// ════════════════════════════════════════════════════════════════
// §12 Velocity monitoring
// ════════════════════════════════════════════════════════════════

function recordVelocity(domain) {
  const now = Date.now();
  const ts  = (VELOCITY.get(domain) || []).filter(t => now - t < VEL_WINDOW);
  ts.push(now);
  VELOCITY.set(domain, ts);
  return ts.length;
}

function getVelocityRisk(count) {
  if (count >= VEL_CRITICAL) return { level: "critical", score: 85 };
  if (count >= VEL_WARN)     return { level: "high",     score: 55 };
  return null;
}

function cleanVelocity() {
  const now = Date.now();
  for (const [d, ts] of VELOCITY.entries()) {
    const fresh = ts.filter(t => now - t < VEL_WINDOW);
    if (!fresh.length) VELOCITY.delete(d);
    else               VELOCITY.set(d, fresh);
  }
}

// ════════════════════════════════════════════════════════════════
// §13 Offline phishing cache
// ════════════════════════════════════════════════════════════════

async function refreshPhishingCache() {
  if (Date.now() - PHISH_TS < PHISH_TTL) return;
  try {
    const api  = await getAPI();
    const resp = await fetch(`${api}/api/phishing/cache`, { signal: AbortSignal.timeout(8000) });
    if (resp.ok) {
      const data = await resp.json();
      if (Array.isArray(data.domains)) {
        PHISH_CACHE.clear();
        data.domains.forEach(d => PHISH_CACHE.add(d.toLowerCase()));
        PHISH_TS = Date.now();
        chrome.storage.local.set({ phishDomains: [...PHISH_CACHE], phishTs: PHISH_TS });
        return;
      }
    }
  } catch {}
  // Load from persisted cache on error
  chrome.storage.local.get({ phishDomains: [], phishTs: 0 }, (d) => {
    if (d.phishDomains.length) {
      d.phishDomains.forEach(x => PHISH_CACHE.add(x));
      PHISH_TS = d.phishTs;
    }
  });
}

function isKnownPhishing(url) {
  try {
    const host  = new URL(url).hostname.toLowerCase();
    if (PHISH_CACHE.has(host)) return true;
    const parts = host.split(".");
    if (parts.length > 2 && PHISH_CACHE.has(parts.slice(-2).join("."))) return true;
  } catch {}
  return false;
}

// ════════════════════════════════════════════════════════════════
// §14 WebSocket — live alert relay
// ════════════════════════════════════════════════════════════════

async function connectWS() {
  if (_ws && (_ws.readyState === WebSocket.OPEN || _ws.readyState === WebSocket.CONNECTING)) return;
  try {
    const api   = await getAPI();
    const wsUrl = api.replace(/^http/, "ws") + "/ws/alerts";
    _ws         = new WebSocket(wsUrl);
    _ws.onopen  = () => { _wsDelay = 3000; };
    _ws.onmessage = (ev) => {
      try {
        const evt = JSON.parse(ev.data);
        chrome.tabs.query({}, tabs =>
          tabs.forEach(t => sendToContent(t.id, { type: "FRAUDX_WS_ALERT", event: evt }))
        );
      } catch {}
    };
    _ws.onclose = () => {
      _ws      = null;
      _wsDelay = Math.min(_wsDelay * 2, WS_MAX);
      setTimeout(connectWS, _wsDelay);
    };
    _ws.onerror = () => { try { _ws?.close(); } catch {} };
  } catch {
    _wsDelay = Math.min(_wsDelay * 2, WS_MAX);
    setTimeout(connectWS, _wsDelay);
  }
}

// ════════════════════════════════════════════════════════════════
// Ignored-pages helpers
// ════════════════════════════════════════════════════════════════

function getIgnoredPages() {
  return new Promise(resolve =>
    chrome.storage.sync.get({ fraudx_ignored_pages: [] }, d =>
      resolve(new Set(d.fraudx_ignored_pages || []))
    )
  );
}

function getPageKey(url) {
  try { const u = new URL(url); return u.origin + u.pathname; } catch { return null; }
}

async function isIgnored(url) {
  if (!url) return false;
  const key = getPageKey(url);
  return key ? (await getIgnoredPages()).has(key) : false;
}

async function addIgnoredPage(url) {
  const key = getPageKey(url);
  if (!key) return;
  const s = await getIgnoredPages();
  s.add(key);
  await chrome.storage.sync.set({ fraudx_ignored_pages: [...s] });
}

async function removeIgnoredPage(url) {
  const key = getPageKey(url);
  if (!key) return;
  const s = await getIgnoredPages();
  s.delete(key);
  await chrome.storage.sync.set({ fraudx_ignored_pages: [...s] });
}

// ════════════════════════════════════════════════════════════════
// §1 Payment URL detection
// ════════════════════════════════════════════════════════════════

const PAYMENT_URL_RE = [
  /\/checkout/i, /\/payment/i, /\/pay(?:\/|$|\?|#)/i,
  /\/order[/-]?confirm/i, /\/billing/i, /\/purchase/i,
  /\/cart[/-]checkout/i, /\/cart\/pay/i, /\/complete[/-]?order/i,
  /\/finalize/i, /\/secure[/-]?pay/i, /\/donate/i,
  /\/proceed[/-]?to[/-]?pay/i, /\/gateway/i, /\/confirm[/-]?payment/i,
  /[?&]payment[=&]/i, /[?&]checkout[=&]/i,
];
const PAYMENT_SUBDOMAINS = new Set([
  "pay","payment","checkout","secure","billing","order","cart","buy","gateway"
]);

function isPaymentUrl(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    if (PAYMENT_URL_RE.some(re => re.test(u.pathname + u.search))) return true;
    if (PAYMENT_SUBDOMAINS.has(u.hostname.split(".")[0]))           return true;
  } catch {}
  return false;
}

function shouldSkip(url) {
  if (!url) return true;
  try {
    const u = new URL(url);
    if (!["http:","https:"].includes(u.protocol))              return true;
    if (SKIP_HOSTS.has(u.hostname))                            return true;
    if (u.hostname === "localhost" || u.hostname.startsWith("127.")) return true;
  } catch { return true; }
  return false;
}

// ════════════════════════════════════════════════════════════════
// Badge helpers (§8 risk bands: 0-30 safe · 31-60 suspicious ·
//                               61-80 high · 81-100 critical)
// ════════════════════════════════════════════════════════════════

function riskBand(score) {
  if (score >= 81) return "danger";
  if (score >= 61) return "danger";
  if (score >= 31) return "caution";
  return "safe";
}

function setBadge(tabId, level, score) {
  let text, color;
  if (typeof score === "number") {
    text  = score >= 10 ? String(score) : `0${score}`;
    color = score >= 81 ? "#DC2626" : score >= 61 ? "#C05621" : score >= 31 ? "#D97706" : "#059669";
  } else {
    text  = level === "danger" ? "!" : level === "caution" ? "?" : "✓";
    color = level === "danger" ? "#DC2626" : level === "caution" ? "#D97706" : "#059669";
  }
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}
const setBadgeScanning = (id) => {
  chrome.action.setBadgeText({ text: "…",  tabId: id });
  chrome.action.setBadgeBackgroundColor({ color: "#6B7280", tabId: id });
};
const setBadgePayment  = (id) => {
  chrome.action.setBadgeText({ text: "💳", tabId: id });
  chrome.action.setBadgeBackgroundColor({ color: "#7C3AED", tabId: id });
};
const setBadgeIgnored  = (id) => {
  chrome.action.setBadgeText({ text: "–",  tabId: id });
  chrome.action.setBadgeBackgroundColor({ color: "#9CA3AF", tabId: id });
};
const clearBadge       = (id) => chrome.action.setBadgeText({ text: "", tabId: id });

// ════════════════════════════════════════════════════════════════
// Content relay + storage
// ════════════════════════════════════════════════════════════════

function sendToContent(tabId, msgObj) {
  chrome.tabs.sendMessage(tabId, msgObj).catch(() =>
    chrome.scripting?.executeScript({ target: { tabId }, files: ["content.js"] })
      .then(() => chrome.tabs.sendMessage(tabId, msgObj).catch(() => {}))
      .catch(() => {})
  );
}

function storeResult(url, result) {
  chrome.storage.local.get({ recentScans: [] }, ({ recentScans }) => {
    const out = recentScans.filter(s => s.url !== url);
    out.unshift({ url, result, ts: Date.now() });
    chrome.storage.local.set({ recentScans: out.slice(0, 30) });
  });
}

function storePaymentResult(tabId, url, result) {
  TAB_PAYMENT.set(tabId, { result, url, ts: Date.now() });
  chrome.storage.local.set({ [`pay_${tabId}`]: { result, url, ts: Date.now() } });
}

// ════════════════════════════════════════════════════════════════
// §20 OS notifications
// ════════════════════════════════════════════════════════════════

function notifyCritical(url, score, threat) {
  try {
    const host = new URL(url).hostname;
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icon48.png",          // fallback if icons/ subfolder missing
      title:    "FRAUD-X: Dangerous Site!",
      message:  `${host} — Risk ${score}/100\n${threat || "Fraud signals detected"}`,
      priority: 2,
    });
  } catch {}
}

// ════════════════════════════════════════════════════════════════
// §2 Mode A — Standard URL scan
// ════════════════════════════════════════════════════════════════

async function scanUrl(url, tabId) {
  if (shouldSkip(url) || SCANNING.has(url)) return;
  if (await isIgnored(url)) { setBadgeIgnored(tabId); return; }

  // Instant offline check (§13/§18)
  if (isKnownPhishing(url)) {
    const result = {
      risk_level: "danger", risk_score: 95,
      primary_threat: "Known phishing domain (offline cache)",
      explanation: { primary_threat: "Known phishing domain", factors: [] },
      recommendation: "Do not enter any information on this site.",
    };
    CACHE.set(url, { result, ts: Date.now() });
    storeResult(url, result);
    TAB_RISK.set(tabId, { score: 95, level: "danger" });
    setBadge(tabId, "danger", 95);
    sendToContent(tabId, { type: "FRAUDX_RESULT", result, url });
    notifyCritical(url, 95, "Known phishing domain");
    return;
  }

  const hit = CACHE.get(url);
  if (hit && Date.now() - hit.ts < CACHE_TTL) {
    setBadge(tabId, hit.result.risk_level, hit.result.risk_score);
    if (hit.result.risk_level !== "safe")
      sendToContent(tabId, { type: "FRAUDX_RESULT", result: hit.result, url });
    return;
  }

  SCANNING.add(url);
  setBadgeScanning(tabId);
  try {
    const api  = await getAPI();
    const resp = await fetch(`${api}/api/scan/url`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, use_ai: false }),
      signal:  AbortSignal.timeout(8000),
    });
    if (!resp.ok) { clearBadge(tabId); return; }

    const result = await resp.json();
    CACHE.set(url, { result, ts: Date.now() });
    storeResult(url, result);
    TAB_RISK.set(tabId, { score: result.risk_score, level: result.risk_level });
    setBadge(tabId, result.risk_level, result.risk_score);

    if (result.risk_level !== "safe") {
      sendToContent(tabId, { type: "FRAUDX_RESULT", result, url });
      if (result.risk_score >= 81) notifyCritical(url, result.risk_score, result.primary_threat);
    }
  } catch {
    clearBadge(tabId);
  } finally {
    SCANNING.delete(url);
  }
}

// ════════════════════════════════════════════════════════════════
// §1/§4 Mode B — Payment page scan
// ════════════════════════════════════════════════════════════════

async function scanPaymentPage(url, tabId, metadata = {}, biometrics = null) {
  if (PAY_SCAN.has(url)) return;
  if (await isIgnored(url)) { setBadgeIgnored(tabId); return; }
  PAY_SCAN.add(url);
  setBadgePayment(tabId);
  try {
    const api  = await getAPI();
    const body = {
      url,
      use_ai:           false,
      page_title:       metadata.page_title       || null,
      merchant_name:    metadata.merchant_name     || null,
      has_payment_form: metadata.has_payment_form  || false,
      form_action_url:  metadata.form_action_url   || null,
      form_field_names: metadata.form_field_names  || [],
      biometric_risk:   biometrics?.risk_score     || null,
    };
    const resp = await fetch(`${api}/api/scan/payment`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
      signal:  AbortSignal.timeout(12000),
    });
    if (!resp.ok) return;

    const result = await resp.json();
    storePaymentResult(tabId, url, result);
    setBadge(tabId, result.risk_level, result.risk_score);
    sendToContent(tabId, { type: "FRAUDX_PAYMENT_RESULT", result, url });
    if (result.risk_score >= 81) notifyCritical(url, result.risk_score, result.primary_threat);
  } catch {
    /* silent fallback */
  } finally {
    PAY_SCAN.delete(url);
  }
}

// ════════════════════════════════════════════════════════════════
// Navigation listener
// ════════════════════════════════════════════════════════════════

chrome.webNavigation.onCommitted.addListener(({ url, tabId, frameId, transitionType }) => {
  if (frameId !== 0)                      return;
  if (transitionType === "auto_subframe") return;

  // §12 Velocity tracking
  if (!shouldSkip(url)) {
    try {
      const host  = new URL(url).hostname;
      const count = recordVelocity(host);
      const vRisk = getVelocityRisk(count);
      if (vRisk) {
        chrome.storage.local.set({ [`vel_${tabId}`]: { count, ...vRisk, host } });
        sendToContent(tabId, { type: "FRAUDX_VELOCITY", count, host, ...vRisk });
      }
    } catch {}
  }

  scanUrl(url, tabId);

  if (isPaymentUrl(url) && !shouldSkip(url)) {
    setTimeout(() => { if (!PAY_SCAN.has(url)) scanPaymentPage(url, tabId, {}); }, 600);
  }
});

// ════════════════════════════════════════════════════════════════
// Tab lifecycle
// ════════════════════════════════════════════════════════════════

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    clearBadge(tabId);
    chrome.storage.local.remove([`pay_${tabId}`, `vel_${tabId}`]);
    TAB_PAYMENT.delete(tabId);
    TAB_RISK.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.local.remove([`pay_${tabId}`, `vel_${tabId}`]);
  TAB_PAYMENT.delete(tabId);
  TAB_RISK.delete(tabId);
});

// ════════════════════════════════════════════════════════════════
// §19 Alarm-based periodic tasks
// ════════════════════════════════════════════════════════════════

chrome.alarms.create("fraudx_housekeeping",      { periodInMinutes: 60 });
chrome.alarms.create("fraudx_velocity_cleanup",  { periodInMinutes: 1  });

chrome.alarms.onAlarm.addListener(({ name }) => {
  if (name === "fraudx_housekeeping") {
    refreshPhishingCache();
    connectWS();
    const cutoff = Date.now() - CACHE_TTL;
    for (const [url, { ts }] of CACHE.entries()) { if (ts < cutoff) CACHE.delete(url); }
  }
  if (name === "fraudx_velocity_cleanup") cleanVelocity();
});

// ════════════════════════════════════════════════════════════════
// §20 Context menu — right-click any link to scan it
// ════════════════════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "fraudx_scan_link", title: "Scan Link with FRAUD-X",     contexts: ["link"] });
  chrome.contextMenus.create({ id: "fraudx_scan_page", title: "Scan This Page with FRAUD-X", contexts: ["page"] });
  refreshPhishingCache();
  connectWS();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const url = info.linkUrl || info.pageUrl;
  if (!url || !tab?.id) return;
  const api = await getAPI();
  try {
    const resp = await fetch(`${api}/api/scan/url`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, use_ai: false }),
      signal:  AbortSignal.timeout(8000),
    });
    if (!resp.ok) return;
    const result = await resp.json();
    CACHE.set(url, { result, ts: Date.now() });
    storeResult(url, result);
    sendToContent(tab.id, { type: "FRAUDX_CONTEXT_RESULT", result, url });
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icon48.png",
      title:    `FRAUD-X: ${result.risk_level.toUpperCase()}`,
      message:  `Risk ${result.risk_score}/100 — ${result.primary_threat || new URL(url).hostname}`,
      priority: result.risk_score >= 61 ? 2 : 0,
    });
  } catch {}
});

// ════════════════════════════════════════════════════════════════
// Message router
// ════════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // §1 Content-script reports payment page (with DOM metadata + biometrics)
  if (msg.type === "PAYMENT_PAGE_DETECTED") {
    const tabId = sender.tab?.id;
    if (!tabId || !msg.url) return;
    PAY_SCAN.delete(msg.url);
    scanPaymentPage(msg.url, tabId, msg.metadata || {}, msg.biometrics || null);
    return;
  }

  // Popup: manual scan
  if (msg.type === "SCAN_NOW") {
    chrome.tabs.get(msg.tabId, (tab) => {
      if (!tab?.url) { sendResponse({ error: "No URL" }); return; }
      CACHE.delete(tab.url);
      scanUrl(tab.url, msg.tabId);
      sendResponse({ ok: true, url: tab.url });
    });
    return true;
  }

  // Popup: manual payment scan
  if (msg.type === "SCAN_PAYMENT_NOW") {
    chrome.tabs.get(msg.tabId, (tab) => {
      if (!tab?.url) { sendResponse({ error: "No URL" }); return; }
      PAY_SCAN.delete(tab.url);
      chrome.tabs.sendMessage(msg.tabId, { type: "EXTRACT_PAYMENT_CONTEXT" }, (meta) => {
        scanPaymentPage(tab.url, msg.tabId, meta || {});
        sendResponse({ ok: true, url: tab.url });
      });
    });
    return true;
  }

  if (msg.type === "PAYMENT_CONTEXT_REPLY") {
    const tabId = sender.tab?.id;
    if (!tabId || !msg.url) return;
    PAY_SCAN.delete(msg.url);
    scanPaymentPage(msg.url, tabId, msg.metadata || {});
    return;
  }

  if (msg.type === "IGNORE_PAGE") {
    chrome.tabs.get(msg.tabId, async (tab) => {
      if (!tab?.url) { sendResponse({ ok: false }); return; }
      try {
        await addIgnoredPage(tab.url);
        const pageKey = getPageKey(tab.url);
        CACHE.delete(tab.url);
        chrome.storage.local.remove([`pay_${msg.tabId}`, `vel_${msg.tabId}`]);
        TAB_PAYMENT.delete(msg.tabId);
        setBadgeIgnored(msg.tabId);
        sendToContent(msg.tabId, { type: "FRAUDX_IGNORED" });
        sendResponse({ ok: true, pageKey });
      } catch { sendResponse({ ok: false }); }
    });
    return true;
  }

  if (msg.type === "UNIGNORE_PAGE") {
    chrome.tabs.get(msg.tabId, async (tab) => {
      if (!tab?.url) { sendResponse({ ok: false }); return; }
      try {
        await removeIgnoredPage(tab.url);
        clearBadge(msg.tabId);
        sendResponse({ ok: true, pageKey: getPageKey(tab.url) });
      } catch { sendResponse({ ok: false }); }
    });
    return true;
  }

  if (msg.type === "CHECK_IGNORED") {
    chrome.tabs.get(msg.tabId, async (tab) => {
      if (!tab?.url) { sendResponse({ ignored: false }); return; }
      try {
        const ignored = await isIgnored(tab.url);
        sendResponse({ ignored, pageKey: getPageKey(tab.url) });
      } catch { sendResponse({ ignored: false }); }
    });
    return true;
  }

  if (msg.type === "GET_VELOCITY") {
    chrome.storage.local.get(`vel_${msg.tabId}`, (res) => {
      sendResponse(res[`vel_${msg.tabId}`] || null);
    });
    return true;
  }

  if (msg.type === "GET_TAB_RISK") {
    sendResponse(TAB_RISK.get(msg.tabId) || null);
    return;
  }

});

// ════════════════════════════════════════════════════════════════
// Service worker init
// ════════════════════════════════════════════════════════════════

refreshPhishingCache();
connectWS();
