/**
 * FRAUD-X Shield — Enterprise Popup Script  v3.0
 * ================================================
 * §8  Adaptive risk scoring display
 * §17 AI chat assistant (backend relay)
 * §21 Admin dashboard integration
 */

"use strict";

const DEFAULT_API = "http://localhost:8000";
let _currentTab   = null;
let _currentUrl   = "";
let _apiBase      = DEFAULT_API;
let _riskResult   = null;   // current URL scan result
let _payResult    = null;   // current payment scan result

// ════════════════════════════════════════════════════════════════
// Utility
// ════════════════════════════════════════════════════════════════

function esc(s) {
  return String(s || "").replace(/[&<>"']/g, c =>
    ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c])
  );
}

function fmt(ts) {
  return new Date(ts).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" });
}

function trunc(s, n = 38) {
  return (s || "").length > n ? s.slice(0, n) + "…" : (s || "");
}

function getAPI() {
  return new Promise(resolve =>
    chrome.storage.sync.get({ fraudx_api_url: DEFAULT_API }, d =>
      resolve((d.fraudx_api_url || DEFAULT_API).replace(/\/$/, ""))
    )
  );
}

// ════════════════════════════════════════════════════════════════
// Tab system
// ════════════════════════════════════════════════════════════════

document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${tab}`)?.classList.add("active");
    if (tab === "threats") renderThreats();
    if (tab === "chat")    updateChatContext();
    if (tab === "settings") loadSettings();
  });
});

// ════════════════════════════════════════════════════════════════
// §8 Risk score display
// ════════════════════════════════════════════════════════════════

function riskBand(score) {
  if (score >= 81) return "danger";
  if (score >= 61) return "high";
  if (score >= 31) return "caution";
  return "safe";
}

function renderRisk(result, url) {
  const level  = result?.risk_level  || "pending";
  const score  = result?.risk_score  ?? null;
  const threat = result?.primary_threat || result?.explanation?.primary_threat || "";
  const factors= result?.explanation?.factors || [];

  const ring   = document.getElementById("riskRing");
  const sc     = document.getElementById("riskScore");
  const lbl    = document.getElementById("riskLbl");
  const pill   = document.getElementById("riskPill");
  const urlEl  = document.getElementById("riskUrl");
  const threatEl = document.getElementById("riskThreat");
  const sigRow  = document.getElementById("signalsRow");

  const band = score != null ? riskBand(score) : (level === "danger" ? "danger" : level === "caution" ? "caution" : level === "safe" ? "safe" : "pending");

  // Colors
  const bandColor = { danger:"#DC2626", high:"#C05621", caution:"#D97706", safe:"#059669", pending:"#9CA3AF" };
  const c = bandColor[band] || "#9CA3AF";

  // Ring
  ring.className = `risk-ring ${band}`;
  sc.className   = `risk-score ${band}`;
  sc.textContent = score != null ? score : "—";
  lbl.style.color= c;

  // Pill
  const labelMap = { danger:"Dangerous", high:"High Risk", caution:"Suspicious", safe:"Safe", pending:"Not Scanned" };
  pill.className = `risk-level-pill ${band}`;
  pill.textContent = labelMap[band] || "Unknown";

  // URL
  if (url) {
    try { urlEl.textContent = trunc(new URL(url).hostname + new URL(url).pathname.slice(0,30), 42); }
    catch { urlEl.textContent = trunc(url, 42); }
  }

  // Threat
  if (threat) {
    threatEl.textContent = threat;
    threatEl.style.display = "block";
  } else {
    threatEl.style.display = "none";
  }

  // Signal chips (top 5 non-informational)
  const topFactors = factors
    .filter(f => f.impact > 0 && f.severity !== "informational")
    .sort((a, b) => b.impact - a.impact)
    .slice(0, 5);

  if (topFactors.length) {
    sigRow.style.display = "flex";
    sigRow.innerHTML = topFactors.map(f => {
      const sev = f.severity === "critical" ? "danger"
                : f.severity === "high"     ? "high"
                : f.severity === "medium"   ? "caution"
                :                             "info";
      return `<span class="signal-chip ${sev}">+${f.impact} ${esc(f.factor)}</span>`;
    }).join("");
  } else {
    sigRow.style.display = "none";
  }
}

// ════════════════════════════════════════════════════════════════
// Payment badge
// ════════════════════════════════════════════════════════════════

function renderPayment(payResult) {
  const badge   = document.getElementById("payBadge");
  const status  = document.getElementById("payStatus");
  const detail  = document.getElementById("payDetail");

  if (!payResult) {
    badge.className  = "payment-badge";
    badge.querySelector(".pmt-icon").textContent = "🛡️";
    status.className = "pmt-status"; status.style.color = "#6B7280";
    status.textContent = "Not a payment page";
    detail.textContent = "Navigate to a checkout to activate";
    badge.querySelector(".pmt-score")?.remove();
    return;
  }

  const level   = payResult.risk_level || "safe";
  const score   = payResult.risk_score ?? 0;
  const trusted = payResult.is_trusted_gateway || level === "safe";
  const gateway = payResult.verified_gateway   || "";

  let cls, icon, st, dt;
  if (trusted && gateway) {
    cls="trusted"; icon="✅"; st="Verified Gateway"; dt=`✓ ${gateway}`;
  } else if (level === "danger") {
    cls="danger";  icon="🚨"; st="Dangerous Payment Page"; dt=payResult.explanation?.primary_threat||"Fake gateway detected";
  } else if (level === "caution") {
    cls="caution"; icon="⚠️"; st="Suspicious Payment Page"; dt=payResult.explanation?.primary_threat||"Verify before submitting";
  } else {
    cls="trusted"; icon="🛡️"; st="Payment Page — Low Risk"; dt="No gateway fraud signals";
  }

  badge.className = `payment-badge ${cls}`;
  badge.querySelector(".pmt-icon").textContent = icon;
  status.className = `pmt-status ${cls}`; status.style.color = "";
  status.textContent = st;
  detail.textContent = dt;

  let pill = badge.querySelector(".pmt-score");
  if (!pill) { pill = document.createElement("span"); badge.appendChild(pill); }
  pill.className   = `pmt-score ${cls}`;
  pill.textContent = trusted && gateway ? "✓" : `${score}/100`;
}

// ════════════════════════════════════════════════════════════════
// Stats row
// ════════════════════════════════════════════════════════════════

function renderStats(vel, devTrust, apiOk) {
  const vv = document.getElementById("velValue");
  const vs = document.getElementById("velSub");
  if (vel) {
    vv.textContent = vel.count;
    vv.style.color = vel.level === "critical" ? "#DC2626" : vel.level === "high" ? "#D97706" : "#111827";
    vs.textContent = `pages/min (${vel.level})`;
  } else {
    vv.textContent = "—"; vv.style.color = "#9CA3AF"; vs.textContent = "pages/min";
  }

  const dv = document.getElementById("devTrust");
  const ds = document.getElementById("devSub");
  if (devTrust != null) {
    dv.textContent = `${devTrust}%`;
    dv.style.color = devTrust >= 80 ? "#059669" : devTrust >= 50 ? "#D97706" : "#DC2626";
    ds.textContent = devTrust >= 80 ? "trusted" : devTrust >= 50 ? "moderate" : "suspicious";
  }

  const av = document.getElementById("apiStatus");
  const as = document.getElementById("apiSub");
  av.textContent = apiOk ? "Online" : "Offline";
  av.style.color = apiOk ? "#059669" : "#DC2626";
  as.textContent = apiOk ? "connected" : "start server";
}

// ════════════════════════════════════════════════════════════════
// Health check
// ════════════════════════════════════════════════════════════════

async function checkHealth() {
  const dot  = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  try {
    const r = await fetch(`${_apiBase}/api/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      const h = await r.json();
      dot.className  = "dot-live";
      text.textContent = `Online · ${h.alerts ?? 0} alerts`;
      return true;
    }
  } catch {}
  dot.className  = "dot-offline";
  text.textContent = "API offline — start uvicorn";
  return false;
}

// ════════════════════════════════════════════════════════════════
// Threats list
// ════════════════════════════════════════════════════════════════

function renderThreats() {
  chrome.storage.local.get({ recentScans: [] }, ({ recentScans }) => {
    const list = document.getElementById("threatList");
    if (!recentScans?.length) {
      list.innerHTML = `<div class="empty">No scans yet — browse any page!</div>`;
      return;
    }
    list.innerHTML = recentScans.slice(0, 20).map(s => {
      const lv    = s.result?.risk_level || "safe";
      const score = s.result?.risk_score ?? 0;
      const kind  = s.result?.kind || "url";
      const band  = riskBand(score);
      let host    = s.url;
      try { host = new URL(s.url).hostname; } catch {}
      return `<div class="threat-item">
        <span class="threat-dot ${band}"></span>
        <span class="threat-host" title="${esc(s.url)}">${esc(trunc(host, 32))}</span>
        <span class="threat-kind">${esc(kind)}</span>
        <span class="threat-score ${band}">${score}</span>
        <span class="threat-time">${fmt(s.ts)}</span>
      </div>`;
    }).join("");
  });
}

// ════════════════════════════════════════════════════════════════
// §17 AI Chat
// ════════════════════════════════════════════════════════════════

const chatLog   = document.getElementById("chatLog");
const chatInput = document.getElementById("chatInput");
const chatSend  = document.getElementById("chatSend");

function updateChatContext() {
  const badge  = document.getElementById("chatCtxBadge");
  if (!badge) return;
  const level  = _riskResult?.risk_level || _payResult?.risk_level || "none";
  const score  = _riskResult?.risk_score ?? _payResult?.risk_score ?? null;
  const colors = {
    danger:  { bg:"#FEF2F2", color:"#DC2626" },
    caution: { bg:"#FFFBEB", color:"#D97706" },
    safe:    { bg:"#ECFDF5", color:"#059669" },
    none:    { bg:"#F3F4F6", color:"#9CA3AF" },
  };
  const c = colors[level] || colors.none;
  badge.style.background = c.bg;
  badge.style.color      = c.color;
  badge.textContent = score != null ? `Risk ${score} · ${level}` : `No scan yet`;
}

function appendMsg(text, from, typing = false) {
  const el = document.createElement("div");
  el.className = `chat-msg ${from}${typing ? " typing" : ""}`;
  el.textContent = text;
  chatLog.appendChild(el);
  chatLog.scrollTop = chatLog.scrollHeight;
  return el;
}

async function sendChat() {
  const msg = chatInput.value.trim();
  if (!msg) return;
  chatInput.value  = "";
  chatSend.disabled = true;
  appendMsg(msg, "user");
  const typingEl = appendMsg("Thinking…", "bot", true);
  try {
    const resp = await fetch(`${_apiBase}/api/chat`, {
      method:  "POST",
      headers: { "Content-Type":"application/json" },
      body:    JSON.stringify({
        message: msg,
        context: {
          url:     _currentUrl,
          risk:    _riskResult,
          payment: _payResult,
        },
      }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await resp.json();
    typingEl.classList.remove("typing");
    typingEl.textContent = data.reply || data.message || data.detail || "No response.";
  } catch (err) {
    typingEl.classList.remove("typing");
    typingEl.textContent = "AI assistant unavailable. Make sure the FRAUD-X server is running.";
  } finally {
    chatSend.disabled = false;
    chatInput.focus();
  }
}

chatSend.addEventListener("click", sendChat);
chatInput.addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });

// ════════════════════════════════════════════════════════════════
// Settings
// ════════════════════════════════════════════════════════════════

function loadSettings() {
  document.getElementById("apiUrlInput").value = _apiBase;
  chrome.storage.sync.get({
    fraudx_notif: true,
    fraudx_hud:   true,
    fraudx_biometrics: true,
    fraudx_ignored_pages: [],
  }, (d) => {
    document.getElementById("notifEnabled").checked    = d.fraudx_notif;
    document.getElementById("hudEnabled").checked      = d.fraudx_hud;
    document.getElementById("biometricEnabled").checked= d.fraudx_biometrics;
    const il = document.getElementById("ignoredList");
    if (d.fraudx_ignored_pages.length) {
      il.innerHTML = d.fraudx_ignored_pages.map(p =>
        `<div style="display:flex;justify-content:space-between;align-items:center;
          padding:4px 0;border-bottom:1px solid #F3F4F6">
          <span style="font-size:10.5px;overflow:hidden;text-overflow:ellipsis;
            white-space:nowrap;flex:1">${esc(trunc(p, 38))}</span>
          <button data-page="${esc(p)}" style="font-size:10px;color:#DC2626;background:none;
            border:none;cursor:pointer;padding:0 4px" class="remove-ignored">✕</button>
        </div>`
      ).join("");
      il.querySelectorAll(".remove-ignored").forEach(btn => {
        btn.addEventListener("click", async () => {
          const page = btn.dataset.page;
          chrome.storage.sync.get({ fraudx_ignored_pages: [] }, (d2) => {
            const updated = d2.fraudx_ignored_pages.filter(p => p !== page);
            chrome.storage.sync.set({ fraudx_ignored_pages: updated }, loadSettings);
          });
        });
      });
    } else {
      il.textContent = "No ignored pages.";
    }
  });
}

document.getElementById("saveApi").addEventListener("click", () => {
  const val = document.getElementById("apiUrlInput").value.trim().replace(/\/$/, "");
  if (!val) return;
  _apiBase = val;
  chrome.storage.sync.set({ fraudx_api_url: val }, () => {
    document.getElementById("openDash").href = `${val}/`;
    checkHealth();
  });
});

["notifEnabled","hudEnabled","biometricEnabled"].forEach(id => {
  document.getElementById(id).addEventListener("change", (e) => {
    const keyMap = { notifEnabled:"fraudx_notif", hudEnabled:"fraudx_hud", biometricEnabled:"fraudx_biometrics" };
    chrome.storage.sync.set({ [keyMap[id]]: e.target.checked });
  });
});

// ════════════════════════════════════════════════════════════════
// Ignore/un-ignore buttons
// ════════════════════════════════════════════════════════════════

let _isIgnored = false;

function applyIgnoreState(ignored) {
  _isIgnored = ignored;
  const btn    = document.getElementById("ignoreBtn");
  const notice = document.getElementById("ignoreNotice");
  const scanBtn= document.getElementById("scanBtn");
  const payBtn = document.getElementById("payBtn");
  if (ignored) {
    btn.textContent = "↩ Resume Scanning";
    btn.className   = "btn btn-ignore active";
    notice.classList.add("show");
    scanBtn.disabled = true;
    payBtn.disabled  = true;
  } else {
    btn.textContent = "🚫 Ignore";
    btn.className   = "btn btn-ignore";
    notice.classList.remove("show");
    scanBtn.disabled = false;
    payBtn.disabled  = false;
  }
}

document.getElementById("ignoreBtn").addEventListener("click", () => {
  if (!_currentTab?.id) return;
  const wasIgnored = _isIgnored;
  const type = wasIgnored ? "UNIGNORE_PAGE" : "IGNORE_PAGE";
  chrome.runtime.sendMessage({ type, tabId: _currentTab.id }, (resp) => {
    if (resp?.ok) {
      applyIgnoreState(!wasIgnored);
      if (!wasIgnored) {
        // Just ignored this page — clear stale scan displays
        renderRisk(null, _currentUrl);
        renderPayment(null);
      }
    }
  });
});

// ════════════════════════════════════════════════════════════════
// Scan buttons
// ════════════════════════════════════════════════════════════════

document.getElementById("scanBtn").addEventListener("click", async () => {
  if (!_currentTab?.id) return;
  const btn       = document.getElementById("scanBtn");
  btn.disabled    = true;
  btn.textContent = "⏳ Scanning…";
  chrome.runtime.sendMessage({ type: "SCAN_NOW", tabId: _currentTab.id }, () => {
    let tries = 0;
    const poll = setInterval(() => {
      chrome.storage.local.get({ recentScans: [] }, ({ recentScans }) => {
        const hit = recentScans.find(s => s.url === _currentUrl);
        if (hit || ++tries > 25) {
          clearInterval(poll);
          btn.disabled    = false;
          btn.textContent = "🔍 Scan";
          if (hit) { _riskResult = hit.result; renderRisk(hit.result, _currentUrl); }
        }
      });
    }, 400);
  });
});

document.getElementById("payBtn").addEventListener("click", async () => {
  if (!_currentTab?.id) return;
  const btn       = document.getElementById("payBtn");
  btn.disabled    = true;
  btn.textContent = "⏳ Scanning…";
  chrome.runtime.sendMessage({ type: "SCAN_PAYMENT_NOW", tabId: _currentTab.id }, () => {
    let tries = 0;
    const poll = setInterval(() => {
      chrome.storage.local.get(`pay_${_currentTab.id}`, (res) => {
        const pay = res[`pay_${_currentTab.id}`];
        if ((pay && pay.url === _currentUrl) || ++tries > 30) {
          clearInterval(poll);
          btn.disabled    = false;
          btn.textContent = "💳 Scan Payment";
          if (pay) { _payResult = pay.result; renderPayment(pay.result); }
        }
      });
    }, 400);
  });
});

// ════════════════════════════════════════════════════════════════
// Live storage updates
// ════════════════════════════════════════════════════════════════

chrome.storage.onChanged.addListener(async (changes) => {
  if (changes.recentScans?.newValue && _currentUrl) {
    const hit = changes.recentScans.newValue.find(s => s.url === _currentUrl);
    if (hit) { _riskResult = hit.result; renderRisk(hit.result, _currentUrl); }
    const active = document.querySelector(".tab-btn.active")?.dataset.tab;
    if (active === "threats") renderThreats();
  }
  if (_currentTab?.id) {
    const key = `pay_${_currentTab.id}`;
    if (changes[key]?.newValue?.url === _currentUrl) {
      _payResult = changes[key].newValue.result;
      renderPayment(_payResult);
    }
  }
});

// ════════════════════════════════════════════════════════════════
// Init
// ════════════════════════════════════════════════════════════════

(async () => {
  _apiBase = await getAPI();
  document.getElementById("openDash").href = `${_apiBase}/`;

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  _currentTab = tab;
  _currentUrl = tab?.url || "";

  // Show hostname while loading
  if (_currentUrl) {
    try { document.getElementById("riskUrl").textContent = trunc(new URL(_currentUrl).hostname, 40); } catch {}
  }

  // Health
  const apiOk = await checkHealth();

  // Current page URL scan result
  chrome.storage.local.get({ recentScans: [] }, ({ recentScans }) => {
    const hit = _currentUrl ? recentScans.find(s => s.url === _currentUrl) : null;
    _riskResult = hit?.result ?? null;
    renderRisk(_riskResult, _currentUrl);
    renderThreats();
  });

  // Current tab payment scan result
  if (tab?.id != null) {
    chrome.storage.local.get(`pay_${tab.id}`, (res) => {
      const pay = res[`pay_${tab.id}`];
      _payResult = (pay && pay.url === _currentUrl) ? pay.result : null;
      renderPayment(_payResult);
    });
  }

  // Velocity for current tab
  let vel = null;
  if (tab?.id) {
    chrome.runtime.sendMessage({ type: "GET_VELOCITY", tabId: tab.id }, (v) => {
      vel = v;
      renderStats(vel, null, apiOk);
    });
  }

  // Device trust (simple computation from navigator)
  let devTrust = 80;
  try {
    if (!navigator.cookieEnabled) devTrust -= 10;
    if (!navigator.hardwareConcurrency) devTrust -= 15;
    if (navigator.plugins?.length === 0) devTrust -= 5;
  } catch {}
  renderStats(vel, devTrust, apiOk);

  // Ignore state
  if (tab?.id) {
    chrome.runtime.sendMessage({ type: "CHECK_IGNORED", tabId: tab.id }, (resp) => {
      applyIgnoreState(resp?.ignored || false);
    });
  }

  // Chat context
  updateChatContext();

})();
