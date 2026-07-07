/**
 * FRAUD-X Shield — Enterprise Content Script  v3.0
 * ==================================================
 * Runs in every page context at document_start.
 *
 * §1  Real-time payment page detection (DOM analysis)
 * §4  Payment gateway signals
 * §6  Behavioral biometrics (mouse · keyboard · scroll · bot detection)
 * §7  Device fingerprinting (canvas · WebGL · timezone · language)
 * §8  Adaptive risk scoring display (bands: safe/suspicious/high/critical)
 * §9  Smart fraud response (blur · disable · block by risk level)
 * §10 Advanced warning popups with detailed fraud explanation
 * §11 Live draggable security overlay (dark/light mode · real-time)
 * §16 Privacy-preserving (no card storage, local biometrics processing)
 * §17 AI chat assistant widget (backend Gemini relay)
 * §18 Offline fraud detection signals
 * §19 Performance optimization (debounce · lazy init · passive listeners)
 */

(function () {
  "use strict";

  // ── Element IDs ───────────────────────────────────────────────
  const BANNER_ID      = "fraudx-banner";
  const OVERLAY_ID     = "fraudx-overlay";
  const TRUST_ID       = "fraudx-trust";
  const SECURITY_HUD   = "fraudx-hud";
  const CHAT_PANEL_ID  = "fraudx-chat";
  const BLOCKED_KEY    = "__fraudx_blocked__";

  // ── State ─────────────────────────────────────────────────────
  let _paymentResult     = null;
  let _paymentIntercepted= false;
  let _currentRisk       = null;
  let _hudVisible        = false;
  let _darkMode          = false;
  let _chatOpen          = false;

  // ════════════════════════════════════════════════════════════════
  // Utility
  // ════════════════════════════════════════════════════════════════

  function esc(s) {
    return String(s || "")
      .replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function debounce(fn, ms) {
    let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  // ════════════════════════════════════════════════════════════════
  // §6 Behavioral Biometrics Module
  // ════════════════════════════════════════════════════════════════

  const Biometrics = (() => {
    const mouse  = { speeds: [], angles: [], lastX: null, lastY: null, lastTs: 0 };
    const keys   = { intervals: [], lastTs: 0 };
    const scroll = { velocities: [], dirChanges: 0, lastDir: 0, lastTs: 0 };
    let   clicks = 0;
    let   _ready = false;

    function onMouseMove(e) {
      const now = Date.now();
      if (mouse.lastX !== null) {
        const dx = e.clientX - mouse.lastX;
        const dy = e.clientY - mouse.lastY;
        const dt = now - mouse.lastTs || 1;
        const dist = Math.sqrt(dx * dx + dy * dy);
        mouse.speeds.push(dist / dt * 100);  // px/100ms
        mouse.angles.push(Math.atan2(dy, dx));
        if (mouse.speeds.length > 200) { mouse.speeds.shift(); mouse.angles.shift(); }
      }
      mouse.lastX = e.clientX;
      mouse.lastY = e.clientY;
      mouse.lastTs = now;
    }

    function onKeyDown(e) {
      const now = Date.now();
      if (keys.lastTs) keys.intervals.push(now - keys.lastTs);
      keys.lastTs = now;
      if (keys.intervals.length > 100) keys.intervals.shift();
    }

    function onScroll() {
      const now = Date.now();
      const y   = window.scrollY;
      if (scroll.lastTs) {
        const dt  = now - scroll.lastTs || 1;
        const vel = Math.abs(y - (scroll._lastY || 0)) / dt * 100;
        scroll.velocities.push(vel);
        if (scroll.velocities.length > 100) scroll.velocities.shift();
        const dir = y > (scroll._lastY || 0) ? 1 : -1;
        if (dir !== scroll.lastDir && scroll.lastDir !== 0) scroll.dirChanges++;
        scroll.lastDir = dir;
      }
      scroll._lastY = y;
      scroll.lastTs = now;
    }

    function onClickCapture() { clicks++; }

    function _std(arr) {
      if (!arr.length) return 0;
      const m = arr.reduce((a, b) => a + b, 0) / arr.length;
      return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / arr.length);
    }

    function _mean(arr) {
      return arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;
    }

    // Bot detection heuristics
    function getRiskScore() {
      let risk = 0;
      const signals = [];

      // Mouse analysis
      if (mouse.speeds.length >= 10) {
        const stdSpeed = _std(mouse.speeds);
        const meanSpeed = _mean(mouse.speeds);
        // Bots: very uniform speed (low std) or impossibly fast
        if (stdSpeed < 0.5 && meanSpeed > 50) {
          risk += 25; signals.push("uniform_mouse");
        }
        // Completely straight lines (angles nearly constant)
        if (mouse.angles.length >= 10 && _std(mouse.angles) < 0.01) {
          risk += 20; signals.push("linear_mouse");
        }
      } else {
        // No mouse movement at all is suspicious on interactive pages
        risk += 10; signals.push("no_mouse");
      }

      // Keystroke analysis
      if (keys.intervals.length >= 5) {
        const stdKI = _std(keys.intervals);
        // Perfectly regular typing interval = bot
        if (stdKI < 5 && _mean(keys.intervals) < 100) {
          risk += 30; signals.push("robotic_typing");
        }
      }

      // Scroll analysis
      if (scroll.velocities.length >= 5) {
        const meanVel = _mean(scroll.velocities);
        if (meanVel > 800) { risk += 15; signals.push("rapid_scroll"); }
      }
      if (scroll.dirChanges < 1 && scroll.velocities.length > 20) {
        risk += 10; signals.push("no_scroll_change");
      }

      // No clicks on an interactive page
      if (clicks === 0 && Date.now() - _startTs > 5000) {
        risk += 10; signals.push("no_clicks");
      }

      return { risk_score: Math.min(100, risk), signals };
    }

    const _startTs = Date.now();

    function init() {
      if (_ready) return;
      _ready = true;
      // Use passive listeners for performance (§19)
      document.addEventListener("mousemove",  onMouseMove,    { passive: true, capture: false });
      document.addEventListener("keydown",    onKeyDown,      { passive: true, capture: false });
      window.addEventListener  ("scroll",     onScroll,       { passive: true });
      document.addEventListener("click",      onClickCapture, { passive: true, capture: true  });
    }

    return { init, getRiskScore };
  })();

  // ════════════════════════════════════════════════════════════════
  // §7 Device Fingerprinting Module
  // ════════════════════════════════════════════════════════════════

  const DeviceFingerprint = (() => {
    let _fp = null;

    function _canvasHash() {
      try {
        const c = document.createElement("canvas");
        c.width = 200; c.height = 50;
        const ctx = c.getContext("2d");
        ctx.textBaseline = "alphabetic";
        ctx.fillStyle    = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.font      = "11pt no-real-font-lol";
        ctx.fillText("FRAUD-X:93@#$!", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.font      = "18pt Arial";
        ctx.fillText("FRAUD-X:93@#$!", 4, 45);
        return c.toDataURL().slice(-40);
      } catch { return "canvas_blocked"; }
    }

    function _webglInfo() {
      try {
        const c   = document.createElement("canvas");
        const gl  = c.getContext("webgl") || c.getContext("experimental-webgl");
        if (!gl) return "webgl_none";
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        return ext
          ? `${gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)}|${gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)}`
          : `${gl.getParameter(gl.VENDOR)}|${gl.getParameter(gl.RENDERER)}`;
      } catch { return "webgl_err"; }
    }

    function collect() {
      if (_fp) return _fp;
      _fp = {
        canvas:    _canvasHash(),
        webgl:     _webglInfo(),
        lang:      navigator.language  || "und",
        langs:     (navigator.languages || []).join(","),
        tz:        Intl.DateTimeFormat().resolvedOptions().timeZone || "unknown",
        tzOffset:  new Date().getTimezoneOffset(),
        screen:    `${screen.width}x${screen.height}x${screen.colorDepth}`,
        platform:  navigator.platform || "unknown",
        cores:     navigator.hardwareConcurrency || 0,
        memory:    navigator.deviceMemory        || 0,
        plugins:   navigator.plugins?.length     || 0,
        touch:     navigator.maxTouchPoints       || 0,
        cookieOk:  navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack === "1",
      };
      // Simple trust scoring
      let trust = 100;
      if (_fp.canvas === "canvas_blocked") trust -= 15;
      if (_fp.cores  === 0)               trust -= 10;
      if (_fp.memory === 0)               trust -= 10;
      if (_fp.plugins === 0)              trust -= 5;
      _fp.trust_score = Math.max(0, trust);
      return _fp;
    }

    return { collect };
  })();

  // ════════════════════════════════════════════════════════════════
  // §8 DOM Mutation Fraud Detection
  // ════════════════════════════════════════════════════════════════

  const DOMGuard = (() => {
    let _observer   = null;
    let _hiddenIframes   = 0;
    let _formReplaced    = false;
    let _scriptInjections= 0;
    let _overlaysDetected= 0;
    let _externalFormAction = false;
    let _originalForms   = new WeakSet();

    function _checkNode(node) {
      if (!node || node.nodeType !== Node.ELEMENT_NODE) return;

      // Hidden iframes
      if (node.tagName === "IFRAME") {
        const s = node.style;
        const hidden = s.display === "none" || s.visibility === "hidden"
                    || parseInt(s.width || "9") < 2
                    || parseInt(s.height || "9") < 2;
        if (hidden) _hiddenIframes++;
      }

      // Injected scripts (not page-initial)
      if (node.tagName === "SCRIPT" && node.src && !node.src.startsWith(window.location.origin)) {
        _scriptInjections++;
      }

      // Form replacement detection
      if (node.tagName === "FORM" && !_originalForms.has(node)) {
        _formReplaced = true;
        // Check for external form action
        if (node.action) {
          try {
            const actionHost = new URL(node.action).hostname;
            if (actionHost && actionHost !== window.location.hostname) _externalFormAction = true;
          } catch {}
        }
      }

      // High-z-index overlays
      if (node.nodeType === Node.ELEMENT_NODE) {
        const z = parseInt(window.getComputedStyle(node).zIndex || "0");
        if (z > 9999 && node.id !== "fraudx-hud" && !node.id?.startsWith("fraudx")) {
          const rect = node.getBoundingClientRect();
          if (rect.width > 300 && rect.height > 200) _overlaysDetected++;
        }
      }
    }

    function init() {
      // Record initial forms
      document.querySelectorAll("form").forEach(f => _originalForms.add(f));

      _observer = new MutationObserver(mutations => {
        for (const m of mutations) {
          m.addedNodes.forEach(_checkNode);
        }
      });
      _observer.observe(document.documentElement, {
        childList:  true,
        subtree:    true,
        attributes: false,
      });
    }

    function getSignals() {
      return {
        hidden_iframes:      _hiddenIframes,
        form_replaced:       _formReplaced,
        script_injections:   _scriptInjections,
        overlays_detected:   _overlaysDetected,
        external_form_action:_externalFormAction,
      };
    }

    function stop() { _observer?.disconnect(); }

    return { init, getSignals, stop };
  })();

  // ════════════════════════════════════════════════════════════════
  // §9 Browser Environment Risk Analysis
  // ════════════════════════════════════════════════════════════════

  const BrowserEnv = (() => {
    function collect() {
      const env = {
        webdriver_detected: false,
        devtools_open:      false,
        popup_count:        0,
        redirect_count:     0,
        extension_count:    0,
        canvas_blocked:     false,
        font_count:         0,
        languages_count:    (navigator.languages || []).length,
        cookie_enabled:     navigator.cookieEnabled,
        storage_accessible: false,
      };

      // WebDriver / automation detection
      if (navigator.webdriver === true) env.webdriver_detected = true;
      if (window.__selenium_unwrapped || window._phantom || window.callPhantom ||
          window._WEBDRIVER_ELEM_CACHE || document.$chrome_asyncScriptInfo) {
        env.webdriver_detected = true;
      }
      // Headless Chrome detection
      if (/HeadlessChrome/.test(navigator.userAgent)) env.webdriver_detected = true;

      // DevTools detection via window size heuristic
      const threshold = 160;
      if ((window.outerWidth - window.innerWidth > threshold) ||
          (window.outerHeight - window.innerHeight > threshold)) {
        env.devtools_open = true;
      }

      // Canvas blocked check (reuse DeviceFingerprint result)
      try {
        const cv = document.createElement("canvas");
        env.canvas_blocked = !cv.getContext("2d");
      } catch { env.canvas_blocked = true; }

      // localStorage accessible
      try { localStorage.setItem("__fx_test", "1"); localStorage.removeItem("__fx_test"); env.storage_accessible = true; }
      catch {}

      // Redirect count from navigation timing
      try {
        const perf = performance.getEntriesByType("navigation")[0];
        env.redirect_count = perf?.redirectCount || 0;
      } catch {}

      // Font enumeration (headless browsers have very few)
      try {
        const fonts = ["Arial","Calibri","Courier New","Georgia","Helvetica",
                       "Impact","Palatino","Times New Roman","Trebuchet MS","Verdana",
                       "Comic Sans MS","Tahoma","Garamond","Book Antiqua"];
        let count = 0;
        const test = document.createElement("span");
        test.style.visibility = "hidden";
        test.style.position   = "absolute";
        test.textContent = "mmmmmmmmmmlli";
        document.body.appendChild(test);
        const base = test.offsetWidth;
        fonts.forEach(f => {
          test.style.fontFamily = `'${f}',monospace`;
          if (test.offsetWidth !== base) count++;
        });
        document.body.removeChild(test);
        env.font_count = count;
      } catch {}

      // Risk scoring
      let risk = 0;
      const signals = [];
      if (env.webdriver_detected) { risk += 50; signals.push("WebDriver detected"); }
      if (env.devtools_open)      { risk += 15; signals.push("DevTools open"); }
      if (env.redirect_count >= 3){ risk += 25; signals.push(`Redirect chain: ${env.redirect_count}`); }
      if (env.canvas_blocked)     { risk += 12; signals.push("Canvas blocked"); }
      if (env.font_count < 5)     { risk += 15; signals.push("Minimal fonts (headless)"); }
      if (!env.cookie_enabled)    { risk += 8;  signals.push("Cookies disabled"); }

      env.risk_score = Math.min(100, risk);
      env.signals    = signals;
      return env;
    }

    return { collect };
  })();

  // ════════════════════════════════════════════════════════════════
  // §10 Adaptive Behavioral Baselines
  // ════════════════════════════════════════════════════════════════

  const AdaptiveBaseline = (() => {
    const STORAGE_KEY = "fraudx_behavioral_baseline";
    const ALPHA       = 0.05;  // EMA smoothing — same as backend §10
    let _baseline     = null;

    function _load() {
      return new Promise(resolve => {
        try {
          chrome.storage.local.get([STORAGE_KEY], r => {
            _baseline = r[STORAGE_KEY] || null;
            resolve(_baseline);
          });
        } catch { resolve(null); }
      });
    }

    function _save(bl) {
      try { chrome.storage.local.set({ [STORAGE_KEY]: bl }); } catch {}
    }

    function _ema(old, nw) {
      if (old === null || old === undefined) return nw;
      return ALPHA * nw + (1 - ALPHA) * old;
    }

    function compare(current) {
      if (!_baseline) return { drift: 0, anomalies: [] };
      const anomalies = [];
      let drift = 0;

      // Compare typing speed baseline
      const typingDrift = Math.abs((current.mean_keystroke_ms || 200) - (_baseline.mean_keystroke_ms || 200));
      if (typingDrift > 100) { drift += 0.3; anomalies.push("Keystroke speed shifted"); }

      // Compare scroll pattern
      const scrollDrift = Math.abs((current.mean_scroll_vel || 0) - (_baseline.mean_scroll_vel || 0));
      if (scrollDrift > 200) { drift += 0.2; anomalies.push("Scroll velocity changed"); }

      // Sudden biometrics shift
      const riskDrift = Math.abs((current.bio_risk || 0) - (_baseline.avg_bio_risk || 0));
      if (riskDrift > 30) { drift += 0.5; anomalies.push("Biometric pattern mismatch"); }

      return { drift: Math.min(1, drift), anomalies };
    }

    function update(current) {
      const now = {
        mean_keystroke_ms: current.mean_keystroke_ms || 200,
        mean_scroll_vel:   current.mean_scroll_vel   || 0,
        avg_bio_risk:      _ema(_baseline?.avg_bio_risk,  current.bio_risk || 0),
        last_seen:         Date.now(),
      };
      _baseline = now;
      _save(now);
    }

    async function init() { await _load(); }

    return { init, compare, update, getBaseline: () => _baseline };
  })();

  // ════════════════════════════════════════════════════════════════
  // §7-ext Pre-Payment AI Fraud Prediction
  // ════════════════════════════════════════════════════════════════

  const PrePaymentAnalyzer = (() => {
    let _formFocusTs     = null;
    let _copyPasteCount  = 0;
    let _autofillCount   = 0;
    let _hesitationCount = 0;
    let _interactionMs   = [];

    function onFormFocus(e) {
      const name = (e.target.name || e.target.id || e.target.placeholder || "").toLowerCase();
      const isPayField = ["card","cvv","cvc","expiry","account","payment","upi"].some(k => name.includes(k));
      if (isPayField && !_formFocusTs) _formFocusTs = Date.now();
    }

    function onPaste(e) {
      const tgt = e.target.tagName;
      if (tgt === "INPUT" || tgt === "TEXTAREA") _copyPasteCount++;
    }

    function onInput(e) {
      const now = Date.now();
      const tgt = e.target;
      // Detect autofill: value set programmatically (length jump > 8 chars)
      if (tgt.value.length > 8 && !_interactionMs.length) _autofillCount++;
      _interactionMs.push(now);
      if (_interactionMs.length > 200) _interactionMs.shift();
    }

    function onBlurPayment(e) {
      const name = (e.target.name || e.target.id || "").toLowerCase();
      const isPayField = ["card","cvv","cvc","expiry","account"].some(k => name.includes(k));
      if (!isPayField) return;
      // If focus→blur in < 500ms → no hesitation (bot-like)
      if (_formFocusTs && (Date.now() - _formFocusTs) < 500) _hesitationCount++;
    }

    function init() {
      document.addEventListener("focus",  onFormFocus,   { passive: true, capture: true });
      document.addEventListener("paste",  onPaste,       { passive: true, capture: true });
      document.addEventListener("input",  onInput,       { passive: true, capture: true });
      document.addEventListener("blur",   onBlurPayment, { passive: true, capture: true });
    }

    function analyze() {
      const risk    = [];
      let   score   = 0;

      if (_copyPasteCount >= 3) { score += 25; risk.push(`High copy-paste: ${_copyPasteCount}×`); }
      if (_autofillCount  >= 2) { score += 20; risk.push("Suspicious autofill pattern"); }
      if (_hesitationCount >= 2){ score += 20; risk.push("No hesitation on payment fields"); }

      // Interaction speed: if <100ms between inputs consistently = bot
      if (_interactionMs.length >= 5) {
        const gaps = _interactionMs.slice(1).map((t, i) => t - _interactionMs[i]);
        const meanGap = gaps.reduce((a, b) => a + b, 0) / gaps.length;
        if (meanGap < 80) { score += 30; risk.push(`Inhuman input speed (${Math.round(meanGap)}ms avg)`); }
      }

      return {
        score:           Math.min(100, score),
        copy_paste_count:_copyPasteCount,
        autofill_count:  _autofillCount,
        hesitation_count:_hesitationCount,
        risk_signals:    risk,
      };
    }

    return { init, analyze };
  })();

  // ════════════════════════════════════════════════════════════════
  // §11 Live Draggable Security HUD
  // ════════════════════════════════════════════════════════════════

  function buildHUD(risk) {
    const existing = document.getElementById(SECURITY_HUD);
    if (existing) { updateHUD(risk); return; }

    const score = risk?.risk_score ?? 0;
    const level = risk?.risk_level ?? "safe";
    const { bg, border, text, glow } = _hudColors(score);

    const hud = document.createElement("div");
    hud.id = SECURITY_HUD;
    hud.setAttribute("data-fraudx","1");
    Object.assign(hud.style, {
      position:   "fixed",
      bottom:     "18px",
      right:      "18px",
      zIndex:     "2147483647",
      background: bg,
      border:     `2px solid ${border}`,
      borderRadius:"14px",
      padding:    "10px 14px",
      fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
      fontSize:   "12px",
      color:      text,
      boxShadow:  `0 4px 20px ${glow}`,
      cursor:     "default",
      userSelect: "none",
      minWidth:   "160px",
      transition: "box-shadow .2s, opacity .2s",
      opacity:    "0",
    });

    hud.innerHTML = `
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="font-size:16px">🛡️</span>
        <span style="font-weight:700;font-size:12px;letter-spacing:-.2px">FRAUD-X Shield</span>
        <span id="fraudx-hud-mode" style="margin-left:auto;font-size:10px;cursor:pointer;
          opacity:.6;padding:1px 5px;border-radius:4px;background:rgba(0,0,0,.08)"
          title="Toggle dark mode">🌙</span>
        <span style="font-size:12px;cursor:pointer;opacity:.6;margin-left:2px"
          id="fraudx-hud-close" title="Minimize">—</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px">
        <div id="fraudx-hud-score" style="
          min-width:42px;height:42px;border-radius:9px;
          background:${border}22;border:2px solid ${border};
          display:flex;flex-direction:column;align-items:center;justify-content:center">
          <span style="font-size:17px;font-weight:900;color:${border};line-height:1">${score}</span>
          <span style="font-size:8px;font-weight:700;color:${text};letter-spacing:.5px">RISK</span>
        </div>
        <div>
          <div id="fraudx-hud-level" style="font-weight:700;font-size:12px;color:${border};
            text-transform:uppercase;letter-spacing:.3px">${_levelLabel(level)}</div>
          <div id="fraudx-hud-detail" style="font-size:10.5px;color:${text};opacity:.8;
            margin-top:1px;max-width:100px;overflow:hidden;text-overflow:ellipsis;
            white-space:nowrap">${risk?.primary_threat || "Scanning…"}</div>
        </div>
      </div>
      <div style="display:flex;gap:6px;margin-top:8px">
        <button id="fraudx-hud-chat" style="
          flex:1;padding:5px;font-size:10.5px;font-weight:600;
          background:rgba(37,99,235,.12);border:1px solid #2563EB;
          border-radius:6px;color:#1d4ed8;cursor:pointer;font-family:inherit">
          💬 AI Chat
        </button>
        <button id="fraudx-hud-report" style="
          flex:1;padding:5px;font-size:10.5px;font-weight:600;
          background:rgba(0,0,0,.05);border:1px solid ${border};
          border-radius:6px;color:${text};cursor:pointer;font-family:inherit">
          📋 Report
        </button>
      </div>`;

    // Drag support
    _makeDraggable(hud);

    document.body.appendChild(hud);
    requestAnimationFrame(() => { hud.style.opacity = "1"; });
    _hudVisible = true;

    // Wire buttons
    hud.querySelector("#fraudx-hud-close").onclick = () => {
      hud.style.opacity = "0";
      setTimeout(() => hud.remove(), 200);
      _hudVisible = false;
    };
    hud.querySelector("#fraudx-hud-mode").onclick = () => {
      _darkMode = !_darkMode;
      updateHUD(_currentRisk);
    };
    hud.querySelector("#fraudx-hud-chat").onclick = toggleChatPanel;
    hud.querySelector("#fraudx-hud-report").onclick = () =>
      window.open(document.getElementById("statusText")?.dataset?.api + "/" || "#");
  }

  function updateHUD(risk) {
    const hud = document.getElementById(SECURITY_HUD);
    if (!hud) return;
    const score  = risk?.risk_score ?? 0;
    const level  = risk?.risk_level ?? "safe";
    const { bg, border, text, glow } = _hudColors(score);
    Object.assign(hud.style, {
      background: bg, border: `2px solid ${border}`,
      boxShadow:  `0 4px 20px ${glow}`, color: text,
    });
    const sc = hud.querySelector("#fraudx-hud-score");
    if (sc) sc.innerHTML = `
      <span style="font-size:17px;font-weight:900;color:${border};line-height:1">${score}</span>
      <span style="font-size:8px;font-weight:700;color:${text};letter-spacing:.5px">RISK</span>`;
    const lv = hud.querySelector("#fraudx-hud-level");
    if (lv) { lv.textContent = _levelLabel(level); lv.style.color = border; }
    const dt = hud.querySelector("#fraudx-hud-detail");
    if (dt) dt.textContent = risk?.primary_threat || "Protected";
  }

  function _hudColors(score) {
    if (_darkMode) {
      if (score >= 81) return { bg:"#1a0000", border:"#ef4444", text:"#fca5a5", glow:"rgba(220,38,38,.4)" };
      if (score >= 61) return { bg:"#1a0d00", border:"#f97316", text:"#fdba74", glow:"rgba(217,119,6,.4)"  };
      if (score >= 31) return { bg:"#1a1500", border:"#eab308", text:"#fde68a", glow:"rgba(234,179,8,.4)"  };
      return               { bg:"#001a0a", border:"#22c55e", text:"#86efac", glow:"rgba(5,150,105,.3)"   };
    }
    if (score >= 81) return { bg:"#FEF2F2", border:"#DC2626", text:"#991B1B", glow:"rgba(220,38,38,.2)" };
    if (score >= 61) return { bg:"#FFF7ED", border:"#C05621", text:"#7C2D12", glow:"rgba(192,86,33,.2)" };
    if (score >= 31) return { bg:"#FFFBEB", border:"#D97706", text:"#92400E", glow:"rgba(217,119,6,.2)" };
    return               { bg:"#ECFDF5", border:"#059669", text:"#065F46", glow:"rgba(5,150,105,.15)"};
  }

  function _levelLabel(level) {
    return level === "danger"  ? "High Risk"
         : level === "caution" ? "Suspicious"
         : level === "safe"    ? "Protected"
         : "Scanning…";
  }

  function _makeDraggable(el) {
    let ox = 0, oy = 0, startX = 0, startY = 0, dragging = false;
    el.addEventListener("mousedown", (e) => {
      if (e.target.tagName === "BUTTON" || e.target.tagName === "SPAN") return;
      dragging = true;
      startX = e.clientX; startY = e.clientY;
      const r = el.getBoundingClientRect();
      ox = window.innerWidth  - r.right;
      oy = window.innerHeight - r.bottom;
      e.preventDefault();
    });
    document.addEventListener("mousemove", (e) => {
      if (!dragging) return;
      const dx = startX - e.clientX;
      const dy = startY - e.clientY;
      el.style.right  = Math.max(4, ox + dx) + "px";
      el.style.bottom = Math.max(4, oy + dy) + "px";
    });
    document.addEventListener("mouseup", () => { dragging = false; });
  }

  // ════════════════════════════════════════════════════════════════
  // §17 AI Chat Widget
  // ════════════════════════════════════════════════════════════════

  async function _getApiBase() {
    return new Promise(resolve =>
      chrome.storage.sync.get({ fraudx_api_url: "http://localhost:8000" }, d =>
        resolve((d.fraudx_api_url || "http://localhost:8000").replace(/\/$/, ""))
      )
    );
  }

  function toggleChatPanel() {
    if (_chatOpen) {
      const p = document.getElementById(CHAT_PANEL_ID);
      if (p) { p.style.opacity = "0"; setTimeout(() => p.remove(), 200); }
      _chatOpen = false;
      return;
    }
    _chatOpen = true;
    _buildChatPanel();
  }

  function _buildChatPanel() {
    const hud   = document.getElementById(SECURITY_HUD);
    const hudR  = hud ? hud.getBoundingClientRect() : null;
    const right = hudR ? (window.innerWidth - hudR.right) : 18;

    const panel = document.createElement("div");
    panel.id    = CHAT_PANEL_ID;
    panel.setAttribute("data-fraudx","1");
    Object.assign(panel.style, {
      position:   "fixed",
      bottom:     `${(hudR?.height || 60) + 28}px`,
      right:      `${right}px`,
      zIndex:     "2147483646",
      width:      "300px",
      background: _darkMode ? "#111827" : "#fff",
      border:     `1.5px solid ${_darkMode ? "#374151" : "#E5E7EB"}`,
      borderRadius:"14px",
      boxShadow:  "0 8px 32px rgba(0,0,0,.18)",
      fontFamily: "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
      fontSize:   "12.5px",
      color:      _darkMode ? "#F9FAFB" : "#111827",
      display:    "flex",
      flexDirection:"column",
      maxHeight:  "380px",
      opacity:    "0",
      transition: "opacity .2s",
    });

    panel.innerHTML = `
      <div style="padding:10px 12px;border-bottom:1px solid ${_darkMode ? "#374151" : "#E5E7EB"};
        display:flex;align-items:center;gap:6px;font-weight:700;font-size:13px">
        <span>🤖</span> FRAUD-X AI Assistant
        <span id="fraudx-chat-close" style="margin-left:auto;cursor:pointer;opacity:.6;
          font-size:14px;font-weight:400" title="Close">✕</span>
      </div>
      <div id="fraudx-chat-log" style="flex:1;overflow-y:auto;padding:10px 12px;
        display:flex;flex-direction:column;gap:8px;min-height:150px;">
        <div style="align-self:flex-start;background:${_darkMode ? "#1F2937" : "#F3F4F6"};
          padding:7px 10px;border-radius:10px;max-width:85%;font-size:12px;line-height:1.45">
          Hi! I'm your AI fraud analyst. Ask me about this page, suspicious signals, or anything security-related.
        </div>
      </div>
      <div style="padding:8px 10px;border-top:1px solid ${_darkMode ? "#374151" : "#E5E7EB"};
        display:flex;gap:6px">
        <input id="fraudx-chat-input" type="text" placeholder="Ask about this site…"
          style="flex:1;padding:6px 9px;border:1px solid ${_darkMode ? "#374151" : "#D1D5DB"};
          border-radius:8px;font-size:11.5px;outline:none;font-family:inherit;
          background:${_darkMode ? "#1F2937" : "#fff"};color:${_darkMode ? "#F9FAFB" : "#111827"}"/>
        <button id="fraudx-chat-send" style="padding:6px 12px;background:#2563EB;color:#fff;
          border:none;border-radius:8px;font-size:11.5px;font-weight:600;cursor:pointer;
          font-family:inherit">Send</button>
      </div>`;

    document.body.appendChild(panel);
    requestAnimationFrame(() => { panel.style.opacity = "1"; });

    panel.querySelector("#fraudx-chat-close").onclick = toggleChatPanel;

    const input  = panel.querySelector("#fraudx-chat-input");
    const sendBtn= panel.querySelector("#fraudx-chat-send");

    async function sendMsg() {
      const msg = input.value.trim();
      if (!msg) return;
      input.value = "";
      _appendChatMsg(msg, "user");
      sendBtn.disabled = true;
      const typingEl = _appendChatMsg("Thinking…", "bot");

      try {
        const api  = await _getApiBase();
        const resp = await fetch(`${api}/api/chat`, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({
            message: msg,
            context: {
              url:       window.location.href,
              risk:      _currentRisk,
              payment:   _paymentResult,
              biometrics: Biometrics.getRiskScore(),
            },
          }),
          signal: AbortSignal.timeout(15000),
        });
        const data = await resp.json();
        typingEl.textContent = data.reply || data.message || "No response from AI.";
      } catch (e) {
        typingEl.textContent = "AI assistant unavailable. Check that the FRAUD-X server is running.";
      } finally {
        sendBtn.disabled = false;
        input.focus();
      }
    }

    sendBtn.onclick = sendMsg;
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") sendMsg(); });
    input.focus();
  }

  function _appendChatMsg(text, from) {
    const log = document.getElementById("fraudx-chat-log");
    if (!log) return null;
    const el = document.createElement("div");
    Object.assign(el.style, {
      alignSelf:    from === "user" ? "flex-end" : "flex-start",
      background:   from === "user"
        ? "#2563EB"
        : (_darkMode ? "#1F2937" : "#F3F4F6"),
      color:        from === "user" ? "#fff" : (_darkMode ? "#F9FAFB" : "#111827"),
      padding:      "7px 10px",
      borderRadius: "10px",
      maxWidth:     "88%",
      fontSize:     "12px",
      lineHeight:   "1.45",
      wordBreak:    "break-word",
    });
    el.textContent = text;
    log.appendChild(el);
    log.scrollTop  = log.scrollHeight;
    return el;
  }

  // ════════════════════════════════════════════════════════════════
  // Mode A — Standard alert banner (§8/§9)
  // ════════════════════════════════════════════════════════════════

  function removeBanner() {
    const el = document.getElementById(BANNER_ID);
    if (el) { el.style.opacity = "0"; el.style.transform = "translateY(-100%)"; setTimeout(() => el.remove(), 250); }
  }

  function buildBanner(result, url) {
    removeBanner();
    if (_paymentResult) return;

    const score  = result.risk_score  || 0;
    const level  = result.risk_level  || "caution";
    const threat = result.primary_threat || result.explanation?.primary_threat
      || (level === "danger" ? "Fraud signals detected" : "Suspicious signals");
    const factors= (result.explanation?.factors || [])
      .filter(f => f.impact > 0 && f.severity !== "informational")
      .slice(0, 3).map(f => f.factor);

    // §8 Risk band styling
    const scheme = score >= 81
      ? { bg:"#FEF2F2", border:"#DC2626", text:"#991B1B", accent:"#DC2626", icon:"🚨" }
      : score >= 61
      ? { bg:"#FFF7ED", border:"#C05621", text:"#7C2D12", accent:"#C05621", icon:"🔥" }
      : { bg:"#FFFBEB", border:"#D97706", text:"#92400E", accent:"#D97706", icon:"⚠️" };

    const banner = document.createElement("div");
    banner.id    = BANNER_ID;
    banner.setAttribute("data-fraudx","1");
    Object.assign(banner.style, {
      position:  "fixed", top:"0", left:"0", right:"0",
      zIndex:    "2147483646",
      background: scheme.bg,
      borderBottom: `3px solid ${scheme.border}`,
      padding:   "11px 16px 11px 18px",
      fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
      fontSize:  "13.5px", lineHeight:"1.45",
      display:   "flex", alignItems:"center", gap:"14px",
      boxShadow: "0 4px 24px rgba(0,0,0,.18)",
      transition:"opacity .2s, transform .2s",
      opacity:   "0", transform:"translateY(-100%)",
      boxSizing: "border-box",
    });

    const pill = document.createElement("div");
    Object.assign(pill.style, {
      minWidth:"48px", height:"48px", borderRadius:"10px",
      background:`${scheme.border}22`, border:`2px solid ${scheme.border}`,
      display:"flex", flexDirection:"column",
      alignItems:"center", justifyContent:"center", flexShrink:"0",
    });
    pill.innerHTML = `
      <span style="font-size:17px;font-weight:900;color:${scheme.accent};line-height:1">${score}</span>
      <span style="font-size:9px;font-weight:600;color:${scheme.text};letter-spacing:.5px">RISK</span>`;

    const info = document.createElement("div");
    info.style.flex    = "1";
    info.style.minWidth= "0";
    info.innerHTML = `
      <div style="font-weight:700;color:${scheme.accent};font-size:13.5px;margin-bottom:2px">
        ${scheme.icon} FRAUD-X ${score >= 81 ? "CRITICAL" : score >= 61 ? "High Risk" : "Warning"}
      </div>
      <div style="color:#374151;font-size:12.5px">
        <strong>${esc(threat)}</strong>
        ${factors.length ? `<span style="color:#6B7280;margin-left:6px">— ${factors.map(esc).join(" · ")}</span>` : ""}
      </div>`;

    const btns = document.createElement("div");
    Object.assign(btns.style, { display:"flex", gap:"8px", flexShrink:"0", alignItems:"center" });

    if (level === "danger") {
      const back = document.createElement("button");
      back.textContent = "← Go Back";
      Object.assign(back.style, {
        padding:"7px 14px", background:scheme.border, color:"#fff",
        border:"none", borderRadius:"6px", fontSize:"12.5px",
        fontWeight:"700", cursor:"pointer", fontFamily:"inherit",
      });
      back.addEventListener("click", () => history.back());
      btns.appendChild(back);
    }

    const dismiss = document.createElement("button");
    dismiss.textContent = level === "danger" ? "Proceed Anyway" : "Dismiss";
    Object.assign(dismiss.style, {
      padding:"7px 14px", background:"transparent",
      border:`1px solid ${scheme.border}`, borderRadius:"6px",
      fontSize:"12.5px", fontWeight:"600", cursor:"pointer",
      color:scheme.text, fontFamily:"inherit",
    });
    dismiss.addEventListener("click", removeBanner);
    btns.appendChild(dismiss);

    banner.appendChild(pill);
    banner.appendChild(info);
    banner.appendChild(btns);
    (document.documentElement || document.body).prepend(banner);
    requestAnimationFrame(() => {
      banner.style.opacity   = "1";
      banner.style.transform = "translateY(0)";
    });
    if (level === "caution") setTimeout(removeBanner, 12000);
  }

  // ════════════════════════════════════════════════════════════════
  // Mode B — Payment overlay & trust badge (§8/§9/§10)
  // ════════════════════════════════════════════════════════════════

  function removePaymentOverlay() {
    [OVERLAY_ID, TRUST_ID].forEach(id => {
      const el = document.getElementById(id);
      if (el) { el.style.opacity = "0"; setTimeout(() => el.remove(), 200); }
    });
  }

  function buildTrustBadge(result) {
    document.getElementById(TRUST_ID)?.remove();
    const gateway = result.verified_gateway || result.gateway_info?.verified_gateway || "";
    const badge   = document.createElement("div");
    badge.id      = TRUST_ID;
    badge.setAttribute("data-fraudx","1");
    Object.assign(badge.style, {
      position:"fixed", bottom:"18px", right:"18px",
      zIndex:"2147483647",
      background:"#ECFDF5", border:"2px solid #059669", borderRadius:"12px",
      padding:"10px 14px",
      fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
      fontSize:"12.5px",
      display:"flex", alignItems:"center", gap:"8px",
      boxShadow:"0 4px 16px rgba(0,0,0,.12)",
      cursor:"pointer", opacity:"0", transition:"opacity .25s", maxWidth:"280px",
    });
    badge.innerHTML = `
      <span style="font-size:20px;line-height:1">🛡️</span>
      <div>
        <div style="font-weight:700;color:#065F46;font-size:12px">FRAUD-X ✓ Verified</div>
        <div style="color:#047857;font-size:11px;margin-top:1px">${esc(gateway || "Trusted payment processor")}</div>
      </div>
      <button style="margin-left:auto;background:none;border:none;cursor:pointer;
        font-size:14px;color:#6B7280;padding:0 2px;line-height:1" title="Dismiss">×</button>`;
    badge.querySelector("button").onclick = () => removePaymentOverlay();
    document.body.appendChild(badge);
    requestAnimationFrame(() => { badge.style.opacity = "1"; });
    setTimeout(() => removePaymentOverlay(), 8000);
  }

  function buildPaymentOverlay(result, url) {
    removePaymentOverlay();
    removeBanner();

    const level    = result.risk_level   || "caution";
    const score    = result.risk_score   || 0;
    const isDanger = level === "danger";
    const factors  = (result.explanation?.factors || [])
      .filter(f => f.impact > 0 && f.severity !== "informational").slice(0, 4);
    const threat   = result.explanation?.primary_threat || result.primary_threat
      || (isDanger ? "Fake payment page detected" : "Suspicious payment page");

    // §8 band-based color scheme
    const colors = score >= 81
      ? { bg:"#FEF2F2", border:"#DC2626", badge:"#DC2626", text:"#991B1B", btn:"#DC2626" }
      : score >= 61
      ? { bg:"#FFF7ED", border:"#C05621", badge:"#C05621", text:"#7C2D12", btn:"#C05621" }
      : { bg:"#FFFBEB", border:"#D97706", badge:"#D97706", text:"#92400E", btn:"#D97706" };

    const backdrop = document.createElement("div");
    backdrop.id    = OVERLAY_ID;
    backdrop.setAttribute("data-fraudx","1");
    Object.assign(backdrop.style, {
      position:"fixed", inset:"0",
      background: score >= 61 ? "rgba(127,29,29,.6)" : "rgba(120,83,16,.4)",
      zIndex:"2147483646", backdropFilter:"blur(3px)",
      display:"flex", alignItems:"center", justifyContent:"center",
      padding:"20px", opacity:"0", transition:"opacity .2s",
      fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
    });

    const card = document.createElement("div");
    Object.assign(card.style, {
      background:"#fff", borderRadius:"16px",
      border:`3px solid ${colors.border}`,
      maxWidth:"500px", width:"100%",
      boxShadow:"0 20px 60px rgba(0,0,0,.25)",
      overflow:"hidden", transform:"scale(.92)", transition:"transform .2s",
    });

    // Header
    const hdr = document.createElement("div");
    Object.assign(hdr.style, {
      background:colors.badge, padding:"16px 20px",
      display:"flex", alignItems:"center", gap:"12px",
    });
    hdr.innerHTML = `
      <span style="font-size:30px;line-height:1">${score >= 81 ? "🚨" : score >= 61 ? "🔥" : "⚠️"}</span>
      <div style="flex:1">
        <div style="color:#fff;font-size:16px;font-weight:800;letter-spacing:-.2px">
          FRAUD-X Payment Protection
        </div>
        <div style="color:rgba(255,255,255,.85);font-size:11.5px;margin-top:2px">
          ${score >= 81 ? "PAYMENT BLOCKED — CRITICAL RISK" : isDanger ? "PAYMENT BLOCKED" : "PAYMENT WARNING"}
        </div>
      </div>
      <div style="background:rgba(255,255,255,.25);border-radius:10px;
        padding:6px 12px;text-align:center;min-width:58px">
        <div style="color:#fff;font-size:22px;font-weight:900;line-height:1">${score}</div>
        <div style="color:rgba(255,255,255,.8);font-size:8.5px;letter-spacing:.5px;
          font-weight:700">RISK/100</div>
      </div>`;

    // Body
    const body = document.createElement("div");
    body.style.padding = "18px 20px";

    // Threat
    const threatEl = document.createElement("div");
    Object.assign(threatEl.style, {
      background:colors.bg, border:`1.5px solid ${colors.border}`,
      borderRadius:"10px", padding:"12px 14px", marginBottom:"12px",
    });
    threatEl.innerHTML = `
      <div style="font-weight:700;color:${colors.border};font-size:13.5px;margin-bottom:4px">
        ${esc(threat)}
      </div>
      <div style="font-size:11px;color:#4B5563;font-family:monospace;
        word-break:break-all;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
        title="${esc(url)}">${esc(url.length > 65 ? url.slice(0,65)+"…" : url)}</div>`;

    // Signals
    const sigList = document.createElement("div");
    sigList.style.marginBottom = "12px";
    if (factors.length) {
      const title = document.createElement("div");
      Object.assign(title.style, {
        fontSize:"10.5px", fontWeight:"700", color:"#6B7280",
        textTransform:"uppercase", letterSpacing:".7px", marginBottom:"7px",
      });
      title.textContent = "Detection signals";
      sigList.appendChild(title);
      factors.forEach(f => {
        const sev   = f.severity || "medium";
        const c     = sev === "critical" ? "#DC2626" : sev === "high" ? "#D97706" : "#6B7280";
        const row   = document.createElement("div");
        Object.assign(row.style, {
          display:"flex", alignItems:"flex-start", gap:"8px",
          padding:"5px 0", borderBottom:"1px solid #F3F4F6",
          fontSize:"12px", color:"#374151",
        });
        row.innerHTML = `
          <span style="width:8px;height:8px;border-radius:50%;background:${c};
            flex-shrink:0;margin-top:3px"></span>
          <span style="flex:1">${esc(f.factor)}</span>
          <span style="font-weight:700;color:${c};flex-shrink:0">+${f.impact}</span>`;
        sigList.appendChild(row);
      });
    }

    // Block notice
    let blockedEl = null;
    if (isDanger) {
      blockedEl = document.createElement("div");
      Object.assign(blockedEl.style, {
        background:"#FEF2F2", border:"1.5px solid #FCA5A5", borderRadius:"8px",
        padding:"10px 14px", fontSize:"12px", color:"#991B1B",
        fontWeight:"600", textAlign:"center", marginBottom:"12px",
      });
      blockedEl.textContent = "🔒 Payment form interactions have been disabled on this page.";
    }

    // Recommendation
    const rec = document.createElement("div");
    Object.assign(rec.style, {
      fontSize:"11.5px", color:"#6B7280", lineHeight:"1.5",
      borderTop:"1px solid #E5E7EB", paddingTop:"12px", marginBottom:"14px",
    });
    rec.textContent = result.recommendation || "";

    // Buttons
    const btnRow = document.createElement("div");
    Object.assign(btnRow.style, { display:"flex", gap:"10px" });

    const backBtn = document.createElement("button");
    backBtn.textContent = "← Go Back Safely";
    Object.assign(backBtn.style, {
      flex:"1", padding:"11px 16px", background:colors.btn, color:"#fff",
      border:"none", borderRadius:"8px", fontSize:"13px", fontWeight:"700",
      cursor:"pointer", fontFamily:"inherit",
    });
    backBtn.addEventListener("click", () => history.back());

    const proceedBtn = document.createElement("button");
    proceedBtn.textContent = isDanger ? "Proceed Anyway ⚠️" : "Continue";
    Object.assign(proceedBtn.style, {
      flex: isDanger ? "0 0 auto" : "1",
      padding:"11px 16px", background:"transparent",
      border:`1.5px solid ${colors.border}`, borderRadius:"8px",
      fontSize:isDanger ? "11.5px" : "13px",
      fontWeight:"600", cursor:"pointer", color:colors.text, fontFamily:"inherit",
    });
    proceedBtn.addEventListener("click", () => {
      releasePaymentForms();
      removePaymentOverlay();
    });

    btnRow.appendChild(backBtn);
    btnRow.appendChild(proceedBtn);

    body.appendChild(threatEl);
    if (factors.length) body.appendChild(sigList);
    if (blockedEl)      body.appendChild(blockedEl);
    body.appendChild(rec);
    body.appendChild(btnRow);

    const footer = document.createElement("div");
    Object.assign(footer.style, {
      padding:"8px 20px", background:"#F9FAFB",
      borderTop:"1px solid #E5E7EB",
      display:"flex", alignItems:"center", gap:"6px",
      fontSize:"10.5px", color:"#9CA3AF",
    });
    footer.innerHTML = `🛡️ <strong style="color:#374151">FRAUD-X Shield v3.0</strong>
      &nbsp;·&nbsp; Enterprise Payment Protection`;

    card.appendChild(hdr);
    card.appendChild(body);
    card.appendChild(footer);
    backdrop.appendChild(card);
    document.body.appendChild(backdrop);
    requestAnimationFrame(() => {
      backdrop.style.opacity = "1";
      card.style.transform   = "scale(1)";
    });
    if (!isDanger) setTimeout(() => removePaymentOverlay(), 30000);
  }

  // ════════════════════════════════════════════════════════════════
  // §9 Form interception + smart blur/disable by risk band
  // ════════════════════════════════════════════════════════════════

  function interceptPaymentForms(result) {
    if (_paymentIntercepted) return;
    _paymentIntercepted = true;
    const score = result.risk_score || 0;

    const blockHandler = (e) => {
      e.preventDefault();
      e.stopImmediatePropagation();
      buildPaymentOverlay(result, window.location.href);
      return false;
    };

    document.querySelectorAll("form").forEach(form => {
      form[BLOCKED_KEY] = blockHandler;
      form.addEventListener("submit", blockHandler, { capture: true });
    });

    const PAY_BTN_RE = /pay|checkout|submit|order|purchase|buy|confirm|proceed/i;
    document.querySelectorAll("button,input[type=submit],a[role=button]").forEach(btn => {
      const label = (btn.textContent || btn.value || btn.getAttribute("aria-label") || "").trim();
      if (PAY_BTN_RE.test(label) || btn.type === "submit") {
        btn[BLOCKED_KEY] = blockHandler;
        btn.addEventListener("click", blockHandler, { capture: true });
      }
    });

    // §9 Smart visual response: blur fields for suspicious (31-60), disable for danger (61+)
    const CARD_FIELDS = "input[name*='card'],input[name*='cvv'],input[name*='upi']," +
      "input[name*='account'],input[name*='expir'],input[name*='pan'],input[name*='pin']";
    document.querySelectorAll(CARD_FIELDS).forEach(inp => {
      inp.setAttribute("data-fraudx-blocked","true");
      if (score >= 61) {
        inp.setAttribute("readonly","true");
        inp.style.cursor    = "not-allowed";
        inp.style.background= "#FEF2F2";
        inp.style.borderColor= "#DC2626";
      } else {
        inp.style.filter    = "blur(3px)";
        inp.style.background= "#FFFBEB";
        inp.style.borderColor= "#D97706";
        inp.addEventListener("focus", () => { inp.style.filter = ""; }, { once: true });
      }
    });
  }

  function releasePaymentForms() {
    _paymentIntercepted = false;
    document.querySelectorAll("form").forEach(form => {
      if (form[BLOCKED_KEY]) {
        form.removeEventListener("submit", form[BLOCKED_KEY], { capture: true });
        delete form[BLOCKED_KEY];
      }
    });
    document.querySelectorAll("[data-fraudx-blocked]").forEach(inp => {
      inp.removeAttribute("readonly");
      inp.removeAttribute("data-fraudx-blocked");
      inp.style.background = inp.style.borderColor = inp.style.cursor = inp.style.filter = "";
    });
  }

  // ════════════════════════════════════════════════════════════════
  // §1 Payment page detection (DOM analysis)
  // ════════════════════════════════════════════════════════════════

  const PAYMENT_TITLE_KW = ["checkout","payment","pay now","billing","purchase",
    "order","confirm payment","card details","buy now","transaction","complete order"];
  const PAYMENT_FIELD_KW = ["card number","cvv","cvc","expiry","expiration",
    "cardholder","upi","account number","routing","ifsc","sort code","wallet address","pin"];
  const PAYMENT_BTN_KW   = /pay now|checkout|place order|confirm payment|buy now|pay securely/i;

  function extractPaymentMetadata() {
    const fields = [];
    let hasPaymentForm = false;
    let formAction     = null;

    document.querySelectorAll("form").forEach(form => {
      form.querySelectorAll("input,select,textarea").forEach(inp => {
        const name = (inp.name||inp.id||inp.placeholder||inp.getAttribute("aria-label")||"").toLowerCase();
        if (PAYMENT_FIELD_KW.some(kw => name.includes(kw))) {
          hasPaymentForm = true;
          fields.push(name);
        }
      });
      form.querySelectorAll("button,[type=submit]").forEach(btn => {
        if (PAYMENT_BTN_KW.test(btn.textContent)) hasPaymentForm = true;
      });
      if (!formAction && form.action && form.action !== window.location.href) formAction = form.action;
    });

    document.querySelectorAll("label,[placeholder]").forEach(el => {
      const txt = (el.textContent || el.getAttribute("placeholder") || "").toLowerCase();
      if (PAYMENT_FIELD_KW.some(kw => txt.includes(kw))) hasPaymentForm = true;
    });

    let merchantName = null;
    const ogSite     = document.querySelector('meta[property="og:site_name"]');
    if (ogSite) merchantName = ogSite.getAttribute("content");
    if (!merchantName) { const h1 = document.querySelector("h1"); if (h1) merchantName = h1.textContent.trim().slice(0,80); }

    return {
      page_title:       document.title || "",
      merchant_name:    merchantName,
      has_payment_form: hasPaymentForm,
      form_action_url:  formAction,
      form_field_names: fields.slice(0, 20),
    };
  }

  function isPaymentPage() {
    const meta = extractPaymentMetadata();
    if (meta.has_payment_form) return true;
    if (PAYMENT_TITLE_KW.some(kw => document.title.toLowerCase().includes(kw))) return true;
    const body = (document.body?.innerText || "").slice(0, 3000).toLowerCase();
    return PAYMENT_FIELD_KW.filter(kw => body.includes(kw)).length >= 2;
  }

  // ════════════════════════════════════════════════════════════════
  // DOMContentLoaded — detect payment page + init biometrics
  // ════════════════════════════════════════════════════════════════

  async function onDOMReady() {
    Biometrics.init();
    DOMGuard.init();
    PrePaymentAnalyzer.init();
    await AdaptiveBaseline.init();

    if (!isPaymentPage()) return;

    const metadata       = extractPaymentMetadata();
    const biometrics     = Biometrics.getRiskScore();
    const device         = DeviceFingerprint.collect();
    const browserEnv     = BrowserEnv.collect();
    const domSignals     = DOMGuard.getSignals();
    const prePayment     = PrePaymentAnalyzer.analyze();

    // §10 Baseline comparison
    const baselineCmp = AdaptiveBaseline.compare({
      bio_risk:         biometrics.risk_score,
      mean_keystroke_ms:200,
      mean_scroll_vel:  0,
    });
    // Update baseline with current session (EMA update)
    AdaptiveBaseline.update({
      bio_risk:         biometrics.risk_score,
      mean_keystroke_ms:200,
      mean_scroll_vel:  0,
    });

    chrome.runtime.sendMessage({
      type:        "PAYMENT_PAGE_DETECTED",
      url:         window.location.href,
      metadata,
      biometrics:  { ...biometrics, device_trust: device.trust_score },
      browser_env: browserEnv,
      dom_signals: domSignals,
      pre_payment: prePayment,
      baseline:    baselineCmp,
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", onDOMReady);
  } else {
    onDOMReady();
  }

  // ════════════════════════════════════════════════════════════════
  // Message listener
  // ════════════════════════════════════════════════════════════════

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {

    // Standard scan result
    if (msg.type === "FRAUDX_RESULT") {
      const { result } = msg;
      if (!result || result.risk_level === "safe") {
        // Show HUD even for safe (green)
        _currentRisk = result;
        buildHUD(result);
        return;
      }
      _currentRisk = result;
      buildBanner(result, msg.url);
      buildHUD(result);
      return;
    }

    // Payment scan result (§1/§4/§8/§9)
    if (msg.type === "FRAUDX_PAYMENT_RESULT") {
      const { result, url } = msg;
      if (!result) return;
      _paymentResult = result;
      _currentRisk   = result;
      removeBanner();
      updateHUD(result);

      const level = result.risk_level;
      if (level === "safe" || result.is_trusted_gateway) {
        buildTrustBadge(result);
      } else if (level === "caution") {
        buildPaymentOverlay(result, url);
      } else if (level === "danger") {
        buildPaymentOverlay(result, url);
        interceptPaymentForms(result);
      }
      return;
    }

    // Popup requests DOM context
    if (msg.type === "EXTRACT_PAYMENT_CONTEXT") {
      sendResponse(extractPaymentMetadata());
      return true;
    }

    // Page ignored — remove all UI
    if (msg.type === "FRAUDX_IGNORED") {
      removeBanner();
      removePaymentOverlay();
      releasePaymentForms();
      document.getElementById(SECURITY_HUD)?.remove();
      document.getElementById(CHAT_PANEL_ID)?.remove();
      _paymentResult = null;
      _currentRisk   = null;
      _hudVisible    = false;
      _chatOpen      = false;
      return;
    }

    // §14 WebSocket live alert
    if (msg.type === "FRAUDX_WS_ALERT") {
      const evt = msg.event;
      if (evt?.url === window.location.href && evt?.risk_level !== "safe") {
        buildBanner({ ...evt, primary_threat: evt.threat || evt.message }, evt.url);
      }
      return;
    }

    // Context menu result
    if (msg.type === "FRAUDX_CONTEXT_RESULT") {
      const { result, url } = msg;
      if (result && result.risk_level !== "safe") buildBanner(result, url);
      return;
    }

    // §12 Velocity alert from background
    if (msg.type === "FRAUDX_VELOCITY") {
      if (msg.level === "critical" || msg.level === "high") {
        const velDiv = document.createElement("div");
        velDiv.setAttribute("data-fraudx","1");
        Object.assign(velDiv.style, {
          position:"fixed", top:"0", left:"50%", transform:"translateX(-50%) translateY(-100%)",
          zIndex:"2147483645",
          background: msg.level === "critical" ? "#DC2626" : "#D97706",
          color:"#fff", padding:"8px 18px", borderRadius:"0 0 10px 10px",
          fontFamily:"-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif",
          fontSize:"12px", fontWeight:"600",
          boxShadow:"0 4px 16px rgba(0,0,0,.18)",
          transition:"transform .3s", whiteSpace:"nowrap",
        });
        velDiv.textContent = `⚡ FRAUD-X: High navigation velocity on ${msg.host} (${msg.count} pages/min)`;
        document.body.appendChild(velDiv);
        requestAnimationFrame(() => { velDiv.style.transform = "translateX(-50%) translateY(0)"; });
        setTimeout(() => {
          velDiv.style.transform = "translateX(-50%) translateY(-110%)";
          setTimeout(() => velDiv.remove(), 300);
        }, 5000);
      }
      return;
    }

  });

})();
