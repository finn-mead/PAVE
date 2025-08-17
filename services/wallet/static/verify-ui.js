// ===== config =====
const ISSUER_UI = "http://localhost:8001/ui";  // issuer supports both /ui and /approve with return_to/return_url
const VERIFIER  = "http://localhost:8003";

// ===== small helpers =====
const qs = new URLSearchParams(location.search);
const $  = (id) => document.getElementById(id);

function b64urlEncode(str) {
  // base64url without padding
  const b64 = btoa(unescape(encodeURIComponent(str)));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function safeJson(obj) {
  try { return JSON.stringify(obj); } catch (_) { return "{}"; }
}

function setStatus(text) { $("status").textContent = text; }
function showError(text) { const el = $("error"); el.style.display="block"; el.textContent = text; $("spinner").style.display="none"; }
function showResult(obj) {
  const el = $("result");
  el.style.display = "block";
  el.textContent = JSON.stringify(obj, null, 2);
  $("spinner").style.display = "none";
}

// ===== IndexedDB minimal wrapper =====
const DB_NAME = "pave_wallet";
const DB_VERSION = 1;
const STORE = "receipts";
const FASTAGE_KEY = "native:fastage";
const ISSUER_ID = "fastage"; // must match wallet.js
// compat store (used by iframe wallet.js)
const COMPAT_DB_NAME = "pave";
const COMPAT_STORE   = "receipts";
const RETURN_URL_KEY = "pave:return_url";
const PARAMS_KEY = "pave:params";

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

function openCompatDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(COMPAT_DB_NAME, 1);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(COMPAT_STORE)) {
        db.createObjectStore(COMPAT_STORE, { keyPath: "issuer_id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const st = tx.objectStore(STORE);
    const rq = st.get(key);
    rq.onsuccess = () => resolve(rq.result || null);
    rq.onerror   = () => reject(rq.error);
  });
}

async function idbPut(key, val) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    const st = tx.objectStore(STORE);
    const rq = st.put(val, key);
    rq.onsuccess = () => resolve(true);
    rq.onerror   = () => reject(rq.error);
  });
}

async function compatGetReceipt() {
  const db = await openCompatDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(COMPAT_STORE, "readonly");
    const st = tx.objectStore(COMPAT_STORE);
    const rq = st.get(ISSUER_ID);
    rq.onsuccess = () => resolve(rq.result || null);
    rq.onerror   = () => reject(rq.error);
  });
}

async function compatPutReceipt(jwt) {
  const db = await openCompatDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(COMPAT_STORE, "readwrite");
    const st = tx.objectStore(COMPAT_STORE);
    const rq = st.put({ issuer_id: ISSUER_ID, receipt_jwt: jwt });
    rq.onsuccess = () => resolve(true);
    rq.onerror   = () => reject(rq.error);
  });
}

// ===== verifier calls =====
async function fetchChallenge() {
  const res = await fetch(`${VERIFIER}/challenge`, {
    method: "GET",
    mode: "cors",
    credentials: "omit"
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText} @ ${VERIFIER}/challenge ${txt}`);
  }
  return res.json();
}

async function verifyWithVerifier(aud, policy_id, jwt) {
  setStatus("Requesting challenge…");
  const { nonce } = await fetchChallenge();

  setStatus("Submitting verification envelope…");
  // Correct nested structure for verifier
  const payload = { 
    envelope: { aud, nonce, receipt: jwt },
    policy_id 
  };
  
  const res = await fetch(`${VERIFIER}/verify/envelope`, {
    method: "POST",
    mode: "cors",
    credentials: "omit",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${res.statusText} @ ${VERIFIER}/verify/envelope ${txt}`);
  }
  
  return res.json();
}

// ===== return result to caller (popup or full redirect) =====
function returnToCaller(aud, return_url, state, result) {
  // Allowlist check for aud before using as targetOrigin (security)
  const ALLOWED_ORIGINS = new Set(["http://localhost:9001", "http://localhost:9002"]);
  
  // Try popup first
  try {
    if (window.opener && !window.opener.closed) {
      if (ALLOWED_ORIGINS.has(aud)) {
        const targetOrigin = new URL(aud).origin;  // precise targetOrigin for security
        window.opener.postMessage({ type: "pave.verify.result", state, result }, targetOrigin);
        // Small UX nicety: close the popup; if blocked, we still posted the result.
        window.close();
        return;
      } else {
        // Malicious aud - fall through to fragment only
        console.warn("[verify-ui] aud not allowlisted, using fragment fallback only:", aud);
      }
    }
  } catch (_) {
    // cross-origin edge, fall through to fragment path
  }
  // Full-redirect fragment fallback
  const payload = b64urlEncode(JSON.stringify({ state, result }));
  const hash = `#pave_result=${payload}`;
  if (return_url && typeof return_url === "string") {
    const base = return_url.split('#')[0];
    location.href = base + hash;
  } else {
    // As a last resort, stick it on our own URL so SDK on the opener can read it (rare path)
    location.hash = hash;
  }
}

// ===== main flow =====
(async function main() {
  try {
    $("error").style.display = "none";
    $("result").style.display = "none";
    $("spinner").style.display = "block";

    // ---- parse inputs & coalesce from session ----
    const issuer_result = qs.get("issuer_result"); // "ok" | "fail" | null

    // First, read whatever we have on the URL
    let aud       = qs.get("aud") || "";
    let policy_id = (qs.get("policy_id") || "").trim();
    let state     = qs.get("state") || "";
    let return_url = qs.get("return_url") || "";

    // Then, pull persisted values (from pre-issuer hop)
    const persisted = JSON.parse(sessionStorage.getItem(PARAMS_KEY) || "{}");
    if (!aud)       aud       = persisted.aud       || "";
    if (!policy_id) policy_id = persisted.policy_id || "uk_adult_high";
    if (!state)     state     = persisted.state     || "";
    if (!return_url) return_url = persisted.return_url || "";
    
    // Normalize: drop any existing fragment to avoid '#%23pave_result=' loops
    if (return_url) return_url = return_url.split('#')[0];

    const mode = (qs.get("mode") || "auto").toLowerCase();

    // Require params only on the **pre-issuer** hop.
    // On callback (issuer_result present), we allow recovery from session.
    if (!issuer_result && (!aud || !policy_id || !return_url || !state)) {
      const err = { ok: false, reason: "wallet_param_error" };
      showError("Missing required parameters.");
      return returnToCaller(aud || "*", return_url || "", state || "", err);
    }

    // If we came back from issuer, handle immediately
    if (issuer_result === "ok") {
      setStatus("Storing issuer receipt…");
      const jwt = qs.get("jwt");
      const returnedState = qs.get("state");
      
      // State integrity check - CSRF/flow protection
      const original = JSON.parse(sessionStorage.getItem(PARAMS_KEY) || "{}");
      const originalState = original.state || state; // fallback
      if (returnedState !== originalState) {
        const err = { ok: false, reason: "state_mismatch" };
        showError("State mismatch - possible CSRF attack.");
        history.replaceState(null, '', location.origin + '/verify-ui');
        return returnToCaller(aud, return_url, originalState, err);
      }
      
      if (!jwt) {
        const err = { ok: false, reason: "malformed_issuer_callback" };
        showError("Issuer returned ok but no jwt was provided.");
        history.replaceState(null, '', location.origin + '/verify-ui');
        return returnToCaller(aud, return_url, state, err);
      }
      
      // Strip sensitive query params from URL ASAP
      history.replaceState(null, '', location.origin + '/verify-ui');
      
      try {
        // write to both (legacy key & iframe-compatible store)\n        await idbPut(FASTAGE_KEY, jwt);\n        await compatPutReceipt(jwt);
      } catch (storageError) {
        const err = { ok: false, reason: "storage_error", message: storageError.message };
        showError(`Storage failed: ${storageError.message}`);
        return returnToCaller(aud, return_url, state, err);
      }

      const result = await verifyWithVerifier(aud, policy_id, jwt);
      showResult(result);
      sessionStorage.removeItem(PARAMS_KEY);
      sessionStorage.removeItem(RETURN_URL_KEY);
      return returnToCaller(aud, return_url, state, result);
    }
    if (issuer_result === "fail") {
      const reason = qs.get("reason") || "issuer_reject";
      const returnedState = qs.get("state");
      
      // State integrity check for fail path too
      const original = JSON.parse(sessionStorage.getItem(PARAMS_KEY) || "{}");
      const originalState = original.state || state; // fallback
      if (returnedState !== originalState) {
        const err = { ok: false, reason: "state_mismatch" };
        showError("State mismatch - possible CSRF attack.");
        history.replaceState(null, '', location.origin + '/verify-ui');
        return returnToCaller(aud, return_url, originalState, err);
      }
      
      // Strip params in fail path for consistency
      history.replaceState(null, '', location.origin + '/verify-ui');
      
      const result = { ok: false, reason };
      showError(`Issuer rejected: ${reason}`);
      sessionStorage.removeItem(PARAMS_KEY);
      sessionStorage.removeItem(RETURN_URL_KEY);
      return returnToCaller(aud, return_url, state, result);
    }

    // No issuer_result → decide: verify existing vs go to issuer
    setStatus("Checking for an existing pass…");
    // Prefer iframe-compatible record; fall back to legacy key if present\n    const compatRec = await compatGetReceipt();\n    const legacyJwt = await idbGet(FASTAGE_KEY);\n    const existingJwt = compatRec?.receipt_jwt || legacyJwt;
    const forceIssue  = mode === "issue";

    if (!existingJwt || forceIssue) {
      setStatus("No pass found (or 'issue' mode). Redirecting to issuer…");
      // Persist full param bundle across the issuer bounce
      sessionStorage.setItem(PARAMS_KEY, JSON.stringify({ return_url, aud, policy_id, state }));
      const params = new URLSearchParams({
        return_to: location.origin + "/verify-ui",  // issuer accepts both return_to and return_url
        aud, policy_id, state
      });
      // 302 via JS: the Issuer UI will read return_to and bounce back here
      location.href = `${ISSUER_UI}?${params.toString()}`;
      return;
    }

    // We have a pass; try immediate verification
    setStatus("Found existing pass. Verifying…");
    const result = await verifyWithVerifier(aud, policy_id, existingJwt);
    showResult(result);
    return returnToCaller(aud, return_url, state, result);

  } catch (e) {
    console.error("[verify-ui] fatal error", e);
    const aud        = qs.get("aud") || "*";
    const return_url = qs.get("return_url") || "";
    const state      = qs.get("state") || "";
    const result     = { ok: false, reason: "wallet_exception", message: String(e && e.message || e) };
    showError(`Error: ${result.message}`);
    sessionStorage.removeItem(RETURN_URL_KEY);
    return returnToCaller(aud, return_url, state, result);
  }
})();