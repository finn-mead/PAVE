// services/wallet/static/wallet.js
(() => {
  const ALLOWLIST = new Set(["http://localhost:9001","http://localhost:9002"]);
  const ISSUER_ISS = "http://localhost:8001";
  const ISSUER_ID = "fastage"; // matches guest_list.json issuer_id
  const ISSUER_ENDPOINT = "http://localhost:8001/issue";
  const VERIFIER_CHALLENGE = "http://localhost:8003/challenge";
  const VERIFIER_VERIFY = "http://localhost:8003/verify/envelope";

  // --- IndexedDB helpers ---
  const DB_NAME = "pave";
  const STORE = "receipts";
  
  // Storage capability cache
  let storageCapability = null; // { supported: boolean, ts: number }
  function openDB() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE, { keyPath: "issuer_id" });
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  async function putReceipt(obj) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(obj);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
  async function getReceipt(issuer_id) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(issuer_id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }
  async function clearReceipt(issuer_id) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(issuer_id);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  // --- Capability-driven storage detection ---
  async function needsRedirect() {
    // TEMP: Force redirect in Safari for testing since localhost doesn't trigger ITP
    const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
    if (isSafari && window.parent !== window) {
      console.log(`[wallet] needsRedirect: TRUE (Safari iframe - forced for testing)`);
      return true;
    }
    
    // Re-use cache if fresh (30s); otherwise probe again
    const fresh = storageCapability && (Date.now() - storageCapability.ts) < 30000;
    if (fresh) {
      return !storageCapability.supported;
    }
    
    // Quick probe without Storage Access API
    const supported = await probeStorage();
    storageCapability = { supported, ts: Date.now() };
    console.log(`[wallet] needsRedirect: ${!supported} (probe: ${supported})`);
    return !supported;
  }

  // --- Storage capability probe ---
  async function probeStorage() {
    const PROBE_KEY = "__probe__";
    const PROBE_VALUE = { issuer_id: PROBE_KEY, receipt_jwt: "test" };
    
    try {
      const db = await openDB();
      
      // Test write
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(PROBE_VALUE);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      
      // Test read
      const retrieved = await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const req = tx.objectStore(STORE).get(PROBE_KEY);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
      
      // Test delete
      await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete(PROBE_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      
      // Verify round-trip worked
      return retrieved && retrieved.issuer_id === PROBE_KEY;
      
    } catch (error) {
      // SecurityError, InvalidStateError, or any IDB failure
      return false;
    }
  }

  async function checkStorageCapability() {
    try {
      const supported = await probeStorage();
      const ts = Date.now();
      storageCapability = { supported, ts };
      
      console.log(`[wallet] storage probe: ${supported ? 'SUPPORTED' : 'BLOCKED'} (ts: ${ts})`);
      
      // Optional: notify parent of capabilities
      if (window.parent !== window) {
        window.parent.postMessage({ 
          type: "pave.wallet.capabilities", 
          storage_ok: supported 
        }, "*");
      }
      
      return supported;
    } catch (error) {
      console.log(`[wallet] storage probe: ERROR ${error.message}`);
      storageCapability = { supported: false, ts: Date.now() };
      return false;
    }
  }

  // --- Fallback UI for blocked storage ---
  function showRedirectFallback(aud, policy_id, return_url) {
    // Create inline banner in iframe
    const banner = document.createElement('div');
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.1); z-index: 10000;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    `;
    
    const card = document.createElement('div');
    card.style.cssText = `
      background: white; padding: 24px; border-radius: 8px; 
      box-shadow: 0 4px 12px rgba(0,0,0,0.2); max-width: 400px;
      text-align: center; border: 1px solid #ddd;
    `;
    
    const text = document.createElement('p');
    text.textContent = "Your browser blocks embedded wallet storage. To finish securely, we'll open Wallet in a new window.";
    text.style.cssText = "margin: 0 0 16px 0; color: #333; line-height: 1.4;";
    
    const button = document.createElement('button');
    button.textContent = "Continue";
    button.style.cssText = `
      background: #007acc; color: white; border: none; 
      padding: 12px 24px; border-radius: 4px; cursor: pointer;
      font-size: 14px; font-weight: 500;
    `;
    
    button.onclick = () => {
      initiateRedirect(aud, policy_id, return_url);
      document.body.removeChild(banner);
    };
    
    card.appendChild(text);
    card.appendChild(button);
    banner.appendChild(card);
    document.body.appendChild(banner);
  }

  function initiateRedirect(aud, policy_id, return_url, mode = "verify") {
    const walletBase = window.location.origin;
    const state = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    
    const params = new URLSearchParams({
      aud,
      policy_id: policy_id || "uk_adult_high",
      return_url: return_url || aud,
      state,
      mode
    });
    
    const url = `${walletBase}/verify-ui?${params}`;
    
    // Try popup first, fallback to navigation
    try {
      const popup = window.open(url, 'pave_wallet', 'width=600,height=400,centerscreen=yes');
      if (!popup) {
        throw new Error('Popup blocked');
      }
      
      // Store state for result correlation
      sessionStorage.setItem('pave_redirect_state', state);
      
    } catch (error) {
      // Popup blocked, use full navigation
      window.location.href = url;
    }
  }

  // --- Utilities ---
  function b64urlToObj(b64) {
    try {
      const pad = "=".repeat((4 - (b64.length % 4)) % 4);
      const json = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(json);
    } catch { return null; }
  }
  function parseJwtPayload(jwt) {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    return b64urlToObj(parts[1]);
  }

  // --- RPC handlers ---
  async function handleIssue(params) {
    const { aud, return_url } = params || {};
    
    console.log(`[wallet] handleIssue: checking redirect need (iframe: ${window.parent !== window})`);
    
    // Check if we need redirect for issue operation
    if (window.parent !== window && await needsRedirect()) {
      console.log(`[wallet] handleIssue: REDIRECTING (storage blocked)`);
      // We're in iframe and storage is blocked - signal parent to redirect
      throw {
        code: "redirect_required",
        message: "Embedded storage unavailable; top-level redirect required",
        mode: "issue",
        aud,
        return_url: return_url || aud
      };
    }
    
    console.log(`[wallet] handleIssue: PROCEEDING INLINE (storage ok)`);
    
    console.log(`[wallet] issue: storing with issuer_id: ${ISSUER_ID}`);
    const resp = await fetch(ISSUER_ENDPOINT, { method: "POST", headers: {"Content-Type": "application/json"} });
    if (!resp.ok) throw { code: "issuer_http_error", message: `HTTP ${resp.status}` };
    const data = await resp.json();
    const jwt = data.receipt_jwt;
    if (!jwt) throw { code: "issuer_no_jwt", message: "No receipt_jwt" };
    await putReceipt({ issuer_id: ISSUER_ID, receipt_jwt: jwt });
    console.log(`[wallet] issue: stored receipt for ${ISSUER_ID}`);
    const pay = parseJwtPayload(jwt) || {};
    return {
      issuer: pay.iss,
      method: pay.method,
      over18: !!pay.over18,
      iat: pay.iat,
      exp: pay.exp
    };
  }

  async function handleVerify(params) {
    const { aud, flow, return_url } = params || {};
    if (!aud || typeof aud !== "string") throw { code: "bad_params", message: "verify requires {aud}" };

    // Check if we need redirect for verify operation
    if (window.parent !== window && await needsRedirect()) {
      // We're in iframe and storage is blocked - signal parent to redirect
      throw {
        code: "redirect_required", 
        message: "Embedded storage unavailable; top-level redirect required",
        mode: "verify",
        aud,
        return_url: return_url || aud
      };
    }

    const rec = await getReceipt(ISSUER_ID);
    if (!rec) throw { code: "no_receipt", message: "No stored receipt" };

    // fetch nonce
    const ch = await fetch(VERIFIER_CHALLENGE, { method: "GET" });
    if (!ch.ok) throw { code: "challenge_http_error", message: `HTTP ${ch.status}` };
    const { nonce, exp_s } = await ch.json();
    if (!nonce) throw { code: "challenge_missing_nonce", message: "No nonce" };

    const envelope = {
      aud,
      nonce,
      receipt: rec.receipt_jwt
      // (MVP) omit ppid, device_sig, receipt_hash
    };

    const body = JSON.stringify({ envelope, policy_id: "uk_adult_high" });
    const v = await fetch(VERIFIER_VERIFY, { method: "POST", headers: {"Content-Type":"application/json"}, body });
    if (!v.ok) {
      const t = await v.text().catch(()=> "");
      throw { code: "verify_http_error", message: `HTTP ${v.status} ${t}` };
    }
    const result = await v.json();
    // NEVER include the raw JWT
    return result;
  }

  async function handleSummary() {
    console.log(`[wallet] summary: checking for issuer_id: ${ISSUER_ID}`);
    const rec = await getReceipt(ISSUER_ID);
    console.log(`[wallet] summary: receipt ${rec ? 'found' : 'not_found'}`);
    if (!rec) return { has_receipt: false };
    const pay = parseJwtPayload(rec.receipt_jwt);
    if (!pay) return { has_receipt: false, error: "decode_failed" };
    return {
      has_receipt: true,
      issuer: pay.iss,
      method: pay.method,
      over18: !!pay.over18,
      iat: pay.iat,
      exp: pay.exp,
      kid: pay.kid ?? null
    };
  }

  async function handleClear(params) {
    const { aud, return_url } = params || {};
    
    // Check if we need redirect for clear operation
    if (window.parent !== window && await needsRedirect()) {
      console.log(`[wallet] handleClear: REDIRECTING (storage blocked)`);
      // We're in iframe and storage is blocked - signal parent to redirect
      throw {
        code: "redirect_required",
        message: "Embedded storage unavailable; top-level redirect required", 
        mode: "clear",
        aud,
        return_url: return_url || aud
      };
    }
    
    console.log(`[wallet] handleClear: PROCEEDING INLINE (storage ok)`);
    await clearReceipt(ISSUER_ID);
    return { ok: true };
  }

  const handlers = {
    issue: handleIssue,
    verify: handleVerify,
    summary: handleSummary,
    clear: handleClear
  };

  // postMessage router with strict origin check
  window.addEventListener("message", async (evt) => {
    if (!ALLOWLIST.has(evt.origin)) return; // drop
    const msg = evt.data;
    if (!msg || msg.type !== "pave.wallet.rpc" || typeof msg.id !== "string") return;

    const { method, params } = msg;
    const fn = handlers[method];
    if (!fn) {
      evt.source?.postMessage({ type:"pave.wallet.resp", id: msg.id, ok:false, error:{code:"unknown_method", message: method} }, evt.origin);
      return;
    }

    try {
      const result = await fn(params);
      evt.source?.postMessage({ type:"pave.wallet.resp", id: msg.id, ok:true, result }, evt.origin);
    } catch (e) {
      const err = (typeof e === "object" && e) ? e : { code:"error", message:String(e) };
      evt.source?.postMessage({ type:"pave.wallet.resp", id: msg.id, ok:false, error: err }, evt.origin);
    }
  });

  // Initialize: run silent storage probe on iframe load
  if (window.parent !== window) {
    // We're in an iframe - run silent probe
    checkStorageCapability().catch(() => {
      // Probe failed, but don't show UI yet - wait for verify() call
    });
  }
})();