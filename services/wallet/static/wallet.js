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
  async function handleIssue() {
    const resp = await fetch(ISSUER_ENDPOINT, { method: "POST", headers: {"Content-Type": "application/json"} });
    if (!resp.ok) throw { code: "issuer_http_error", message: `HTTP ${resp.status}` };
    const data = await resp.json();
    const jwt = data.receipt_jwt;
    if (!jwt) throw { code: "issuer_no_jwt", message: "No receipt_jwt" };
    await putReceipt({ issuer_id: ISSUER_ID, receipt_jwt: jwt });
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
    const { aud } = params || {};
    if (!aud || typeof aud !== "string") throw { code: "bad_params", message: "verify requires {aud}" };

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
    const rec = await getReceipt(ISSUER_ID);
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

  async function handleClear() {
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
})();