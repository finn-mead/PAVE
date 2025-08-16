// services/wallet/static/verify-ui.js
(() => {
  const ALLOWLIST = new Set(["http://localhost:9001", "http://localhost:9002"]);
  const ISSUER_ID = "fastage";
  const VERIFIER_CHALLENGE = "http://localhost:8003/challenge";
  const VERIFIER_VERIFY = "http://localhost:8003/verify/envelope";
  
  // DOM elements
  const statusEl = document.getElementById('status');
  const spinnerEl = document.getElementById('spinner');
  const resultEl = document.getElementById('result');
  const errorEl = document.getElementById('error');

  function log(message) {
    console.log(`[wallet.verify_ui] ${message}`);
  }

  function setStatus(message, hideSpinner = false) {
    statusEl.textContent = message;
    if (hideSpinner) {
      spinnerEl.style.display = 'none';
    }
  }

  function showError(message, showBackLink = true) {
    spinnerEl.style.display = 'none';
    errorEl.style.display = 'block';
    errorEl.innerHTML = `
      <div class="error">
        ${message}
        ${showBackLink ? `<br><a href="#" onclick="history.back()" class="back-link">← Back to site</a>` : ''}
      </div>
    `;
  }

  function showResult(result, aud) {
    spinnerEl.style.display = 'none';
    resultEl.style.display = 'block';
    
    if (result.ok) {
      resultEl.innerHTML = `
        <div class="success">✅ Verification Complete</div>
        <div style="font-size: 14px; color: #666; margin-top: 8px;">
          Age verified successfully
        </div>
      `;
    } else {
      resultEl.innerHTML = `
        <div class="error">❌ Verification Failed</div>
        <div style="font-size: 14px; color: #666; margin-top: 8px;">
          ${result.reason || 'Unknown error'}
        </div>
      `;
    }
    
    setTimeout(() => {
      setStatus('Returning to site...', true);
    }, 1500);
  }

  // IndexedDB helpers (same as wallet.js)
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

  async function getReceipt(issuer_id) {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(issuer_id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  function returnResult(result, aud, state, return_url) {
    const payload = { state, result };
    
    // Option A: postMessage to opener (preferred)
    if (window.opener && aud) {
      try {
        log(`return.postmessage to ${aud}`);
        window.opener.postMessage({
          type: "pave.verify.result",
          state,
          result
        }, aud);
        window.close();
        return;
      } catch (error) {
        log(`postMessage failed: ${error.message}`);
      }
    }
    
    // Option B: URL fragment fallback
    log(`return.location to ${return_url}`);
    const fragment = btoa(JSON.stringify(payload))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    window.location.href = `${return_url}#pave_result=${fragment}`;
  }

  // --- Mode handlers ---
  async function handleIssueMode(aud, policy_id, return_url, state, siteName) {
    setStatus(`Getting 18+ pass for ${siteName}...`);
    
    // Issue a new receipt
    const issueResp = await fetch("http://localhost:8001/issue", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    
    if (!issueResp.ok) {
      showError(`Failed to get pass: HTTP ${issueResp.status}`);
      return;
    }
    
    const issueData = await issueResp.json();
    const jwt = issueData.receipt_jwt;
    if (!jwt) {
      showError('No receipt received from issuer');
      return;
    }
    
    // Store the receipt
    await new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE, { keyPath: "issuer_id" });
        }
      };
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put({ issuer_id: ISSUER_ID, receipt_jwt: jwt });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
      req.onerror = () => reject(req.error);
    });
    
    // Return success result
    const payload = parseJwtPayload(jwt) || {};
    const result = {
      ok: true,
      issuer: payload.iss,
      method: payload.method,
      over18: !!payload.over18,
      iat: payload.iat,
      exp: payload.exp
    };
    
    showResult({ ok: true, reason: 'Pass issued successfully' }, aud);
    setTimeout(() => {
      returnResult(result, aud, state, return_url);
    }, 2000);
  }

  async function handleVerifyMode(aud, policy_id, return_url, state, siteName) {
    setStatus(`Verifying your 18+ pass for ${siteName}...`);

    // Check for stored receipt
    log(`verifyui.checking_receipt for issuer_id: ${ISSUER_ID}`);
    const rec = await getReceipt(ISSUER_ID);
    log(`verifyui.receipt_result: ${rec ? 'found' : 'not_found'}`);
    if (!rec) {
      log('verifyui.no_receipt');
      // Return failure result instead of showing error page
      const result = { ok: false, reason: "no_receipt" };
      setStatus('No pass found - returning to site...', true);
      
      setTimeout(() => {
        returnResult(result, aud, state, return_url);
      }, 1500);
      return;
    }

    await performVerification(rec, aud, policy_id, state, return_url);
  }

  async function handleAutoMode(aud, policy_id, return_url, state, siteName) {
    // Auto mode: try verify first, if no receipt then issue
    setStatus(`Checking for 18+ pass for ${siteName}...`);
    
    const rec = await getReceipt(ISSUER_ID);
    if (rec) {
      // Have receipt, proceed with verification
      await performVerification(rec, aud, policy_id, state, return_url);
    } else {
      // No receipt, issue one first then verify
      log('verifyui.auto_mode.no_receipt_issuing');
      await handleIssueMode(aud, policy_id, return_url, state, siteName);
    }
  }

  async function handleClearMode(aud, policy_id, return_url, state, siteName) {
    setStatus(`Clearing stored pass for ${siteName}...`);
    
    // Clear the receipt from first-party storage
    const req = indexedDB.open(DB_NAME, 1);
    await new Promise((resolve, reject) => {
      req.onsuccess = () => {
        const db = req.result;
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).delete(ISSUER_ID);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      };
      req.onerror = () => reject(req.error);
    });
    
    // Show clear-specific success message
    spinnerEl.style.display = 'none';
    resultEl.style.display = 'block';
    resultEl.innerHTML = `
      <div class="success">🗑️ Pass Cleared</div>
      <div style="font-size: 14px; color: #666; margin-top: 8px;">
        Your 18+ pass has been removed from wallet storage
      </div>
    `;
    
    setTimeout(() => {
      setStatus('Returning to site...', true);
    }, 1500);
    
    // Return success result
    const result = { ok: true };
    setTimeout(() => {
      returnResult(result, aud, state, return_url);
    }, 2000);
  }

  function parseJwtPayload(jwt) {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    try {
      const pad = "=".repeat((4 - (parts[1].length % 4)) % 4);
      const json = atob((parts[1] + pad).replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(json);
    } catch { 
      return null; 
    }
  }

  async function performVerification(rec, aud, policy_id, state, return_url) {
    // Fetch challenge nonce
    setStatus('Getting verification challenge...');
    const chResp = await fetch(VERIFIER_CHALLENGE, { 
      method: "GET",
      headers: { "Origin": window.location.origin }
    });
    
    if (!chResp.ok) {
      log(`verifyui.challenge.fail {status: ${chResp.status}}`);
      showError(`Challenge failed: HTTP ${chResp.status}`);
      return;
    }

    const { nonce, exp_s } = await chResp.json();
    if (!nonce) {
      showError('No nonce received from challenge');
      return;
    }

    log('verifyui.challenge.ok');

    // Build envelope and verify
    setStatus('Verifying with PAVE network...');
    const envelope = {
      aud,
      nonce,
      receipt: rec.receipt_jwt
    };

    const verifyResp = await fetch(VERIFIER_VERIFY, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json",
        "Origin": window.location.origin
      },
      body: JSON.stringify({ envelope, policy_id })
    });

    if (!verifyResp.ok) {
      const errorText = await verifyResp.text().catch(() => '');
      log(`verifyui.verify.fail {status: ${verifyResp.status}}`);
      showError(`Verification failed: HTTP ${verifyResp.status} ${errorText}`);
      return;
    }

    const result = await verifyResp.json();
    log(`verifyui.verify.ok {reason: ${result.reason || 'success'}}`);

    // Show result briefly
    showResult(result, aud);
    
    // Return result after brief delay
    setTimeout(() => {
      returnResult(result, aud, state, return_url);
    }, 2000);
  }

  async function main() {
    try {
      // Parse and validate URL parameters
      const params = new URLSearchParams(window.location.search);
      const aud = params.get('aud');
      const policy_id = params.get('policy_id') || 'uk_adult_high';
      const return_url = params.get('return_url');
      const state = params.get('state');
      const mode = params.get('mode') || 'verify'; // verify|issue|auto
      const force = params.get('force') === '1';

      log(`verifyui.init {aud: ${aud}, policy_id: ${policy_id}, mode: ${mode}, forced: ${force}}`);

      // Validate required parameters
      if (!aud || !return_url || !state) {
        showError('Missing required parameters: aud, return_url, state');
        return;
      }

      // Validate aud is allowlisted
      if (!ALLOWLIST.has(aud)) {
        showError(`Audience '${aud}' not allowlisted`);
        return;
      }

      // Validate return_url origin matches aud
      let returnUrlObj;
      try {
        returnUrlObj = new URL(return_url);
      } catch (error) {
        showError('Invalid return_url format');
        return;
      }

      if (returnUrlObj.origin !== aud) {
        showError(`return_url origin '${returnUrlObj.origin}' does not match aud '${aud}'`);
        return;
      }

      // Validate scheme (HTTPS required except localhost)
      if (returnUrlObj.protocol !== 'https:' && !returnUrlObj.hostname.includes('localhost')) {
        showError('return_url must use HTTPS (except localhost)');
        return;
      }

      // Update status to show which site we're verifying for
      const siteName = aud.includes('9001') ? 'Site A' : 
                      aud.includes('9002') ? 'Site B' : 
                      new URL(aud).hostname;
      
      // Handle different modes
      if (mode === 'issue') {
        await handleIssueMode(aud, policy_id, return_url, state, siteName);
        return;
      } else if (mode === 'verify') {
        await handleVerifyMode(aud, policy_id, return_url, state, siteName);
        return;
      } else if (mode === 'auto') {
        await handleAutoMode(aud, policy_id, return_url, state, siteName);
        return;
      } else if (mode === 'clear') {
        await handleClearMode(aud, policy_id, return_url, state, siteName);
        return;
      } else {
        showError(`Invalid mode '${mode}'. Expected: verify, issue, auto, or clear`);
        return;
      }

    } catch (error) {
      log(`verifyui.error: ${error.message}`);
      showError(`Unexpected error: ${error.message}`);
    }
  }

  // Start verification flow when page loads
  document.addEventListener('DOMContentLoaded', main);
})();