// PAVE Wallet Client SDK
// Simple wrapper for communicating with the wallet iframe

class PaveWalletClient {
  constructor(walletOrigin = "http://localhost:8000", iframePath = "/iframe.html") {
    this.walletOrigin = walletOrigin;
    this.iframePath = iframePath;
    this.iframe = null;
    this.pendingRequests = new Map();
    this.requestId = 0;
    
    // Bind message handler
    this.handleMessage = this.handleMessage.bind(this);
    window.addEventListener("message", this.handleMessage);
  }

  async init() {
    if (this.iframe) return; // Already initialized
    
    // Create and inject iframe
    this.iframe = document.createElement("iframe");
    this.iframe.src = this.walletOrigin + this.iframePath;
    this.iframe.style.display = "none";
    this.iframe.style.width = "0";
    this.iframe.style.height = "0";
    this.iframe.style.border = "none";
    
    document.body.appendChild(this.iframe);
    
    // Wait for iframe to load
    return new Promise((resolve, reject) => {
      this.iframe.onload = () => resolve();
      this.iframe.onerror = () => reject(new Error("Failed to load wallet iframe"));
      
      // Timeout after 10 seconds
      setTimeout(() => reject(new Error("Wallet iframe load timeout")), 10000);
    });
  }

  handleMessage(event) {
    if (event.origin !== this.walletOrigin) return;
    
    const msg = event.data;
    if (!msg || msg.type !== "pave.wallet.resp") return;
    
    const { id, ok, result, error } = msg;
    const pending = this.pendingRequests.get(id);
    if (!pending) return;
    
    this.pendingRequests.delete(id);
    
    if (ok) {
      pending.resolve(result);
    } else {
      const err = new Error(error?.message || "Wallet operation failed");
      err.code = error?.code;
      pending.reject(err);
    }
  }

  async sendRequest(method, params = null) {
    if (!this.iframe) {
      throw new Error("Wallet not initialized. Call init() first.");
    }
    
    const id = String(++this.requestId);
    const message = {
      type: "pave.wallet.rpc",
      id,
      method,
      params
    };
    
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      
      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Request timeout: ${method}`));
        }
      }, 30000);
      
      this.iframe.contentWindow.postMessage(message, this.walletOrigin);
    });
  }

  // API methods

  /**
   * Issue a new age verification receipt
   * @returns {Promise<Object>} Receipt info with issuer, method, over18, iat, exp
   */
  async issue() {
    const aud = window.location.origin;
    const return_url = window.location.href;
    try {
      return await this.sendRequest("issue", { aud, return_url });
    } catch (err) {
      if (err?.code === "redirect_required") {
        const mode = err.mode === "issue" ? "issue" : "auto";
        return this.initiateRedirectFlow(aud, "uk_adult_high", return_url, { mode });
      }
      throw err;
    }
  }

  /**
   * Verify existing receipt with a verifier (legacy iframe-only)
   * @param {string} aud - Audience (verifier URL)
   * @returns {Promise<Object>} Verification result
   */
  async verify(aud) {
    if (!aud || typeof aud !== "string") {
      throw new Error("verify() requires aud parameter");
    }
    return this.sendRequest("verify", { aud });
  }

  /**
   * Verify with flow control (new API)
   * @param {Object} options - Verification options
   * @param {string} options.policy - Policy ID (default: uk_adult_high)
   * @param {string} options.flow - Flow mode: auto|iframe|redirect (default: auto)
   * @param {string} options.returnUrl - Return URL for redirect (default: current page)
   * @returns {Promise<Object>} Verification result
   */
  async verifyWithFlow(options = {}) {
    const {
      policy = "uk_adult_high",
      flow = "auto", 
      returnUrl = window.location.href
    } = options;
    
    const aud = window.location.origin;
    
    console.log(`[pave.sdk] verify.start {flow: ${flow}, aud: ${aud}}`);

    // Force redirect mode
    if (flow === "redirect") {
      return this.initiateRedirectFlow(aud, policy, returnUrl);
    }

    // Try iframe first (auto or iframe mode)
    try {
      const result = await this.sendRequest("verify", { 
        aud, 
        flow, 
        policy_id: policy,
        return_url: returnUrl 
      });
      return result;
    } catch (error) {
      // If iframe fails and we're in auto mode, try redirect
      if (flow === "auto" && (
        error.code === "redirect_required" || 
        error.code === "no_receipt" ||
        error.code === "storage_blocked"
      )) {
        console.log(`[pave.sdk] iframe failed (${error.code}), falling back to redirect`);
        return this.initiateRedirectFlow(aud, policy, returnUrl);
      }
      throw error;
    }
  }

  initiateRedirectFlow(aud, policy_id, return_url, opts = {}) {
    return new Promise((resolve, reject) => {
      const mode = opts.mode || "verify"; // verify | issue | auto
      const state = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      
      const params = new URLSearchParams({
        aud,
        policy_id,
        return_url,
        state,
        mode
      });
      
      const url = `${this.walletOrigin}/verify-ui?${params}`;
      
      // Store promise resolvers for result handling
      window.paveRedirectResolvers = window.paveRedirectResolvers || {};
      window.paveRedirectResolvers[state] = { resolve, reject };
      
      // Set up result listeners
      this.setupRedirectResultHandlers();
      
      // Try popup first
      try {
        const popup = window.open(url, 'pave_wallet', 'width=600,height=400');
        if (!popup) {
          throw new Error('Popup blocked');
        }
        
        // Timeout for popup
        setTimeout(() => {
          if (window.paveRedirectResolvers[state]) {
            delete window.paveRedirectResolvers[state];
            reject(new Error('Redirect verification timeout'));
          }
        }, 120000); // 2 minutes
        
      } catch (error) {
        // Popup blocked, use full navigation
        console.log('[pave.sdk] popup blocked, using full redirect');
        window.location.href = url;
      }
    });
  }

  setupRedirectResultHandlers() {
    // Avoid duplicate listeners
    if (window.paveRedirectHandlersSetup) return;
    window.paveRedirectHandlersSetup = true;
    
    // Handle postMessage returns (from popup)
    window.addEventListener('message', (event) => {
      if (event.origin !== this.walletOrigin) return;
      if (event.data?.type !== 'pave.verify.result') return;
      
      const { state, result } = event.data;
      const resolver = window.paveRedirectResolvers?.[state];
      if (resolver) {
        delete window.paveRedirectResolvers[state];
        resolver.resolve(result);
      }
    });
    
    // Handle fragment returns (from full page redirect)
    const checkFragment = () => {
      const hash = window.location.hash;
      if (!hash.startsWith('#pave_result=')) return;
      
      try {
        const b64 = hash.substring('#pave_result='.length);
        const jsonStr = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
        const { state, result } = JSON.parse(jsonStr);
        
        const resolver = window.paveRedirectResolvers?.[state];
        if (resolver) {
          delete window.paveRedirectResolvers[state];
          resolver.resolve(result);
          // Clean up hash
          history.replaceState(null, '', window.location.pathname + window.location.search);
        }
      } catch (error) {
        console.error('[pave.sdk] failed to parse redirect result:', error);
      }
    };
    
    // Check on load and hash changes
    checkFragment();
    window.addEventListener('hashchange', checkFragment);
  }

  /**
   * Get summary of stored receipt
   * @returns {Promise<Object>} Receipt summary or {has_receipt: false}
   */
  async summary() {
    return this.sendRequest("summary");
  }

  /**
   * Clear stored receipt
   * @returns {Promise<Object>} {ok: true}
   */
  async clear() {
    const aud = window.location.origin;
    const return_url = window.location.href;
    try {
      return await this.sendRequest("clear", { aud, return_url });
    } catch (err) {
      if (err?.code === "redirect_required") {
        return this.initiateRedirectFlow(aud, "uk_adult_high", return_url, { mode: "clear" });
      }
      throw err;
    }
  }

  /**
   * Cleanup - remove iframe and event listeners
   */
  destroy() {
    window.removeEventListener("message", this.handleMessage);
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
    }
    this.iframe = null;
    this.pendingRequests.clear();
  }
}

// Export for both CommonJS and ES modules
if (typeof module !== "undefined" && module.exports) {
  module.exports = PaveWalletClient;
} else if (typeof window !== "undefined") {
  window.PaveWalletClient = PaveWalletClient;
}