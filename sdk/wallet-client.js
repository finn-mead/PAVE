// PAVE SDK v0.1.0-dev (single-source via wallet:8000)
// PAVE Wallet Client SDK
// Simple wrapper for communicating with the wallet iframe

class PaveWalletClient {
  static REDIRECT_RESULT_KEY = "pave:redirect_result";
  static PENDING_STATE_KEY   = "pave:pending_state";
  
  constructor(walletOrigin = "http://localhost:8000", iframePath = "/static/iframe.html") {
    this.walletOrigin = walletOrigin;
    this.iframePath = iframePath;
    this.iframe = null;
    this.pendingRequests = new Map();
    this.pendingRedirectRequests = new Map();
    this.requestId = 0;
    
    // Bind message handler
    this.handleMessage = this.handleMessage.bind(this);
    window.addEventListener("message", this.handleMessage);
    
    // Check for fragment result on page load
    this.checkFragmentResult();
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
    
    // Handle iframe RPC responses
    if (msg && msg.type === "pave.wallet.resp") {
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
      return;
    }
    
    // Handle redirect flow results
    if (msg && msg.type === "pave.verify.result") {
      const { state, result } = msg;
      const pending = this.pendingRedirectRequests?.get(state);
      if (pending) {
        this.pendingRedirectRequests.delete(state);
        pending.resolve(result);
      }
      return;
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
  async issue(options = {}) {
    const { policy = "uk_adult_high", returnUrl = window.location.href } = options;
    try {
      await this.init();
      return await this.sendRequest("issue");
    } catch (error) {
      if (error && error.code === "redirect_required") {
        // Same redirect machinery we use elsewhere
        return this.initiateRedirectFlow(policy, returnUrl, /*usePopup*/ false);
      }
      throw error;
    }
  }

  /**
   * Verify existing receipt with a verifier
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
    return this.sendRequest("clear");
  }

  /**
   * Main verification method with flow control
   * @param {Object} options - Verification options
   * @param {string} options.policy - Policy tag (e.g., "uk_adult_high")
   * @param {string} options.flow - Flow type: "auto" (iframe first), "redirect", "popup"
   * @param {string} options.returnUrl - Return URL for redirect flow
   * @returns {Promise<Object>} Verification result
   */
  async verifyWithFlow(options = {}) {
    const { policy = "uk_adult_high", flow = "auto", returnUrl = window.location.href } = options;
    
    if (flow === "redirect" || flow === "popup") {
      return this.initiateRedirectFlow(policy, returnUrl, flow === "popup");
    }
    
    // Auto flow: try iframe first, fallback to redirect
    try {
      await this.init();
      return await this.verify(window.location.origin);
    } catch (error) {
      if (error.code === "redirect_required") {
        return this.initiateRedirectFlow(policy, returnUrl, false);
      }
      throw error;
    }
  }

  /**
   * Initiate redirect/popup flow
   * @param {string} policy - Policy tag
   * @param {string} returnUrl - Return URL
   * @param {boolean} usePopup - Whether to use popup vs full redirect
   * @returns {Promise<Object>} Verification result
   */
  async initiateRedirectFlow(policy, returnUrl, usePopup = false) {
    const state = this.generateState();
    const aud = window.location.origin;
    
    // Ensure the wallet can append its own #pave_result cleanly
    const cleanReturnUrl = String(returnUrl).split('#')[0];
    
    const params = new URLSearchParams({
      aud,
      policy_id: policy,
      return_url: cleanReturnUrl,
      state,
      mode: "auto"
    });
    
    const walletUrl = `${this.walletOrigin}/verify-ui?${params.toString()}`;
    
    return new Promise((resolve, reject) => {
      this.pendingRedirectRequests.set(state, { resolve, reject });
      // remember state so we can correlate after a full page load
      try { sessionStorage.setItem(PaveWalletClient.PENDING_STATE_KEY, state); } catch {}
      
      // Cleanup after timeout
      setTimeout(() => {
        if (this.pendingRedirectRequests.has(state)) {
          this.pendingRedirectRequests.delete(state);
          reject(new Error("Redirect flow timeout"));
        }
      }, 300000); // 5 minute timeout
      
      if (usePopup) {
        // Open popup
        const popup = window.open(walletUrl, 'pave_wallet', 'width=500,height=600,scrollbars=yes,resizable=yes');
        if (!popup) {
          // Popup blocked, fallback to redirect
          window.location.href = walletUrl;
        }
      } else {
        // Full redirect
        window.location.href = walletUrl;
      }
    });
  }

  /**
   * Generate random state for CSRF protection
   */
  generateState() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode.apply(null, array))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Check for fragment result on page load
   */
  checkFragmentResult() {
    const hash = window.location.hash;
    if (hash.startsWith('#pave_result=') || hash.startsWith('#%23pave_result=')) {
      try {
        // tolerate '#%23pave_result=' by decoding once
        const raw = hash.startsWith('#%23') ? decodeURIComponent(hash.slice(1)) : hash.slice(1);
        const encoded = raw.replace(/^pave_result=/, '');
        const decoded = atob(encoded.replace(/-/g, '+').replace(/_/g, '/'));
        const { state, result } = JSON.parse(decoded);
        
        // Clear the fragment
        window.location.hash = '';
        
        // 1) Resolve if this page still has a pending Promise (popup case)
        const pending = this.pendingRedirectRequests?.get(state);
        if (pending) {
          this.pendingRedirectRequests.delete(state);
          pending.resolve(result);
        }
        // 2) Always persist so a *new* page load can consume it
        try {
          sessionStorage.setItem(
            PaveWalletClient.REDIRECT_RESULT_KEY,
            JSON.stringify({ state, result })
          );
          sessionStorage.removeItem(PaveWalletClient.PENDING_STATE_KEY);
        } catch {}

        // 3) Fire a DOM event for apps that want to listen
        try { window.dispatchEvent(new CustomEvent('pave:result', { detail: { state, result } })); } catch {}
      } catch (error) {
        console.warn("[PAVE SDK] Failed to parse fragment result:", error);
      }
    }
  }

  /**
   * Retrieve & clear a redirect result after a full page reload.
   * @returns {{state: string, result: object}|null}
   */
  consumeRedirectResult() {
    try {
      const raw = sessionStorage.getItem(PaveWalletClient.REDIRECT_RESULT_KEY);
      if (!raw) return null;
      sessionStorage.removeItem(PaveWalletClient.REDIRECT_RESULT_KEY);
      return JSON.parse(raw);
    } catch {
      return null;
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
    this.pendingRedirectRequests.clear();
  }
}

// Export for both CommonJS and ES modules
if (typeof module !== "undefined" && module.exports) {
  module.exports = PaveWalletClient;
} else if (typeof window !== "undefined") {
  window.PaveWalletClient = PaveWalletClient;
}