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
    return this.sendRequest("issue");
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