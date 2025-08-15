/**
 * PAVE SDK - Client-side helper for age verification
 */

const AgePass = {
    // Storage key for cookie
    STORAGE_KEY: 'agepass.jwt',
    
    // Default endpoints
    ISSUER_ENDPOINT: 'http://localhost:8001/issue',
    VERIFIER_ENDPOINT: 'http://localhost:8003/verify',
    
    setCookie(name, value, options = {}) {
        let cookieString = `${name}=${encodeURIComponent(value)}`;
        if (options.secure) cookieString += '; Secure';
        if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
        if (options.expires) cookieString += `; expires=${options.expires.toUTCString()}`;
        cookieString += '; path=/';
        document.cookie = cookieString;
    },
    getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) {
            return decodeURIComponent(parts.pop().split(';').shift());
        }
        return null;
    },
    deleteCookie(name) {
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
    },
    
    storeReceipt(jwt) {
        if (!jwt || typeof jwt !== 'string') {
            throw new Error('Invalid JWT provided');
        }
        const expires = new Date();
        expires.setTime(expires.getTime() + (24 * 60 * 60 * 1000));
        this.setCookie(this.STORAGE_KEY, jwt, { secure: true, sameSite: 'None', expires });
    },
    
    getReceipt() {
        return this.getCookie(this.STORAGE_KEY);
    },
    
    clearReceipt() {
        this.deleteCookie(this.STORAGE_KEY);
    },
    
    /**
     * Issue a new receipt from the Issuer and store it
     * @returns {Promise<string>} - The issued JWT
     */
    async issue() {
        try {
            const response = await fetch(this.ISSUER_ENDPOINT, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                mode: 'cors'
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Issue failed: ${response.status} ${errorText}`);
            }
            
            const data = await response.json();
            
            if (!data.receipt_jwt) {
                throw new Error('No receipt_jwt in response');
            }
            
            // Store the receipt
            this.storeReceipt(data.receipt_jwt);
            
            return data.receipt_jwt;
            
        } catch (error) {
            console.error('AgePass.issue() failed:', error);
            throw error;
        }
    },
    
    /**
     * Verify the stored receipt with the Verifier
     * @param {Object} options - Verification options
     * @param {string} [options.endpoint] - Custom verifier endpoint
     * @returns {Promise<Object>} - Verification result
     */
    async verify(options = {}) {
        const endpoint = options.endpoint || this.VERIFIER_ENDPOINT;
        const jwt = this.getReceipt();
        
        if (!jwt) {
            return {
                ok: false,
                reason: 'no_receipt_stored',
                error: 'No receipt found in storage. Call issue() first.'
            };
        }
        
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                mode: 'cors',
                body: JSON.stringify({
                    receipt_jwt: jwt
                })
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Verify failed: ${response.status} ${errorText}`);
            }
            
            const result = await response.json();
            
            return result;
            
        } catch (error) {
            console.error('AgePass.verify() failed:', error);
            return {
                ok: false,
                reason: 'network_error',
                error: error.message
            };
        }
    },
    
    /**
     * Get a summary of the stored receipt without verifying
     * @returns {Object|null} - Receipt summary or null if no receipt
     */
    getReceiptSummary() {
        const jwt = this.getReceipt();
        if (!jwt) {
            return null;
        }
        
        try {
            // Decode JWT payload (without verifying signature)
            const parts = jwt.split('.');
            if (parts.length !== 3) {
                return { error: 'Invalid JWT format' };
            }
            
            const payload = parts[1];
            // Add padding if needed
            const paddedPayload = payload + '='.repeat((4 - payload.length % 4) % 4);
            const decoded = JSON.parse(atob(paddedPayload));
            
            return {
                issuer: decoded.iss,
                method: decoded.method,
                issued_at: new Date(decoded.iat * 1000).toLocaleString(),
                expires_at: new Date(decoded.exp * 1000).toLocaleString(),
                over18: decoded.over18,
                preview: jwt.substring(0, 20) + '...' + jwt.substring(jwt.length - 20)
            };
        } catch (error) {
            return { error: 'Failed to decode JWT' };
        }
    }
};

// Export for both ESM and global usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AgePass;
} else if (typeof window !== 'undefined') {
    window.AgePass = AgePass;
}