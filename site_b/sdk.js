/**
 * PAVE SDK - Client-side helper for age verification
 */

const AgePass = {
    // Storage key and endpoints
    STORAGE_KEY: 'agepass.jwt',
    ISSUER_ENDPOINT: 'http://localhost:8001/issue',
    VERIFIER_ENDPOINT: 'http://localhost:8003/verify',
    SHARED_STORAGE_ENDPOINT: 'http://localhost:8004/storage',

    // Storage mode: 'local' | 'shared' | 'both'
    storageMode: 'both',

    async storeReceipt(jwt) {
        if (!jwt || typeof jwt !== 'string') {
            throw new Error('Invalid JWT provided');
        }
        const mode = this.storageMode;
        if (mode === 'local') {
            localStorage.setItem(this.STORAGE_KEY, jwt);
            return;
        }
        if (mode === 'both') {
            try { localStorage.setItem(this.STORAGE_KEY, jwt); } catch (_) {}
        }
        try {
            await fetch(`${this.SHARED_STORAGE_ENDPOINT}/${this.STORAGE_KEY}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                mode: 'cors',
                body: JSON.stringify({ value: jwt })
            });
        } catch (e) {
            console.warn('Failed to store in shared storage:', e);
            if (mode === 'shared') { throw e; }
        }
    },

    async getReceipt() {
        const mode = this.storageMode;
        if (mode === 'local') {
            return localStorage.getItem(this.STORAGE_KEY);
        }
        if (mode === 'shared') {
            try {
                const response = await fetch(`${this.SHARED_STORAGE_ENDPOINT}/${this.STORAGE_KEY}`, {
                    method: 'GET',
                    mode: 'cors'
                });
                if (!response.ok) return null;
                const data = await response.json();
                return (data.exists && data.value) ? data.value : null;
            } catch (e) {
                console.warn('Failed to get from shared storage:', e);
                return null;
            }
        }
        let jwt = null;
        try { jwt = localStorage.getItem(this.STORAGE_KEY); } catch (_) {}
        if (jwt) return jwt;
        try {
            const response = await fetch(`${this.SHARED_STORAGE_ENDPOINT}/${this.STORAGE_KEY}`, {
                method: 'GET',
                mode: 'cors'
            });
            if (!response.ok) return null;
            const data = await response.json();
            return (data.exists && data.value) ? data.value : null;
        } catch (e) {
            console.warn('Failed to get from shared storage:', e);
            return null;
        }
    },

    async clearReceipt() {
        try { localStorage.removeItem(this.STORAGE_KEY); } catch (_) {}
        try {
            await fetch(`${this.SHARED_STORAGE_ENDPOINT}/${this.STORAGE_KEY}`, {
                method: 'DELETE',
                mode: 'cors'
            });
        } catch (e) {
            console.warn('Failed to clear from shared storage:', e);
        }
    },

    async issue() {
        try {
            const response = await fetch(this.ISSUER_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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
            await this.storeReceipt(data.receipt_jwt);
            return data.receipt_jwt;
        } catch (error) {
            console.error('AgePass.issue() failed:', error);
            throw error;
        }
    },

    async verify(options = {}) {
        const endpoint = options.endpoint || this.VERIFIER_ENDPOINT;
        const jwt = await this.getReceipt();
        if (!jwt) {
            return { ok: false, reason: 'no_receipt_stored', error: 'No receipt found in storage. Call issue() first.' };
        }
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                mode: 'cors',
                body: JSON.stringify({ receipt_jwt: jwt })
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Verify failed: ${response.status} ${errorText}`);
            }
            const result = await response.json();
            return result;
        } catch (error) {
            console.error('AgePass.verify() failed:', error);
            return { ok: false, reason: 'network_error', error: error.message };
        }
    },

    async getReceiptSummary() {
        const jwt = await this.getReceipt();
        if (!jwt) { return null; }
        try {
            const parts = jwt.split('.');
            if (parts.length !== 3) { return { error: 'Invalid JWT format' }; }
            const payload = parts[1];
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

if (typeof module !== 'undefined' && module.exports) {
    module.exports = AgePass;
} else if (typeof window !== 'undefined') {
    window.AgePass = AgePass;
}