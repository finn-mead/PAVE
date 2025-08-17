// Global constants
const POLL_INTERVAL_MS = 10_000;   // 10s
const EVENTS_LIMIT = 200;          // GET /log/events?limit=200
const TOAST_DURATION_MS = 3500;

// Global state store
const state = {
    head: null,                 // { ts, digest, key_id, sig }
    canonicalDigest: null,      // { digest }
    issuers: [],                // Issuer[]
    events: [],                 // EventV1[] with enriched fields
    filters: { outcome: "", issuerLabel: "", policy: "", verify_id: "" }, // UI-level
    // Derived
    issuerLabelToServerFilter: null, // function(label) => {attested_issuer?|issuer?}
    lastUpdatedISO: null,
    expandedRows: new Set()     // Track which event rows are expanded
};

// AbortControllers for polling
let headPollerController = null;
let issuersPollerController = null;
let eventsPollerController = null;

// =============================================================================
// Utility functions
// =============================================================================

function truncate(s, n = 8) {
    if (!s || typeof s !== 'string') return '—';
    return s.length > n ? s.substring(0, n) + '...' : s;
}

function copyToClipboard(text) {
    if (!text) return Promise.reject(new Error('No text to copy'));
    return navigator.clipboard.writeText(text);
}

function formatISO(ts) {
    if (!ts) return '—';
    try {
        return new Date(ts).toLocaleString('en-US', { timeZone: 'UTC' });
    } catch {
        return '—';
    }
}

function badge(outcome) {
    const outcomeClass = outcome === 'ok' ? 'outcome-ok' : 'outcome-fail';
    const outcomeIcon = outcome === 'ok' ? '✓' : '✗';
    return { class: outcomeClass, icon: outcomeIcon };
}

function safeText(element, text) {
    if (element) {
        element.textContent = text || '—';
    }
}

function val(x) {
    return x ?? '—';
}

function checkStaleness(eventTs, headTs) {
    if (!eventTs || !headTs) return false;
    try {
        const eventTime = new Date(eventTs).getTime();
        const headTime = new Date(headTs).getTime();
        return Math.abs(eventTime - headTime) > 300000; // 300s = 5 minutes
    } catch {
        return false;
    }
}

// =============================================================================
// API Helpers
// =============================================================================

async function apiGet(path, params = {}, { signal } = {}) {
    const url = new URL(path, window.location.origin);
    
    // Add query parameters
    Object.keys(params).forEach(key => {
        if (params[key] !== '' && params[key] != null) {
            url.searchParams.set(key, params[key]);
        }
    });
    
    const response = await fetch(url.toString(), {
        method: 'GET',
        headers: {
            'Accept': 'application/json',
            'Authorization': 'Basic ' + btoa('admin:dev-admin-pass')
        },
        signal
    });
    
    if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`HTTP ${response.status}${text ? ': ' + text : ''}`);
    }
    
    return response.json();
}

async function apiPost(path, {csrf} = {}) {
    const headers = { "Content-Type": "application/json", "Authorization": "Basic " + btoa("admin:dev-admin-pass") };
    if (csrf) headers["X-Admin-CSRF"] = csrf;
    headers["X-Admin-CSRF"] = "dev-csrf-token"; // Always include CSRF for admin actions
    const r = await fetch(path, { method: "POST", headers });
    if (!r.ok) {
        const text = await r.text().catch(() => "");
        throw new Error(`HTTP ${r.status}: ${text || "request failed"}`);
    }
    return r.json();
}

async function reloadHeadAndIssuers() {
    const [head, issuers] = await Promise.all([
        fetch("/log/head", {headers: {"Authorization": "Basic " + btoa("admin:dev-admin-pass")}}).then(r => r.json()),
        fetch("/log/issuers", {headers: {"Authorization": "Basic " + btoa("admin:dev-admin-pass")}}).then(r => r.json()),
    ]);
    state.head = head;
    state.issuers = issuers;
    renderHeadCard();
    renderIssuersTable();
}

// =============================================================================
// Filter mapping logic
// =============================================================================

function eventsQueryFromFilters(state) {
    const p = new URLSearchParams();
    p.set("limit", String(EVENTS_LIMIT));
    
    if (state.filters.outcome) {
        p.set("outcome", state.filters.outcome);
    }
    
    if (state.filters.policy) {
        p.set("policy_tag", state.filters.policy);
    }
    
    if (state.filters.verify_id) {
        p.set("verify_id", state.filters.verify_id);
    }
    
    // issuerLabel -> server filter
    if (state.filters.issuerLabel && state.issuerLabelToServerFilter) {
        const serverFilter = state.issuerLabelToServerFilter(state.filters.issuerLabel);
        if (serverFilter.attested_issuer) {
            p.set("attested_issuer", serverFilter.attested_issuer);
        } else if (serverFilter.issuer) {
            p.set("issuer", serverFilter.issuer);
        }
    }
    
    return p;
}

function buildIssuerLabelToServerFilter(events) {
    return (label) => {
        // First: does label match any attested_issuer? If so, prefer attested_issuer param.
        const hasAttested = events.some(e => e.attested_issuer === label);
        if (hasAttested) {
            return { attested_issuer: label };
        }
        
        // Else map host label back to a concrete issuer URL seen in events
        const row = events.find(e => !e.attested_issuer && new URL(e.issuer).hostname === label);
        if (row) {
            return { issuer: row.issuer };
        }
        
        // Fallback: no server filter (should not happen if label came from options)
        return {};
    };
}

// =============================================================================
// Toast notifications
// =============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toast');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Auto-remove
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }, TOAST_DURATION_MS);
}

// =============================================================================
// Polling systems
// =============================================================================

async function pollHeadAndDigest() {
    if (headPollerController) {
        headPollerController.abort();
    }
    headPollerController = new AbortController();
    
    try {
        const [head, digest] = await Promise.all([
            apiGet('/log/head', {}, { signal: headPollerController.signal }),
            apiGet('/log/digest', {}, { signal: headPollerController.signal })
        ]);
        
        state.head = head;
        state.canonicalDigest = digest;
        updateLastUpdated();
        renderHeadCard();
        
    } catch (error) {
        if (error.name !== 'AbortError') {
            console.error('Head/digest poll error:', error);
            showToast(`Couldn't load head/digest: ${error.message}`, 'error');
            
            // Retry in 5s instead of 10s
            setTimeout(pollHeadAndDigest, 5000);
            return;
        }
    }
    
    // Schedule next poll
    setTimeout(pollHeadAndDigest, POLL_INTERVAL_MS);
}

async function pollIssuers() {
    if (issuersPollerController) {
        issuersPollerController.abort();
    }
    issuersPollerController = new AbortController();
    
    try {
        const issuers = await apiGet('/log/issuers', {}, { signal: issuersPollerController.signal });
        state.issuers = issuers;
        updateLastUpdated();
        renderIssuersTable();
        
    } catch (error) {
        if (error.name !== 'AbortError') {
            console.error('Issuers poll error:', error);
            showToast(`Couldn't load issuers: ${error.message}`, 'error');
            
            // Retry in 5s instead of 10s
            setTimeout(pollIssuers, 5000);
            return;
        }
    }
    
    // Schedule next poll
    setTimeout(pollIssuers, POLL_INTERVAL_MS);
}

async function pollEvents() {
    if (eventsPollerController) {
        eventsPollerController.abort();
    }
    eventsPollerController = new AbortController();
    
    try {
        const params = {};
        const urlParams = eventsQueryFromFilters(state);
        urlParams.forEach((value, key) => {
            params[key] = value;
        });
        
        const response = await apiGet('/log/events', params, { signal: eventsPollerController.signal });
        state.events = response.items || [];
        
        // Build issuer label mapping
        state.issuerLabelToServerFilter = buildIssuerLabelToServerFilter(state.events);
        
        updateLastUpdated();
        renderEventsTable();
        updateEventFilters();
        
    } catch (error) {
        if (error.name !== 'AbortError') {
            console.error('Events poll error:', error);
            showToast(`Couldn't load events: ${error.message}`, 'error');
            
            // Retry in 5s instead of 10s
            setTimeout(pollEvents, 5000);
            return;
        }
    }
    
    // Schedule next poll
    setTimeout(pollEvents, POLL_INTERVAL_MS);
}

function updateLastUpdated() {
    state.lastUpdatedISO = new Date().toISOString();
    const elem = document.getElementById('last-updated');
    if (elem) {
        elem.textContent = `Last updated: ${new Date(state.lastUpdatedISO).toLocaleTimeString()}`;
    }
}

// =============================================================================
// Rendering functions
// =============================================================================

function renderHeadCard() {
    const digestElem = document.getElementById('head-digest');
    const tsElem = document.getElementById('head-ts');
    const keyElem = document.getElementById('head-key');
    const badgeElem = document.getElementById('head-badge');
    
    if (!state.head || !state.canonicalDigest) {
        digestElem.textContent = 'Loading...';
        tsElem.textContent = '—';
        keyElem.textContent = '—';
        badgeElem.textContent = 'Loading';
        badgeElem.className = 'badge';
        return;
    }
    
    digestElem.textContent = state.head.digest;
    tsElem.textContent = state.head.ts;
    keyElem.textContent = state.head.key_id;
    
    // Verify digest match
    const isVerified = state.head.digest === state.canonicalDigest.digest;
    badgeElem.textContent = isVerified ? '✓ VERIFIED' : '✗ MISMATCH';
    badgeElem.className = `badge ${isVerified ? 'verified' : 'mismatch'}`;
}

function renderIssuersTable() {
    const tbody = document.querySelector('#issuers-table tbody');
    const emptyState = document.getElementById('issuers-empty');
    
    // Apply client-side filters
    let filteredIssuers = state.issuers;
    
    const statusFilter = document.getElementById('issuer-status-filter').value;
    if (statusFilter) {
        filteredIssuers = filteredIssuers.filter(issuer => issuer.status === statusFilter);
    }
    
    const searchFilter = document.getElementById('issuer-search').value.toLowerCase();
    if (searchFilter) {
        filteredIssuers = filteredIssuers.filter(issuer => {
            const hostname = new URL(issuer.iss).hostname.toLowerCase();
            const kids = (issuer.keys || []).map(k => k.kid.toLowerCase()).join(' ');
            return hostname.includes(searchFilter) || kids.includes(searchFilter);
        });
    }
    
    if (filteredIssuers.length === 0) {
        tbody.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    
    tbody.innerHTML = filteredIssuers.map(iss => {
        const hostname = new URL(iss.iss).hostname;
        const methods = iss.allowed_methods?.join(', ') || '—';
        const software = iss.allowed_software?.join(', ') || '—';
        const algs = iss.allowed_algs?.join(', ') || '—';
        const keys = (iss.keys || []).map(k => k.kid).join(', ') || '—';
        const updated = iss.updated_at || '—';
        
        // Find target kid (prefer active key, fallback to first key)
        const key = (iss.keys && iss.keys[0]) || {}; // MVP: first key
        const kid = key.kid || iss.kid;
        const isActive = (iss.status || "active") === "active";
        const actionBtn = isActive
            ? `<button class="btn-suspend" data-kid="${kid}">Suspend</button>`
            : `<button class="btn-activate" data-kid="${kid}">Reactivate</button>`;
        
        return `
            <tr>
                <td>${hostname}</td>
                <td><span class="${isActive ? "badge-active":"badge-suspended"}">${isActive ? "active" : "suspended"}</span></td>
                <td>${methods}</td>
                <td>${software}</td>
                <td>${algs}</td>
                <td title="${(iss.keys || []).map(k => `${k.kid}: ${k.status}`).join(', ')}">${keys}</td>
                <td>${updated}</td>
                <td>${kid || ""}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join('');
}

function renderEventsTable() {
    const tbody = document.querySelector('#events-table tbody');
    const emptyState = document.getElementById('events-empty');
    
    if (state.events.length === 0) {
        tbody.innerHTML = '';
        emptyState.style.display = 'block';
        return;
    }
    
    emptyState.style.display = 'none';
    
    tbody.innerHTML = state.events.map(event => {
        const time = formatISO(event.ts);
        const issuerLabel = event.attested_issuer || new URL(event.issuer).hostname;
        const issuerSuffix = event.attested_issuer ? ' <small>(attested)</small>' : '';
        const { class: outcomeClass, icon: outcomeIcon } = badge(event.outcome);
        const reason = event.outcome === 'fail' ? (event.reason || '') : '';
        
        // NEW: Enriched fields with graceful fallbacks
        const software = val(event.software);
        const alg = val(event.alg);
        const checksCount = event.checks_count !== null ? event.checks_count : '—';
        const headDigest = event.head_digest ? truncate(event.head_digest, 8) : '—';
        const verifyId = event.verify_id ? truncate(event.verify_id, 8) : '—';
        
        // Policy display with version if available
        const policy = event.policy_version 
            ? `${event.policy_tag}@${event.policy_version}`
            : event.policy_tag;
        
        // Staleness check
        const isStale = checkStaleness(event.ts, event.head_ts);
        const staleBadge = isStale ? ' <span class="badge-stale">STALE HEAD</span>' : '';
        
        // Row ID for expansion
        const rowId = `event-row-${event.verify_id || event.ts}`;
        const isExpanded = state.expandedRows.has(rowId);
        const chevron = isExpanded ? '▼' : '▶';
        
        return `
            <tr id="${rowId}" data-event='${JSON.stringify(event).replace(/'/g, "&apos;")}'>
                <td title="${event.ts}">${time} UTC${staleBadge}</td>
                <td>${issuerLabel}${issuerSuffix}</td>
                <td>${val(event.method)}</td>
                <td>${software}</td>
                <td>${alg}</td>
                <td>${checksCount}</td>
                <td class="${outcomeClass}">${outcomeIcon} ${event.outcome.toUpperCase()}</td>
                <td>${policy}</td>
                <td>
                    ${headDigest !== '—' ? `<span class="short-hash" title="${event.head_digest}">${headDigest}</span>
                    <button class="copy-btn" data-copy="${event.head_digest || ''}" title="Copy full head digest">📋</button>` : '—'}
                </td>
                <td>
                    ${verifyId !== '—' ? `<span class="short-hash" title="${event.verify_id}">${verifyId}</span>
                    <button class="copy-btn" data-copy="${event.verify_id || ''}" title="Copy full verify ID">📋</button>` : '—'}
                </td>
                <td>
                    <button class="expand-btn" data-row="${rowId}" title="Toggle event details">${chevron}</button>
                </td>
            </tr>
            ${isExpanded ? `<tr class="details-row"><td colspan="11"><pre class="event-details">${JSON.stringify(event, null, 2)}</pre></td></tr>` : ''}
        `;
    }).join('');
}

function updateEventFilters() {
    const issuerSelect = document.getElementById('f-issuer');
    const policySelect = document.getElementById('f-policy');
    
    // Preserve current selections
    const currentIssuer = issuerSelect.value;
    const currentPolicy = policySelect.value;
    
    // Build issuer options
    const issuerLabels = new Set();
    state.events.forEach(event => {
        const label = event.attested_issuer || new URL(event.issuer).hostname;
        issuerLabels.add(label);
    });
    
    issuerSelect.innerHTML = '<option value="">All</option>';
    Array.from(issuerLabels).sort().forEach(label => {
        const option = document.createElement('option');
        option.value = label;
        option.textContent = label;
        if (label === currentIssuer) option.selected = true;
        issuerSelect.appendChild(option);
    });
    
    // Build policy options
    const policies = new Set();
    state.events.forEach(event => {
        policies.add(event.policy_tag);
    });
    
    policySelect.innerHTML = '<option value="">All</option>';
    Array.from(policies).sort().forEach(policy => {
        const option = document.createElement('option');
        option.value = policy;
        option.textContent = policy;
        if (policy === currentPolicy) option.selected = true;
        policySelect.appendChild(option);
    });
}

// =============================================================================
// Admin actions
// =============================================================================

// Event delegation for the action buttons
document.addEventListener('DOMContentLoaded', () => {
    const tbody = document.querySelector('#issuers-table tbody');
    if (tbody) {
        tbody.addEventListener('click', async (e) => {
            const btn = e.target.closest('button');
            if (!btn) return;
            const kid = btn.dataset.kid;
            if (!kid) return;
            
            try {
                btn.disabled = true;
                if (btn.classList.contains('btn-suspend')) {
                    await apiPost(`/admin/suspend/${encodeURIComponent(kid)}`);
                    showToast(`Issuer key ${kid} suspended`, 'success');
                } else if (btn.classList.contains('btn-activate')) {
                    await apiPost(`/admin/activate/${encodeURIComponent(kid)}`);
                    showToast(`Issuer key ${kid} reactivated`, 'success');
                }
                await reloadHeadAndIssuers(); // refresh table + head digest/badge
            } catch (err) {
                showToast(`Action failed: ${err.message}`, 'error');
            } finally {
                btn.disabled = false;
            }
        });
    }
});

async function performAdminAction(kid, action) {
    // Legacy function - kept for compatibility
    const button = document.querySelector(`button[data-kid="${kid}"]`);
    if (!button) return;
    
    // Disable button and show loading state
    button.disabled = true;
    button.setAttribute('aria-busy', 'true');
    const originalText = button.textContent;
    button.textContent = 'Processing...';
    
    try {
        const endpoint = `/admin/${action}/${kid}`;
        const response = await apiPost(endpoint);
        
        if (response.ok) {
            showToast('Updated successfully', 'success');
            
            // Force immediate refresh of head and issuers
            setTimeout(pollHeadAndDigest, 0);
            setTimeout(pollIssuers, 100);
            
        } else {
            throw new Error('Operation failed');
        }
        
    } catch (error) {
        console.error('Admin action error:', error);
        showToast(`Failed to ${action} issuer: ${error.message}`, 'error');
        
        // Re-enable button
        button.disabled = false;
        button.removeAttribute('aria-busy');
        button.textContent = originalText;
    }
}

// =============================================================================
// Event handlers
// =============================================================================

function setupEventHandlers() {
    // Copy digest button
    document.getElementById('copy-digest').addEventListener('click', () => {
        const digestText = document.getElementById('head-digest').textContent;
        if (digestText && digestText !== 'Loading...') {
            copyToClipboard(digestText).then(() => {
                showToast('Digest copied to clipboard', 'success');
            }).catch(() => {
                showToast('Failed to copy digest', 'error');
            });
        }
    });
    
    // Event delegation for copy buttons and expand buttons in events table
    document.addEventListener('click', (e) => {
        // Copy button handler
        if (e.target.classList.contains('copy-btn')) {
            const text = e.target.dataset.copy;
            if (text) {
                copyToClipboard(text).then(() => {
                    showToast('Copied to clipboard', 'success');
                }).catch(() => {
                    showToast('Failed to copy', 'error');
                });
            }
            return;
        }
        
        // Expand button handler
        if (e.target.classList.contains('expand-btn')) {
            const rowId = e.target.dataset.row;
            if (state.expandedRows.has(rowId)) {
                state.expandedRows.delete(rowId);
            } else {
                state.expandedRows.add(rowId);
            }
            renderEventsTable(); // Re-render to show/hide details
            return;
        }
    });
    
    // Issuer filters
    document.getElementById('issuer-status-filter').addEventListener('change', renderIssuersTable);
    document.getElementById('issuer-search').addEventListener('input', renderIssuersTable);
    
    // Event filters
    document.getElementById('f-outcome').addEventListener('change', (e) => {
        state.filters.outcome = e.target.value;
        pollEvents(); // Trigger immediate refresh with new filter
    });
    
    document.getElementById('f-issuer').addEventListener('change', (e) => {
        state.filters.issuerLabel = e.target.value;
        pollEvents(); // Trigger immediate refresh with new filter
    });
    
    document.getElementById('f-policy').addEventListener('change', (e) => {
        state.filters.policy = e.target.value;
        pollEvents(); // Trigger immediate refresh with new filter
    });
}

// =============================================================================
// Initialization
// =============================================================================

function init() {
    console.log('PAVE Transparency Dashboard initializing...');
    
    // Setup event handlers
    setupEventHandlers();
    
    // Check for deep-linking via URL params
    const params = new URLSearchParams(location.search);
    const qid = params.get('verify_id');
    if (qid) {
        state.filters.verify_id = qid;
        console.log(`Deep-linking to verify_id: ${qid}`);
    }
    
    // Start polling with staggered timing to avoid simultaneous bursts
    setTimeout(pollHeadAndDigest, 0);      // Start immediately
    setTimeout(pollIssuers, 250);          // Start after 250ms
    setTimeout(pollEvents, 500);           // Start after 500ms
    
    console.log('Dashboard initialized');
}

// Start when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

// Make admin action function globally available
window.performAdminAction = performAdminAction;