# Request 2 Sprint Notes - Wallet + Real Transparency + Envelope

## 🎯 High-Level Goal
Move receipt out of site code, enable cross-origin reuse, and make the log head publicly verifiable. **Minimal viable pieces only.**

## 📋 Deliverables Breakdown

### 1. 🏦 Wallet Service (NEW) @ http://localhost:8000
**Location**: Create new `wallet/` directory
**Components**:
- `iframe.html` + JS implementation
- **Storage**: IndexedDB (NOT localStorage) for cross-origin capability
- **postMessage API** to allowed origins (:9001, :9002 only)
- **Strict origin allowlist** - no other endpoints

**API Methods**:
- `issue()` → call issuer service, store JWT in IndexedDB
- `verify()` → 
  - Fetch nonce from verifier `/challenge` endpoint
  - Build envelope `{aud, nonce, receipt_jwt}`
  - POST directly to verifier 
  - Return sanitized result (NO raw JWT to site)

### 2. 🔄 Site SDK Swap
**Current**: Sites use localStorage SDK directly
**New**: Thin client that:
- Embeds hidden wallet iframe
- Uses postMessage to communicate with wallet
- **Remove ALL direct JWT handling** from sites
- Sites never see raw JWT (DevTools verification required)

**Files to modify**:
- `sdk/sdk.js`
- `site_a/sdk.js` 
- `site_b/sdk.js`

### 3. ✅ Verifier Additions
**New endpoint**: `GET /challenge`
- Mint single-use nonce (TTL 60s)
- Store nonce to prevent reuse
- Return nonce to wallet

**Modified verification**:
- Accept envelope format: `{aud, nonce, receipt: <JWT>}`
- Enforce nonce freshness & single-use
- Device binding & PPID can be **stubs for now**

**Files to modify**:
- `services/verifier/app.py`

### 4. 🔐 Transparency Log Crypto
**Switch from HMAC to Ed25519**:
- Generate Ed25519 keypair for log signing
- Publish log public key at `/log/.well-known/jwks.json`
- Sign head with: `{ts, digest, key_id, sig}`
- **Verifier must verify head signature** against log public key before using issuers

**Keep JSON storage** - Merkle tree comes later

**Files to modify**:
- `services/guest_list/app.py`
- Add `/log/.well-known/jwks.json` endpoint
- Generate Ed25519 keys in guest list service

### 5. 🌐 Cross-Origin Reuse Demo
**Goal**: Same receipt works on Site A and Site B
**Update**: Site B copy to reflect this capability
**Verification**: Issue on A, verify on both A & B

**Files to modify**:
- `site_b/index.html` - update copy to state cross-origin reuse works

## 🧪 Acceptance Criteria Checklist

- [ ] **Sites never see raw JWT** (confirmed via DevTools)
- [ ] **Cross-origin reuse**: Verify succeeds on both Site A & B after single issue on A  
- [ ] **Nonce replay protection**: Replay with old nonce fails
- [ ] **Head signature validation**: Verifier rejects if head signature invalid
- [ ] **Real-time suspension**: Suspend issuer → immediate failure on both sites

## 🏗️ Implementation Order

### Phase 1: Infrastructure
1. Create wallet service structure (`wallet/` directory)
2. Implement Ed25519 signing in guest list
3. Add `/challenge` endpoint to verifier
4. Add envelope support to verifier

### Phase 2: Wallet Implementation  
1. Build `iframe.html` with IndexedDB storage
2. Implement postMessage API with origin restrictions
3. Implement `issue()` and `verify()` methods

### Phase 3: SDK Migration
1. Replace site SDKs with iframe-based clients
2. Remove all direct JWT handling from sites
3. Update site copy for cross-origin messaging

### Phase 4: Testing & Validation
1. Verify acceptance criteria
2. Test cross-origin functionality
3. Test nonce replay protection
4. Test head signature validation

## ⚠️ Critical Security Points

1. **Origin Allowlist**: Wallet MUST enforce strict origin allowlist
2. **No Raw JWT Exposure**: Sites must never see JWT in any form
3. **Nonce Single-Use**: Prevent replay attacks with nonce validation
4. **Head Signature**: Verifier MUST validate log head before trusting issuer data
5. **IndexedDB Isolation**: Wallet origin isolation provides cross-origin capability

## 🔧 Technical Notes

- **Timebox**: ~1-1.5 days
- **Ed25519 Library**: Use appropriate crypto library for Python (cryptography?)
- **postMessage Security**: Implement proper origin checking
- **IndexedDB**: Use for persistence in wallet iframe
- **Nonce Storage**: In-memory or lightweight persistence for verifier
- **Error Handling**: Maintain existing error format consistency

## 📁 New File Structure Expected

```
PAVE/
├── wallet/              # NEW
│   ├── app.py          # Wallet service 
│   ├── iframe.html     # Wallet iframe implementation
│   └── static/         # Wallet JS/CSS
├── services/
│   ├── guest_list/
│   │   ├── keys/       # NEW - Ed25519 keys
│   │   └── app.py      # Modified for Ed25519
│   └── verifier/
│       └── app.py      # Modified for challenge/envelope
└── sdk/
    └── sdk.js          # Modified for iframe communication
```

## 🎯 Success Metrics

1. **Functional**: Cross-origin reuse working between sites
2. **Security**: No JWT leakage to sites (DevTools clean)
3. **Reliability**: Nonce replay protection working
4. **Trust**: Ed25519 head signature validation working
5. **Demo**: Suspend/activate flow working across origins

---

**⚠️ REMEMBER**: This is planning only. Do NOT start implementation until instructed!