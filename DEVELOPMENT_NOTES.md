# PAVE Development Notes - Complete Vision & Roadmap

## 🚨 CRITICAL MVP LIMITATIONS (NOT ADDRESSING YET)
1. **"Verify once, reuse everywhere" vs 24-hour expiry**: Users re-enroll daily without refresh/rotation
2. **No holder-binding enforcement**: Stolen receipts are replayable within TTL despite nonces
   - For external demos: tokens/keys must be strictly ephemeral, state limitations clearly

## 🎯 LONG-TERM VISION
**"Reusable, anonymous 18+ stamp"** - Device-held proof that sites can verify (yes/no + assurance) without seeing PII (name/DOB/photo), backed by public tamper-evident guest list.

## 👥 ROLES & ARCHITECTURE

### Issuer (Checker)
- Banks, government-accredited AV vendors, mobile wallets
- Performs actual age checks (ID scan + selfie)
- Issues signed receipt attesting `over18: true`

### Wallet (User Device)
- Web app at `https://wallet.pave.com` 
- Stores "over18=true" pass in browser IndexedDB
- Data lives ONLY on user device (not our servers)
- Lost if user clears data/different browser → must re-enroll

### Verifier (Website/App)
- Sites call SDK: `await pave.verify({policy: 'uk_adult_high'})`
- PAVE verifies proof, site gets only result + verify_id (never raw receipt)
- PAVE server: short-lived nonces, device-binding table, issuer key cache

### Log Operator(s)
- Public transparency log: trusted issuers, methods, software, keys, statuses
- MVP: tamper-evident snapshot log (PAVE-signed heads)
- Future: Merkle tree (truly append-only, third-party verifiable)
- Mirrors possible (NGOs, universities)

## 🔐 CRYPTOGRAPHY EXPLAINED

### A) Digital Signatures = Unforgeable Stamps
- **Format**: JWT/ES256 (future: SD-JWT/Verifiable Credentials)
- **Security Rules**:
  - Verifiers MUST pin keys from allowlist (never follow jku/x5u URLs)
  - Pick key by `header.kid` from allowlisted set only
  - Enforce `alg ∈ allowed_algs`, reject `alg: "none"`
  - Timing: JWT iat/exp as UNIX seconds, log head ts as RFC3339 UTC "Z"

### B) Selective Disclosure = Show Only "Over 18"
- Real deployment: Verifiable Credential format for hiding details
- MVP: Minimal fields, wallet sends receipt only to PAVE (site never sees raw)
- Advanced: ZKP proofs for "age ≥ 18" without revealing birthdate

### C) Holder Binding = "Stamp belongs to this device"
- Device generates WebAuthn key
- Wallet signs challenge (nonce) with device key on each presentation
- Prevents stolen receipt replay on different device
- **MVP**: Simulated (signature collected but not enforced)

### D) Pairwise Pseudonymous ID (PPID) = Different ID per Site
```
ppid = HKDF-SHA256(
  info="PAVE-PPID", 
  IKM=wallet_secret_32B,
  salt=sha256(issuer_subject || rpId || "v1")
)[0..31]
```
- `rpId` = site domain (eTLD+1)
- `issuer_subject` = receipt.sub
- `wallet_secret` = random 32B key (device-only)
- Result: 256-bit PPID unique to (issuer, site) - no cross-site correlation

### E) Transparency Log (Allowlist)
- **MVP**: JSON + Ed25519 signed heads (tamper-evident snapshots)
- **Future**: Merkle STH with inclusion/consistency proofs
- **Terms**:
  - `digest` = SHA256 of canonical JSON allowlist
  - `PAVE-signed head` = `{ts, digest, key_id, sig}` where `sig = Ed25519_sign(PAVE_priv, {ts,digest,key_id})`

### F) Evidence Receipt = Signed Checklist
```json
{
  "iss": "https://issuer.example", 
  "sub": "issuer-opaque-subject",
  "session_id": "fa_9f2c...d1",
  "over18": true,
  "method": "ID+face",
  "checks": ["id_scan", "selfie_match", "liveness"],
  "software": "FaceMatch 2.3.1",
  "iat": 1755211380,
  "exp": 1755297780,
  "policy_tag": "uk_adult_high"
}
```

## 🔄 WALLET INTEGRATION MODES

### Embedded iframe (Default)
- Hidden iframe to `https://wallet.pave.com/iframe.html`
- Communication via postMessage (wallet.issue(), wallet.get(), wallet.signProof())
- Origin allowlisting both directions
- Wallet posts presentation directly to PAVE (site never sees receipt)

### Redirect/Bridge (Optional)
- Redirect to `https://wallet.pave.com/verify-ui?...`
- User sees wallet page, consents, redirected back with `{verify_id, status}`
- Optional server-to-server confirmation via `GET /verify/{verify_id}`

## 📋 POLICY ENGINE

### Policy Format (YAML/JSON)
```yaml
id: uk_adult_high
jurisdiction: UK
category: adult_content
requires:
  assurance: high
  min_age: 18  # MVP: MUST be 18, receipts carry over18=true
  methods_any_of: ["ID+face", "ID+in-person"]
  max_receipt_age_hours: 24
  ppid: required
  holder_binding: required  # (skip in MVP)
```

### Defaults
- `max_clock_skew_seconds = 120`
- Default receipt TTL = 24h (policy may tighten)

## 🛡️ ABUSE & MITIGATIONS

### Corner-cutting (fake method)
- Issuer claims "ID+face" but does cheap check
- Audit/spot-check catches inconsistency → suspend issuer's method
- Instant ecosystem-wide rejection

### Mis-issuance (minor gets 18+)
- Short TTL (24h) limits exposure
- Sites can add risk signals, force re-checks
- Extreme: suspend entire issuer

### Replay/Theft (stolen receipt)
- **Full solution**: Holder-binding (device key required)
- **MVP**: Short expiration + one-time nonce + session binding

### Cross-site tracking
- Different PPID per site prevents collusion
- SDK suppresses extra claims by default

## 🔄 END-TO-END FLOW

### 1. Enroll
- User chooses issuer, verifies age once
- Issuer issues signed receipt `{over18:true,...}`
- Wallet stores locally, shows "18+ pass saved (ID+face)"

### 2. Visit Site A
- Site calls `pave.verify({policy: 'uk_adult_high'})`
- Wallet consent: "Share your 18+ proof with Site A?"
- Wallet builds presentation:
  - Calculates PPID
  - Fetches PAVE-minted nonce (site nonces rejected)
  - Signs `{aud=SiteA, nonce, ppid, receipt_hash}` with WebAuthn

### 3. Verification Flow
```
Wallet → PAVE (direct POST/HTTPS)
POST /verify
{
  aud: "https://siteA.com",
  nonce: "<nonce>",
  ppid: "<32B hex>",
  receipt: "<compact JWT>",              // ONLY to PAVE
  device_sig: { sig: "...", alg: "ES256", kid: "device-kid" },
  receipt_hash: "<hex>"
}

PAVE validates:
- Issuer JWT signature ✓
- Issuer/method/software in allowlist ✓  
- exp/iat timing ✓
- Policy compliance ✓
- (Production) Device signature ✓
- (MVP) Device signature collected but not enforced

Returns: {pass: true|false, assurance: "...", method: "...", verify_id: "<id>", 
         audit_handle: {...}, head: {ts: "...", digest: "..."}, evidencePage: "<url>"}
```

### 4. Repeat for Site B
- Same device, same proof → immediate acceptance
- No re-enrollment needed

## 🏗️ MVP SCOPE (Current Implementation)

### Mock Issuer
- ✅ FastAge service with ES256 keypair (kid: "fastage-k1")
- ✅ Issues JWT receipts (v0 schema)
- ✅ Public key preloaded in log

### Wallet & Binding  
- ✅ Browser-based wallet app
- ✅ WebAuthn device key generation (simplified for demo)
- ✅ JWT storage in LocalStorage (demo: should be IndexedDB)
- ✅ PPID calculation, nonce signing
- ✅ Direct POST to PAVE (site never sees receipt)
- ⚠️ **MVP**: Server ignores holder signature (but wallet produces it)

### Verifier API & SDK
- ✅ `POST /verify` endpoint
- ✅ JWT verification using issuer public key
- ✅ Policy enforcement (except holder-binding skip)
- ✅ Returns `{pass, audit_handle, head, head_age_s}`

### Public Log (MVP - Head-based)
- ✅ `GET /log/head` → `{ts, digest, sig, key_id}`
- ✅ `GET /log/issuers/fastage` → issuer entry
- ✅ Ed25519 signed heads
- ✅ JWKS at `/log/.well-known/jwks.json`

### Demo Sites
- ✅ Site A: Adult content placeholder
- ✅ Site B: Forum/game site  
- ✅ Both call `pave.verify({policy: 'uk_adult_high'})`
- ✅ Admin suspension demo (immediate ecosystem effect)

## 📈 ROADMAP PRIORITIES

### Phase 1 (Current MVP ✅)
- [x] Basic issuer, verifier, guest list
- [x] JWT receipts with minimal schema
- [x] Demo sites with suspension flow
- [x] Signed head transparency (HMAC)

### Phase 2 (Holder Binding)
- [ ] Enforce WebAuthn device signatures
- [ ] PPID implementation and testing
- [ ] Nonce validation improvements
- [ ] Production-ready wallet integration

### Phase 3 (Advanced Crypto)
- [ ] Switch to Ed25519 signing for transparency log  
- [ ] Merkle tree implementation (true append-only)
- [ ] Inclusion/consistency proofs
- [ ] Witness/mirror support

### Phase 4 (Standards & Interop)
- [ ] SD-JWT/Verifiable Credentials support
- [ ] EU age-verification profile compliance
- [ ] Apple/Google wallet integration
- [ ] Multi-issuer federation

## 🚀 WHAT'S OPEN vs PRODUCT

### Open (Specs & Reference Code)
- Receipt schema (10-field JSON + JSON Schema)
- Presentation format envelope
- PPID formula (HKDF documented)
- Policy format (YAML/JSON schema)
- Transparency log API (MVP + future Merkle)
- Reference verifier library
- Minimal log server implementation

### Our Product (Hosted Services)
- Hosted Verify API + SDK
- Policy engine management
- Primary public log (HA + monitoring)
- Issuer marketplace (onboarding, billing, routing)
- Audit program (mystery shopping, suspensions)
- Dashboards (sites: pass rates; issuers: quality metrics)
- Commercial infrastructure (billing, support, legal)

## 🔧 CURRENT LIMITATIONS TO ADDRESS

1. **localStorage vs IndexedDB**: Upgrade storage for production
2. **Cross-origin sharing**: Currently broken by design (browser security)
3. **Holder binding**: Signatures collected but not enforced
4. **PPID**: Not implemented in current demo
5. **Nonce security**: Need PAVE-minted nonces (reject site-generated)
6. **Receipt TTL**: Daily re-enrollment without refresh flow
7. **Ed25519**: Current implementation uses HMAC, need proper Ed25519
8. **Real issuer integration**: Need adapter pattern for existing KYC APIs

## 📊 DEMO STORYBOARD (Enhanced)

1. **Enroll**: User → FastAge → "18+ pass saved (ID+face)"
2. **Site A**: User → SDK consent → "✅ Over 18 (high assurance: ID+face)"  
3. **Site B**: Same device → auto-approval → immediate "✅ Over 18"
4. **Evidence**: Click "View Evidence" → log entry + PAVE head signature
5. **Suspension**: Admin → "Suspend FastAge" → both sites immediately ❌ blocked
6. **Ecosystem Effect**: Demonstrates instant trust revocation across all verifiers

## 🤝 ADOPTION STRATEGY

### Client Mode (Current)
- Wrap existing ID-check services (bank/AV APIs)
- Generate receipts from their results
- No permission needed from vendors

### Partner Mode (Future)  
- Native receipt issuance from vendors
- Apple "Verify with Wallet" integration
- Google wallet ZKP-based age proof compatibility
- Higher trust, direct cryptographic provenance

---

*These notes capture the complete PAVE vision, current MVP state, and roadmap priorities for future development phases.*