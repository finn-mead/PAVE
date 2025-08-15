# PAVE MVP - Step 1/2/3/4 Implementation

This repository contains the complete PAVE MVP implementation with all services and demo sites.

## Overview

PAVE creates reusable, device-held "18+ passes" that sites can verify without seeing PII. This implementation includes:

- **Issuer Service (port 8001)**: Issues signed JWT receipts and publishes JWKS
- **Guest List Service (port 8002)**: Maintains a public allowlist of issuers with signed integrity
- **Verifier Service (port 8003)**: Verifies receipts against issuer policy and status
- **Browser SDK**: JavaScript helper for age verification workflows
- **Demo Sites A & B (ports 9001/9002)**: Cross-origin demonstration sites

## Requirements

- Python 3.11+
- Dependencies: FastAPI, Uvicorn, jwcrypto, pydantic, httpx, pyyaml

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start (All Services)

```bash
# Start all services at once
chmod +x scripts/run_all.sh
./scripts/run_all.sh
```

Then open:
- **Site A**: http://localhost:9001
- **Site B**: http://localhost:9002

## Manual Service Startup

### Start Individual Services

```bash
# Terminal 1 - Issuer
cd services/issuer && python3 app.py

# Terminal 2 - Guest List  
cd services/guest_list && python3 app.py

# Terminal 3 - Verifier
cd services/verifier && python3 app.py

# Terminal 4 - Site A
cd site_a && python3 -m http.server 9001

# Terminal 5 - Site B
cd site_b && python3 -m http.server 9002
```

## Acceptance Tests

### Issuer Service Tests

1. **JWKS visible**:
```bash
curl http://localhost:8001/.well-known/jwks.json
# Should return one key with kid="fastage-k1"
```

2. **Issue receipt**:
```bash
curl -X POST http://localhost:8001/issue
# Should return JSON with receipt_jwt (three dot-segments)
```

3. **Claim inspection** (decode JWT payload):
```bash
# Take the receipt_jwt from step 2 and decode the payload
python3 -c "
import base64, json
jwt = 'YOUR_JWT_HERE'
payload = jwt.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
decoded = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(decoded, indent=2))
print(f'Duration: {decoded[\"exp\"] - decoded[\"iat\"]} seconds')
"
# Should show all required fields, exp - iat = 86400
```

4. **Key persistence**:
```bash
# Restart the Issuer service and check JWKS again
# The 'n' (modulus) value should be unchanged
```

### Guest List Service Tests

1. **Head visible**:
```bash
curl http://localhost:8002/log/head
# Should return ts, digest (64 hex chars), sig (64 hex chars)
```

2. **Issuer visible**:
```bash
curl http://localhost:8002/log/issuers/fastage-k1
# Should return JSON issuer with status:"active"
```

3. **Viewer page**:
```bash
# Open http://localhost:8002/viewer?kid=fastage-k1 in browser
# Should show issuer data and head
```

4. **Suspend issuer**:
```bash
curl -X POST http://localhost:8002/admin/suspend/fastage-k1
# Should return {ok:true,...} and change head digest/sig

# Verify status changed:
curl http://localhost:8002/log/issuers/fastage-k1
# Should show status:"suspended"

# Verify head changed:
curl http://localhost:8002/log/head
# Should show different digest and sig values
```

5. **Restart persistence**:
```bash
# Restart Guest List service
# GET /log/head should maintain the same values (until next change)
# Suspended status should persist
```

### Verifier Service Tests

1. **Happy path verification**:
```bash
# Issue receipt
RECEIPT=$(curl -s -X POST http://localhost:8001/issue | python3 -c "import json, sys; print(json.load(sys.stdin)['receipt_jwt'])")

# Verify receipt
curl -X POST http://localhost:8003/verify \
  -H "Content-Type: application/json" \
  -d "{\"receipt_jwt\": \"$RECEIPT\"}"
# Should return {"ok": true, "assurance": {...}, "head": {...}}
```

2. **Suspended issuer test**:
```bash
# Suspend issuer
curl -X POST http://localhost:8002/admin/suspend/fastage-k1

# Try verification
curl -X POST http://localhost:8003/verify \
  -H "Content-Type: application/json" \
  -d "{\"receipt_jwt\": \"$RECEIPT\"}"
# Should return {"ok": false, "reason": "issuer_suspended"}
```

## End-to-End Demo Flow

### Browser Demo (Recommended)

1. **Start all services**: `./scripts/run_all.sh`
2. **Open Site A**: http://localhost:9001
3. **Get pass**: Click "Get 18+ Pass" → shows JWT preview
4. **Verify pass**: Click "Verify Pass" → shows success + assurance
5. **Suspend issuer**: Click "Suspend Issuer" → changes guest list head
6. **Verify again**: Click "Verify Pass" → shows failure
7. **Cross-origin test**: Open http://localhost:9002 
8. **Verify on Site B**: Click "Verify Pass" → same pass works/fails across origins

### Command Line Demo

```bash
# Complete E2E flow
echo "=== Issue receipt ==="
RECEIPT=$(curl -s -X POST http://localhost:8001/issue | python3 -c "import json, sys; print(json.load(sys.stdin)['receipt_jwt'])")

echo "=== Verify (should succeed) ==="
curl -s -X POST http://localhost:8003/verify -H "Content-Type: application/json" \
  -d "{\"receipt_jwt\": \"$RECEIPT\"}" | python3 -m json.tool

echo "=== Suspend issuer ==="
curl -s -X POST http://localhost:8002/admin/suspend/fastage-k1

echo "=== Verify again (should fail) ==="
curl -s -X POST http://localhost:8003/verify -H "Content-Type: application/json" \
  -d "{\"receipt_jwt\": \"$RECEIPT\"}" | python3 -m json.tool
```

## Sample Success Logs

### Issuer Service Logs
```json
{"event": "issuer.key.generated", "kid": "fastage-k1", "alg": "RSA", "size_bits": 2048}
{"event": "issuer.start", "kid": "fastage-k1", "port": 8001, "keys_dir": "/path/to/keys", "key_existed": false}
{"event": "issuer.jwks.served", "kid": "fastage-k1"}
{"event": "issuer.issue.success", "kid": "fastage-k1", "sub": "user-1234", "iat": 1755240607, "exp": 1755327007, "method": "ID+face", "policy_tag": "uk_adult_high"}
```

### Guest List Service Logs
```json
{"event": "guestlist.start", "data_path": "/path/to/guest_list.json", "issuers_count": 1}
{"event": "guestlist.head.computed", "ts": "2025-08-15T06:51:56.413885Z", "digest": "2f682a0e41bc0156f03b23cce21d4df5aa5897112596ccaf530432e207eb18ce"}
{"event": "guestlist.issuer.fetched", "kid": "fastage-k1"}
{"event": "guestlist.issuer.suspended", "kid": "fastage-k1", "ts": "2025-08-15T06:52:27.276248Z", "digest": "f94901240b89eca5a509dd105a1fade65d52f41c97e9330ab86f4dd77a9cd984"}
```

### Verifier Service Logs
```json
{"event": "verifier.start", "port": 8003}
{"event": "verifier.verify.begin", "kid": "fastage-k1", "iss": "http://localhost:8001"}
{"event": "verifier.verify.success", "kid": "fastage-k1", "iss": "http://localhost:8001", "iat": 1755241475, "exp": 1755327875, "method": "ID+face"}
{"event": "verifier.verify.fail", "reason": "issuer_suspended", "kid": "fastage-k1", "status": "suspended"}
```

## Architecture

### File Structure
```
PAVE/
├── services/
│   ├── issuer/
│   │   ├── app.py              # Issuer FastAPI app
│   │   ├── keys/               # RSA keypair (auto-generated)
│   │   │   ├── issuer_private.jwk
│   │   │   └── issuer_public.jwk
│   │   └── __init__.py
│   ├── guest_list/
│   │   ├── app.py              # Guest List FastAPI app
│   │   ├── data/
│   │   │   └── guest_list.json # Issuer allowlist + signed head
│   │   └── __init__.py
│   └── verifier/
│       ├── app.py              # Verifier FastAPI app
│       └── __init__.py
├── sdk/
│   └── sdk.js                  # Browser SDK for age verification
├── site_a/
│   ├── index.html             # Demo site A (port 9001)
│   └── sdk.js                 # SDK copy
├── site_b/
│   ├── index.html             # Demo site B (port 9002)
│   └── sdk.js                 # SDK copy
├── scripts/
│   └── run_all.sh             # Start all services
├── requirements.txt
└── README.md
```

### Data Flow

1. **Issue**: Site → Issuer → JWT receipt → localStorage
2. **Verify**: Site → SDK → Verifier → Guest List + Issuer JWKS → validation
3. **Policy**: Verifier checks issuer status, method allowance, signature, freshness
4. **Transparency**: Guest List head changes when issuer status updates

### Key Features

- **JWT Receipts**: Tamper-evident signed claims (RS256)
- **JWKS Discovery**: Self-serve public key distribution  
- **Signed Head**: HMAC-signed digest for transparency log
- **Cross-Origin**: Same receipt works across different site origins
- **Real-time Policy**: Issuer suspension immediately fails all verifications
- **Browser SDK**: Simple JavaScript API for sites
- **Persistence**: Keys and state survive service restarts
- **CORS Security**: Restricted to demo origins only

## Environment Variables

- `LOG_SIGNING_SECRET`: HMAC secret for guest list head (defaults to "dev-secret")

## Python Version Used

Built and tested with Python 3.12.4