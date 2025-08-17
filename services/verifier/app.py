import json
import logging
import time
import base64
import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from jwcrypto import jwk, jws
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Constants / config
GUEST_LIST_BASE = os.getenv("PAVE_GUEST_LIST_BASE", "http://localhost:8002")
TIMEOUT = 5.0

# Events log config
EVENTS_HMAC_SECRET = os.getenv("EVENTS_HMAC_SECRET", "dev-events-secret")
EVENTS_INGEST_TOKEN = os.getenv("EVENTS_INGEST_TOKEN")

ALLOWED_WALLET_ORIGIN = os.getenv("PAVE_WALLET_ORIGIN", "http://localhost:8000")
ALLOWED_AUDIENCES = {
    a.strip() for a in os.getenv(
        "PAVE_ALLOWED_AUDIENCES",
        "http://localhost:9001,http://localhost:9002"
    ).split(",") if a.strip()
}

# Global HTTP client
http_client: Optional[httpx.AsyncClient] = None

# Nonce store for challenge/response
NONCES = {}  # nonce -> {"exp": int, "used": bool}

def _now() -> int:
    return int(time.time())

def _gc_nonces():
    now = _now()
    for k in list(NONCES.keys()):
        if NONCES[k]["exp"] <= now:
            del NONCES[k]

class VerifyRequest(BaseModel):
    receipt_jwt: str
    policy_id: Optional[str] = "uk_adult_high"

class VerifyResponse(BaseModel):
    ok: bool
    reason: Optional[str] = None
    assurance: Optional[Dict[str, Any]] = None
    head: Optional[Dict[str, str]] = None

class ErrorResponse(BaseModel):
    error: str
    detail: str

class Envelope(BaseModel):
    aud: str
    nonce: str
    receipt: str
    # ppid: Optional[str] = None
    # device_sig: Optional[Dict[str, Any]] = None
    # receipt_hash: Optional[str] = None

class VerifyEnvelopeRequest(BaseModel):
    envelope: Envelope
    policy_id: Optional[str] = "uk_adult_high"

async def fetch_issuer_by_iss(iss: str) -> Dict[str, Any]:
    """Fetch issuer entry by iss from Guest List"""
    url = f"{GUEST_LIST_BASE}/log/issuers"
    try:
        response = await http_client.get(url)
        response.raise_for_status()
        issuers = response.json()
        for issuer in issuers:
            if issuer.get("iss") == iss:
                return issuer
        return None
    except httpx.HTTPError as e:
        logger.error(json.dumps({
            "event": "verifier.http.error",
            "op": "fetch_issuer_by_iss", 
            "url": url,
            "status": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "error": str(e)
        }))
        raise HTTPException(status_code=500, detail={
            "error": "internal_error", 
            "detail": f"Failed to fetch issuer entry: {str(e)}"
        })

# fetch_digest function removed - we compute digest locally from /log/issuers

async def fetch_head() -> Dict[str, str]:
    """Fetch Guest List head for transparency"""
    url = f"{GUEST_LIST_BASE}/log/head"
    try:
        response = await http_client.get(url)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(json.dumps({
            "event": "verifier.http.error",
            "op": "fetch_head",
            "url": url, 
            "status": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "error": str(e)
        }))
        raise HTTPException(status_code=500, detail={
            "error": "internal_error",
            "detail": f"Failed to fetch head: {str(e)}"
        })

async def fetch_jwks(jwks_url: str) -> Dict[str, Any]:
    """Fetch JWKS from issuer"""
    try:
        response = await http_client.get(jwks_url)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(json.dumps({
            "event": "verifier.http.error",
            "op": "fetch_jwks",
            "url": jwks_url,
            "status": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "error": str(e)
        }))
        raise HTTPException(status_code=500, detail={
            "error": "internal_error",
            "detail": f"Failed to fetch JWKS: {str(e)}"
        })

def parse_jwt_header_payload(token: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Parse JWT header and payload without verifying signature"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")
        
        # Decode header
        header_b64 = parts[0]
        header_b64 += '=' * (-len(header_b64) % 4)  # Add padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Decode payload  
        payload_b64 = parts[1]
        payload_b64 += '=' * (-len(payload_b64) % 4)  # Add padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        return header, payload
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to parse JWT: {e}")

async def fetch_log_jwks():
    url = f"{GUEST_LIST_BASE}/log/.well-known/jwks.json"
    r = await http_client.get(url)
    r.raise_for_status()
    return r.json()

def b64url_to_bytes(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

async def verify_log_head_signature(head: Dict[str,str]) -> bool:
    jwks = await fetch_log_jwks()
    keys = jwks.get("keys", [])
    match = None
    for k in keys:
        if k.get("kid") == head.get("key_id"):
            match = k; break
    if not match: return False
    x = b64url_to_bytes(match.get("x",""))
    pub = Ed25519PublicKey.from_public_bytes(x)
    canonical = json.dumps({
        "ts": head["ts"],
        "digest": head["digest"],
        "key_id": head["key_id"]
    }, separators=(",",":"), sort_keys=True).encode("utf-8")
    try:
        pub.verify(b64url_to_bytes(head["sig"]), canonical)
        return True
    except InvalidSignature:
        return False

def compute_aud_hash(aud: str) -> str:
    """Compute aud_hash using HMAC-SHA256 with canonical aud.
    
    Canonicalization rule: scheme://host[:port] lowercased, preserving explicit ports.
    - https://example.com → https://example.com
    - https://EXAMPLE.COM:443 → https://example.com:443  
    - http://localhost:9001 → http://localhost:9001
    
    Default ports (80/443) are NOT stripped - we preserve whatever was in the original aud.
    """
    parsed = urlparse(aud)
    canonical_aud = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return hmac.new(
        EVENTS_HMAC_SECRET.encode('utf-8'), 
        canonical_aud.encode('utf-8'), 
        hashlib.sha256
    ).hexdigest()

async def emit_event(result: VerifyResponse, envelope: Optional[Any], payload: Optional[Dict[str, Any]]):
    """Emit verification event to events log (fail-open with single retry)"""
    if not envelope:
        return  # Can't emit without envelope
    
    # Extract event data
    aud_hash = compute_aud_hash(envelope.aud)
    issuer = payload.get('iss') if payload else 'unknown'
    attested_issuer = None  # Could extract from issuer entry if needed
    method = payload.get('method') if payload else 'unknown'
    policy_tag = payload.get('policy_tag') if payload else 'unknown'
    outcome = 'ok' if result.ok else 'fail'
    reason = result.reason if not result.ok else None
    issuer_key_kid = payload.get('kid') if payload else None
    
    # Build event
    event_data = {
        "schema": "events.v1",
        "ts": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "aud_hash": aud_hash,
        "issuer": issuer,
        "attested_issuer": attested_issuer,
        "method": method,
        "policy_tag": policy_tag,
        "outcome": outcome,
        "reason": reason,
        "verify_id": None,  # Could add unique verify ID if needed
        "issuer_key_kid": issuer_key_kid
    }
    
    # Remove None values
    event_data = {k: v for k, v in event_data.items() if v is not None}
    
    # Headers for request
    headers = {"Content-Type": "application/json"}
    if EVENTS_INGEST_TOKEN:
        headers["X-Events-Auth"] = EVENTS_INGEST_TOKEN
    
    # Attempt with single retry (fail-open)
    for attempt in range(2):  # 0 and 1
        try:
            response = await http_client.post(
                f"{GUEST_LIST_BASE}/log/events",
                json=event_data,
                headers=headers,
                timeout=0.1 if attempt == 1 else 2.0  # 100ms timeout on retry
            )
            
            if response.status_code in (200, 201):
                return  # Success!
            else:
                logger.warning(f"Events log returned {response.status_code} on attempt {attempt + 1}")
                
        except Exception as e:
            logger.warning(f"Failed to emit event (attempt {attempt + 1}): {e}")
            
        # If this was the retry, give up
        if attempt == 1:
            break

async def verify_receipt(receipt_jwt: str, policy_id: str = "uk_adult_high") -> VerifyResponse:
    """Main verification logic"""
    
    # Parse JWT header and payload for routing info
    try:
        header, payload = parse_jwt_header_payload(receipt_jwt)
        kid = header.get('kid')
        iss = payload.get('iss')
        alg = header.get('alg')
        typ = header.get('typ')
        crit = header.get('crit')
    except ValueError as e:
        return VerifyResponse(
            ok=False, 
            reason="invalid_jwt",
            head=await fetch_head()
        )
    
    # JOSE Header Security Checks
    # typ is optional, but if present must be "JWT"
    if typ is not None and typ != "JWT":
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "typ_not_jwt",
            "typ": typ
        }))
        return VerifyResponse(
            ok=False,
            reason="typ_not_jwt",
            head=await fetch_head()
        )
    
    # Reject b64url=false (RFC 7515 section 4.1.5)
    if header.get('b64') is False:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "b64_false_not_allowed",
            "b64": header.get('b64')
        }))
        return VerifyResponse(
            ok=False,
            reason="b64_false_not_allowed",
            head=await fetch_head()
        )
    
    # Enforce payload/header kid equality
    payload_kid = payload.get('kid')
    if payload_kid is not None and payload_kid != kid:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "kid_mismatch",
            "header_kid": kid,
            "payload_kid": payload_kid
        }))
        return VerifyResponse(
            ok=False,
            reason="kid_mismatch",
            head=await fetch_head()
        )
    
    if crit is not None:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "crit_not_allowed",
            "crit": crit
        }))
        return VerifyResponse(
            ok=False,
            reason="crit_not_allowed",
            head=await fetch_head()
        )
    
    logger.info(json.dumps({
        "event": "verifier.verify.begin",
        "kid": kid,
        "iss": iss,
        "policy_id": policy_id
    }))
    
    # 1. Get issuer entry from Guest List (by iss)
    issuer_entry = await fetch_issuer_by_iss(iss)
    if not issuer_entry:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "unknown_issuer",
            "iss": iss
        }))
        return VerifyResponse(
            ok=False,
            reason="unknown_issuer", 
            head=await fetch_head()
        )
    
    # 2. Check if issuer is active
    if issuer_entry.get('status') != 'active':
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "issuer_suspended",
            "kid": kid,
            "status": issuer_entry.get('status')
        }))
        return VerifyResponse(
            ok=False,
            reason="issuer_suspended",
            head=await fetch_head()
        )
    
    # 3. Validate algorithm is allowed
    allowed_algs = issuer_entry.get('allowed_algs', [])
    if alg not in allowed_algs:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "alg_not_allowed",
            "kid": kid,
            "alg": alg,
            "allowed_algs": allowed_algs
        }))
        return VerifyResponse(
            ok=False,
            reason="alg_not_allowed",
            head=await fetch_head()
        )
    
    # 4. Find matching key in issuer entry and fetch JWKS
    key_entry = None
    for k in issuer_entry.get('keys', []):
        if k.get('kid') == kid:
            key_entry = k
            break
    
    if not key_entry:
        logger.info(json.dumps({
            "event": "verifier.verify.fail", 
            "reason": "kid_not_in_allowlist",
            "kid": kid
        }))
        return VerifyResponse(
            ok=False,
            reason="kid_not_in_allowlist",
            head=await fetch_head()
        )
    
    if key_entry.get('status') != 'active':
        logger.info(json.dumps({
            "event": "verifier.verify.fail", 
            "reason": "key_not_active",
            "kid": kid,
            "key_status": key_entry.get('status')
        }))
        return VerifyResponse(
            ok=False,
            reason="key_not_active",
            head=await fetch_head()
        )
    
    jwks = await fetch_jwks(issuer_entry['jwks_url'])
    matching_key = None
    for key_data in jwks.get('keys', []):
        if key_data.get('kid') == kid:
            matching_key = key_data
            break
    
    if not matching_key:
        logger.info(json.dumps({
            "event": "verifier.verify.fail", 
            "reason": "jwks_kid_not_found",
            "kid": kid
        }))
        return VerifyResponse(
            ok=False,
            reason="jwks_kid_not_found",
            head=await fetch_head()
        )
    
    # 5. Verify signature using jwcrypto
    try:
        public_key = jwk.JWK.from_json(json.dumps(matching_key))
        
        j = jws.JWS()
        j.deserialize(receipt_jwt)
        
        # Algorithm validation already done above
        
        j.verify(public_key)
        verified_payload = json.loads(j.payload)
        
    except Exception as e:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "signature_invalid",
            "kid": kid,
            "error": str(e)
        }))
        return VerifyResponse(
            ok=False,
            reason="signature_invalid", 
            head=await fetch_head()
        )
    
    # 6. Validate claims
    now = int(time.time())
    
    # Check over18
    if not verified_payload.get('over18'):
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "not_over18",
            "kid": kid
        }))
        return VerifyResponse(
            ok=False,
            reason="not_over18",
            head=await fetch_head()
        )
    
    # Check time bounds with ±120s clock skew tolerance
    iat = verified_payload.get('iat')
    exp = verified_payload.get('exp')
    clock_skew = 120  # ±120 seconds
    
    if not isinstance(iat, int) or not isinstance(exp, int):
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "invalid_time_claims",
            "kid": kid,
            "iat": iat,
            "exp": exp
        }))
        return VerifyResponse(
            ok=False,
            reason="invalid_time_claims",
            head=await fetch_head()
        )
    
    # Cap TTL ≤24h (86400 seconds)
    ttl = exp - iat
    if ttl > 86400:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "ttl_too_long",
            "kid": kid,
            "ttl": ttl,
            "max_ttl": 86400
        }))
        return VerifyResponse(
            ok=False,
            reason="ttl_too_long",
            head=await fetch_head()
        )
    
    # Check iat with clock skew
    if iat > now + clock_skew:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "token_issued_in_future",
            "kid": kid,
            "iat": iat,
            "now": now,
            "skew": clock_skew
        }))
        return VerifyResponse(
            ok=False,
            reason="token_issued_in_future",
            head=await fetch_head()
        )
    
    # Check exp with clock skew
    if now >= exp + clock_skew:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "token_expired", 
            "kid": kid,
            "exp": exp,
            "now": now,
            "skew": clock_skew
        }))
        return VerifyResponse(
            ok=False,
            reason="token_expired",
            head=await fetch_head()
        )
    
    # Check method allowed
    method = verified_payload.get('method')
    if method not in issuer_entry.get('allowed_methods', []):
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "method_not_allowed",
            "kid": kid,
            "method": method,
            "allowed": issuer_entry.get('allowed_methods', [])
        }))
        return VerifyResponse(
            ok=False,
            reason="method_not_allowed",
            head=await fetch_head()
        )
    
    # Check software allowed
    software = verified_payload.get('software')
    allowed_software = issuer_entry.get('allowed_software', [])
    if software not in allowed_software:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "software_not_allowed",
            "kid": kid,
            "software": software,
            "allowed_software": allowed_software
        }))
        return VerifyResponse(
            ok=False,
            reason="software_not_allowed",
            head=await fetch_head()
        )
    
    # 7. Verify digest consistency by recomputing from /log/issuers
    head = await fetch_head()
    
    # Verify head signature before checking digest
    if not await verify_log_head_signature(head):
        logger.error(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "head_sig_invalid",
            "head_digest": head.get("digest"),
            "head_key_id": head.get("key_id")
        }))
        return VerifyResponse(
            ok=False,
            reason="head_sig_invalid",
            head=head
        )
    
    # Fetch all issuers and recompute digest
    all_issuers_response = await http_client.get(f"{GUEST_LIST_BASE}/log/issuers")
    all_issuers_response.raise_for_status()
    all_issuers = all_issuers_response.json()
    
    # Recompute canonical digest (same as guest list compute_head)
    canonical = json.dumps(all_issuers, separators=(",", ":"), sort_keys=True)
    canonical_bytes = canonical.encode('utf-8')
    computed_digest = hashlib.sha256(canonical_bytes).hexdigest()
    
    if head["digest"] != computed_digest:
        logger.error(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "digest_mismatch",
            "head_digest": head["digest"],
            "computed_digest": computed_digest
        }))
        return VerifyResponse(
            ok=False,
            reason="digest_mismatch",
            head=head
        )
    
    # 8. Success! Build assurance response
    assurance = {
        "issuer_kid": verified_payload.get('kid'),
        "iss": verified_payload.get('iss'),
        "method": verified_payload.get('method'),
        "checks": verified_payload.get('checks', []),
        "policy_tag": verified_payload.get('policy_tag'),
        "software": verified_payload.get('software'),
        "iat": verified_payload.get('iat'),
        "exp": verified_payload.get('exp')
    }
    
    logger.info(json.dumps({
        "event": "verifier.verify.success",
        "kid": kid,
        "iss": iss,
        "iat": iat,
        "exp": exp,
        "method": method
    }))
    
    return VerifyResponse(
        ok=True,
        assurance=assurance,
        head={"ts": head["ts"], "digest": head["digest"]}
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global http_client
    http_client = httpx.AsyncClient(timeout=TIMEOUT)
    
    logger.info(json.dumps({
        "event": "verifier.start",
        "port": 8003
    }))
    
    yield
    
    # Shutdown
    await http_client.aclose()

app = FastAPI(title="PAVE Verifier Service", lifespan=lifespan)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_AUDIENCES | {ALLOWED_WALLET_ORIGIN}),
    allow_methods=["*"],
    allow_headers=["*"], 
    allow_credentials=False
)

@app.get("/challenge")
async def challenge_endpoint(request: Request):
    """Generate a nonce for envelope verification"""
    _gc_nonces()
    
    origin = request.headers.get("origin")
    if origin != ALLOWED_WALLET_ORIGIN:
        logger.info(json.dumps({
            "event": "verifier.challenge.blocked",
            "reason": "origin_not_allowed",
            "origin": origin
        }))
        raise HTTPException(status_code=403, detail={"error": "origin_not_allowed", "detail": "wallet origin only"})
    
    import secrets
    nonce = secrets.token_urlsafe(32)
    exp_s = _now() + 60  # 60 seconds per Request 2
    
    NONCES[nonce] = {"exp": exp_s, "used": False, "origin": origin}
    
    logger.info(json.dumps({
        "event": "verifier.challenge.issued",
        "nonce": nonce,
        "exp": exp_s
    }))
    
    return JSONResponse({"nonce": nonce, "exp_s": exp_s}, headers={"Cache-Control": "no-store"})

@app.post("/verify")
async def verify_endpoint(request: VerifyRequest):
    """Verify a receipt JWT (legacy endpoint)"""
    try:
        result = await verify_receipt(request.receipt_jwt, request.policy_id)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(json.dumps({
            "event": "verifier.error",
            "error": str(e)
        }))
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "detail": "Verification failed"}
        )

@app.post("/verify/envelope")
async def verify_envelope_endpoint(req: Request, request: VerifyEnvelopeRequest):
    """Verify an envelope containing receipt + nonce"""
    try:
        # Origin check (defense-in-depth)
        origin = req.headers.get("origin")
        if origin != ALLOWED_WALLET_ORIGIN:
            logger.info(json.dumps({
                "event": "verifier.envelope.blocked",
                "reason": "origin_not_allowed",
                "origin": origin
            }))
            return VerifyResponse(ok=False, reason="origin_not_allowed", head=await fetch_head())
        
        envelope = request.envelope
        
        # 1. Check nonce validity
        _gc_nonces()
        nonce_info = NONCES.get(envelope.nonce)
        if not nonce_info:
            logger.info(json.dumps({
                "event": "verifier.envelope.fail",
                "reason": "nonce_unknown",
                "nonce": envelope.nonce
            }))
            return VerifyResponse(
                ok=False,
                reason="nonce_unknown",
                head=await fetch_head()
            )
        
        if nonce_info["used"]:
            logger.info(json.dumps({
                "event": "verifier.envelope.fail", 
                "reason": "nonce_reused",
                "nonce": envelope.nonce
            }))
            return VerifyResponse(
                ok=False,
                reason="nonce_reused",
                head=await fetch_head()
            )
        
        if nonce_info["exp"] <= _now():
            logger.info(json.dumps({
                "event": "verifier.envelope.fail",
                "reason": "nonce_expired", 
                "nonce": envelope.nonce,
                "exp": nonce_info["exp"],
                "now": _now()
            }))
            return VerifyResponse(
                ok=False,
                reason="nonce_expired",
                head=await fetch_head()
            )
        
        # 2. Check nonce origin binding
        if nonce_info.get("origin") != origin:
            logger.info(json.dumps({
                "event": "verifier.envelope.fail",
                "reason": "nonce_origin_mismatch",
                "expected": nonce_info.get("origin"),
                "got": origin
            }))
            return VerifyResponse(ok=False, reason="nonce_origin_mismatch", head=await fetch_head())
        
        # 3. Audience allowlist (MVP)
        if envelope.aud not in ALLOWED_AUDIENCES:
            logger.info(json.dumps({
                "event": "verifier.envelope.fail",
                "reason": "aud_not_allowed",
                "aud": envelope.aud
            }))
            return VerifyResponse(ok=False, reason="aud_not_allowed", head=await fetch_head())
        
        # 4. Mark nonce as used (prevents replay)
        NONCES[envelope.nonce]["used"] = True
        
        # 4. Verify the receipt
        result = await verify_receipt(envelope.receipt, request.policy_id)
        
        # 5. Emit event to transparency log (fail-open)
        try:
            # Parse payload for event data
            payload = None
            try:
                _, payload = parse_jwt_header_payload(envelope.receipt)
            except:
                pass  # Continue without payload if parsing fails
            await emit_event(result, envelope, payload)
        except Exception as e:
            logger.warning(f"Failed to emit event: {e}")
        
        logger.info(json.dumps({
            "event": "verifier.envelope.processed",
            "nonce": envelope.nonce,
            "aud": envelope.aud,
            "ok": result.ok,
            "reason": result.reason
        }))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(json.dumps({
            "event": "verifier.error",
            "error": str(e)
        }))
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "detail": "Envelope verification failed"}
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)