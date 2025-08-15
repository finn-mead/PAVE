import json
import logging
import time
import base64
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jwcrypto import jwk, jws
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Constants
GUEST_LIST_BASE = "http://localhost:8002"
EXPECTED_ISSUER = "http://localhost:8001"
TIMEOUT = 5.0

# Global HTTP client
http_client: Optional[httpx.AsyncClient] = None

class VerifyRequest(BaseModel):
    receipt_jwt: str

class VerifyResponse(BaseModel):
    ok: bool
    reason: Optional[str] = None
    assurance: Optional[Dict[str, Any]] = None
    head: Optional[Dict[str, str]] = None

class ErrorResponse(BaseModel):
    error: str
    detail: str

async def fetch_issuer_entry(kid: str) -> Dict[str, Any]:
    """Fetch issuer entry from Guest List"""
    url = f"{GUEST_LIST_BASE}/log/issuers/{kid}"
    try:
        response = await http_client.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(json.dumps({
            "event": "verifier.http.error",
            "op": "fetch_issuer_entry", 
            "url": url,
            "status": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "error": str(e)
        }))
        raise HTTPException(status_code=500, detail={
            "error": "internal_error", 
            "detail": f"Failed to fetch issuer entry: {str(e)}"
        })

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
        header_b64 += '=' * (4 - len(header_b64) % 4)  # Add padding
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Decode payload  
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)  # Add padding
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        return header, payload
    except (ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Failed to parse JWT: {e}")

async def verify_receipt(receipt_jwt: str) -> VerifyResponse:
    """Main verification logic"""
    
    # Parse JWT header and payload for routing info
    try:
        header, payload = parse_jwt_header_payload(receipt_jwt)
        kid = header.get('kid')
        iss = payload.get('iss')
    except ValueError as e:
        return VerifyResponse(
            ok=False, 
            reason="invalid_jwt",
            head=await fetch_head()
        )
    
    logger.info(json.dumps({
        "event": "verifier.verify.begin",
        "kid": kid,
        "iss": iss
    }))
    
    # 1. Get issuer entry from Guest List
    issuer_entry = await fetch_issuer_entry(kid)
    if not issuer_entry:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "unknown_kid",
            "kid": kid
        }))
        return VerifyResponse(
            ok=False,
            reason="unknown_kid", 
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
    
    # 3. Validate issuer matches expected
    if iss != EXPECTED_ISSUER:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "issuer_mismatch",
            "kid": kid,
            "iss": iss,
            "expected": EXPECTED_ISSUER
        }))
        return VerifyResponse(
            ok=False,
            reason="issuer_mismatch",
            head=await fetch_head()
        )
    
    # 4. Fetch JWKS and find matching key
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
        
        # Enforce RS256 algorithm
        if j.jose_header.get("alg") != "RS256":
            logger.info(json.dumps({
                "event": "verifier.verify.fail",
                "reason": "alg_not_allowed", 
                "kid": kid,
                "alg": j.jose_header.get("alg")
            }))
            return VerifyResponse(
                ok=False,
                reason="alg_not_allowed",
                head=await fetch_head()
            )
        
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
    
    # Check time bounds
    iat = verified_payload.get('iat')
    exp = verified_payload.get('exp')
    
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
    
    if iat > now:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "token_issued_in_future",
            "kid": kid,
            "iat": iat,
            "now": now
        }))
        return VerifyResponse(
            ok=False,
            reason="token_issued_in_future",
            head=await fetch_head()
        )
    
    if now >= exp:
        logger.info(json.dumps({
            "event": "verifier.verify.fail",
            "reason": "token_expired", 
            "kid": kid,
            "exp": exp,
            "now": now
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
    
    # 7. Success! Build assurance response
    head = await fetch_head()
    
    assurance = {
        "issuer_kid": verified_payload.get('kid'),
        "iss": verified_payload.get('iss'),
        "method": verified_payload.get('method'),
        "checks": verified_payload.get('checks', []),
        "policy_tag": verified_payload.get('policy_tag'),
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
    allow_origins=["http://localhost:9001", "http://localhost:9002"],
    allow_methods=["*"],
    allow_headers=["*"], 
    allow_credentials=False
)

@app.post("/verify")
async def verify_endpoint(request: VerifyRequest):
    """Verify a receipt JWT"""
    try:
        result = await verify_receipt(request.receipt_jwt)
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)