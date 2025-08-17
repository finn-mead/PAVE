import json
import logging
import time
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import unquote, quote, urlparse

from fastapi import FastAPI, HTTPException, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jwcrypto import jwk, jwt
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

KID = "fastage-k1"
ISSUER_URL = "http://localhost:8001"
KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY_FILE = KEYS_DIR / "issuer_private.jwk"
PUBLIC_KEY_FILE = KEYS_DIR / "issuer_public.jwk"

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_keys()
    yield

app = FastAPI(title="PAVE Mock Issuer UI", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9001", "http://localhost:9002", "http://localhost:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False
)

app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

class IssuerResponse(BaseModel):
    receipt_jwt: str

class ErrorResponse(BaseModel):
    error: str
    detail: str

private_key: jwk.JWK = None
public_key: jwk.JWK = None

def ensure_keys():
    global private_key, public_key
    
    KEYS_DIR.mkdir(exist_ok=True)
    key_existed = PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists()
    
    try:
        if key_existed:
            with open(PRIVATE_KEY_FILE, 'r') as f:
                private_key = jwk.JWK.from_json(f.read())
            with open(PUBLIC_KEY_FILE, 'r') as f:
                public_key = jwk.JWK.from_json(f.read())
                
            if private_key.get('kid') != KID or public_key.get('kid') != KID:
                raise ValueError("Key ID mismatch")
        else:
            raise FileNotFoundError("Keys not found")
            
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        if key_existed:
            logger.warning(f"Key corruption detected: {e}, regenerating keys")
        
        private_key = jwk.JWK.generate(kty='EC', curve='P-256', kid=KID)
        public_key = jwk.JWK.from_json(private_key.export_public())
        public_key['kid'] = KID
        
        private_temp = PRIVATE_KEY_FILE.with_suffix('.tmp')
        public_temp = PUBLIC_KEY_FILE.with_suffix('.tmp')
        
        try:
            with open(private_temp, 'w') as f:
                f.write(private_key.export())
            with open(public_temp, 'w') as f:
                f.write(public_key.export())
                
            private_temp.rename(PRIVATE_KEY_FILE)
            public_temp.rename(PUBLIC_KEY_FILE)
            
        except Exception:
            private_temp.unlink(missing_ok=True)
            public_temp.unlink(missing_ok=True)
            raise
            
        logger.info(json.dumps({
            "event": "issuer.key.generated",
            "kid": KID,
            "alg": "ES256",
            "curve": "P-256"
        }))
        
        key_existed = False
    
    logger.info(json.dumps({
        "event": "issuer.start",
        "kid": KID,
        "port": 8001,
        "keys_dir": str(KEYS_DIR),
        "key_existed": key_existed
    }))

# CSRF and auth functions removed - not used in MVP GET-based flow

@app.get("/.well-known/jwks.json")
async def get_jwks():
    try:
        logger.info(json.dumps({
            "event": "issuer.jwks.served",
            "kid": KID
        }))
        
        return {
            "keys": [public_key.export_public(as_dict=True)]
        }
    except Exception as e:
        logger.error(json.dumps({
            "event": "issuer.jwks.failure",
            "kid": KID,
            "reason": str(e)
        }))
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "detail": "Failed to serve JWKS"}
        )

@app.post("/issue", response_model=IssuerResponse)
async def issue_receipt():
    try:
        now = int(time.time())
        
        if now < 1640995200:
            logger.error(json.dumps({
                "event": "issuer.issue.failure",
                "kid": KID,
                "reason": "system_time_anomaly"
            }))
            raise HTTPException(
                status_code=500,
                detail={"error": "internal_error", "detail": "System time anomaly detected"}
            )
        
        session_id = secrets.token_urlsafe(16)
        payload = {
            "iss": ISSUER_URL,
            "kid": KID,
            "sub": f"user-{session_id[:8]}",
            "session_id": session_id,
            "over18": True,
            "method": "ID+face",
            "checks": ["id_scan", "selfie_match", "liveness"],
            "software": "FaceMatch 2.3.1",
            "policy_tag": "uk_adult_high",
            "iat": now,
            "exp": now + 86400
        }
        
        token = jwt.JWT(
            header={"alg": "ES256", "typ": "JWT", "kid": KID},
            claims=payload
        )
        token.make_signed_token(private_key)
        
        receipt_jwt = token.serialize()
        
        logger.info(json.dumps({
            "event": "issuer.issue.success",
            "kid": KID,
            "sub": payload["sub"],
            "iat": payload["iat"],
            "exp": payload["exp"],
            "method": payload["method"],
            "policy_tag": payload["policy_tag"]
        }))
        
        return IssuerResponse(receipt_jwt=receipt_jwt)
        
    except Exception as e:
        logger.error(json.dumps({
            "event": "issuer.issue.failure",
            "kid": KID,
            "reason": str(e)
        }))
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "detail": "Failed to issue receipt"}
        )

@app.get("/ui", response_class=HTMLResponse)
@app.get("/approve", response_class=HTMLResponse)
async def approve_form(
    request: Request,
    return_url: Optional[str] = None,
    return_to: Optional[str] = None,
    state: Optional[str] = None,
    aud: Optional[str] = None,
    policy_id: Optional[str] = None
):
    # Normalize return_to/return_url to return_url
    return_url = return_to or return_url
    policy_id = policy_id or "uk_adult_high"
    
    if not all([return_url, state, aud]):
        raise HTTPException(status_code=400, detail="Missing required parameters: return_url/return_to, state, aud")
    
    # Strict return_url validation
    try:
        parsed = urlparse(return_url)
        if not (parsed.scheme == "http" and 
                parsed.hostname == "localhost" and 
                parsed.port == 8000 and 
                parsed.path == "/verify-ui" and 
                not parsed.username and 
                not parsed.password and 
                not parsed.fragment):
            raise ValueError("Invalid return_url format")
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="return_url must be exactly http://localhost:8000/verify-ui")
    
    # Validate aud allowlist  
    if aud not in ["http://localhost:9001", "http://localhost:9002"]:
        raise HTTPException(status_code=400, detail="aud must be http://localhost:9001 or http://localhost:9002")
    
    with open(Path(__file__).parent / "templates" / "approve.html", "r") as f:
        template = f.read()
    
    # Add security headers
    content = template.replace("{return_url}", quote(return_url))\
                     .replace("{state}", quote(state))\
                     .replace("{aud}", quote(aud))\
                     .replace("{policy_id}", quote(policy_id))\
                     .replace("{site_name}", f"Site {'A' if '9001' in aud else 'B' if '9002' in aud else 'Unknown'}")
    
    return Response(
        content=content,
        media_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        }
    )

@app.get("/ui/approve")
@app.get("/approve/approve")
async def handle_approve_get(
    request: Request,
    return_url: Optional[str] = None,
    return_to: Optional[str] = None,
    state: Optional[str] = None,
    aud: Optional[str] = None,
    policy_id: Optional[str] = None
):
    return_url = unquote(return_to or return_url or "")
    state = unquote(state or "")
    aud = unquote(aud or "")
    policy_id = unquote(policy_id or "uk_adult_high")
    
    now = int(time.time())
    session_id = secrets.token_urlsafe(16)
    
    payload = {
        "iss": ISSUER_URL,
        "kid": KID,
        "sub": f"user-{session_id[:8]}",
        "session_id": session_id,
        "over18": True,
        "method": "ID+face",
        "checks": ["id_scan", "selfie_match", "liveness"],
        "software": "FaceMatch 2.3.1",
        "policy_tag": policy_id,
        "iat": now,
        "exp": now + 86400
    }
    
    token = jwt.JWT(
        header={"alg": "ES256", "typ": "JWT", "kid": KID},
        claims=payload
    )
    token.make_signed_token(private_key)
    
    receipt_jwt = token.serialize()
    
    logger.info(json.dumps({
        "event": "issuer.approve.success",
        "kid": KID,
        "sub": payload["sub"],
        "session_id": session_id,
        "aud": aud,
        "state": state
    }))
    
    # Return to wallet with success params
    params = {
        "issuer_result": "ok",
        "jwt": receipt_jwt,
        "issuer_id": "fastage",
        "method": "ID+face",
        "software": "FaceMatch 2.3.1",
        "session_id": session_id,
        "state": state,
        "aud": aud,
        "policy_id": policy_id
    }
    
    redirect_url = f"{return_url}?" + "&".join([f"{k}={quote(str(v))}" for k, v in params.items()])
    return RedirectResponse(
        url=redirect_url, 
        status_code=302,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
        }
    )

@app.get("/ui/reject")
@app.get("/approve/reject")
async def handle_reject_get(
    request: Request,
    return_url: Optional[str] = None,
    return_to: Optional[str] = None,
    state: Optional[str] = None,
    aud: Optional[str] = None,
    policy_id: Optional[str] = None
):
    return_url = unquote(return_to or return_url or "")
    state = unquote(state or "")
    aud = unquote(aud or "")
    policy_id = unquote(policy_id or "uk_adult_high")
    
    logger.info(json.dumps({
        "event": "issuer.approve.rejected",
        "kid": KID,
        "aud": aud,
        "state": state
    }))
    
    # Return to wallet with failure params
    params = {
        "issuer_result": "fail",
        "reason": "manual_reject",
        "issuer_id": "fastage",
        "state": state,
        "aud": aud,
        "policy_id": policy_id
    }
    
    redirect_url = f"{return_url}?" + "&".join([f"{k}={quote(str(v))}" for k, v in params.items()])
    return RedirectResponse(
        url=redirect_url, 
        status_code=302,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)