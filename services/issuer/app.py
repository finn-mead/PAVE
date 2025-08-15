import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from jwcrypto import jwk, jwt
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Constants
KID = "fastage-k1"
ISSUER_URL = "http://localhost:8001"
KEYS_DIR = Path(__file__).parent / "keys"
PRIVATE_KEY_FILE = KEYS_DIR / "issuer_private.jwk"
PUBLIC_KEY_FILE = KEYS_DIR / "issuer_public.jwk"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    ensure_keys()
    yield
    # Shutdown (nothing needed)

app = FastAPI(title="PAVE Issuer Service", lifespan=lifespan)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9001", "http://localhost:9002"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False
)

class IssuerResponse(BaseModel):
    receipt_jwt: str

class ErrorResponse(BaseModel):
    error: str
    detail: str

# Global variables
private_key: jwk.JWK = None
public_key: jwk.JWK = None

def ensure_keys():
    """Ensure RSA keypair exists and is loaded"""
    global private_key, public_key
    
    # Ensure keys directory exists
    KEYS_DIR.mkdir(exist_ok=True)
    
    key_existed = PRIVATE_KEY_FILE.exists() and PUBLIC_KEY_FILE.exists()
    
    try:
        if key_existed:
            # Try to load existing keys
            with open(PRIVATE_KEY_FILE, 'r') as f:
                private_key = jwk.JWK.from_json(f.read())
            with open(PUBLIC_KEY_FILE, 'r') as f:
                public_key = jwk.JWK.from_json(f.read())
                
            # Verify the keys are valid
            if private_key.get('kid') != KID or public_key.get('kid') != KID:
                raise ValueError("Key ID mismatch")
                
        else:
            raise FileNotFoundError("Keys not found")
            
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        if key_existed:
            logger.warning(f"Key corruption detected: {e}, regenerating keys")
        
        # Generate new RSA-2048 keypair
        private_key = jwk.JWK.generate(kty='RSA', size=2048, kid=KID)
        public_key = jwk.JWK.from_json(private_key.export_public())
        public_key['kid'] = KID
        
        # Write keys to disk (atomic write)
        private_temp = PRIVATE_KEY_FILE.with_suffix('.tmp')
        public_temp = PUBLIC_KEY_FILE.with_suffix('.tmp')
        
        try:
            with open(private_temp, 'w') as f:
                f.write(private_key.export())
            with open(public_temp, 'w') as f:
                f.write(public_key.export())
                
            # Atomic rename
            private_temp.rename(PRIVATE_KEY_FILE)
            public_temp.rename(PUBLIC_KEY_FILE)
            
        except Exception:
            # Cleanup temp files on error
            private_temp.unlink(missing_ok=True)
            public_temp.unlink(missing_ok=True)
            raise
            
        logger.info(json.dumps({
            "event": "issuer.key.generated",
            "kid": KID,
            "alg": "RSA",
            "size_bits": 2048
        }))
        
        key_existed = False
    
    logger.info(json.dumps({
        "event": "issuer.start",
        "kid": KID,
        "port": 8001,
        "keys_dir": str(KEYS_DIR),
        "key_existed": key_existed
    }))


@app.get("/.well-known/jwks.json")
async def get_jwks():
    """Return public key set"""
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
    """Issue a signed receipt JWT"""
    try:
        now = int(time.time())
        
        # Check for time anomalies
        if now < 1640995200:  # Jan 1, 2022
            logger.error(json.dumps({
                "event": "issuer.issue.failure",
                "kid": KID,
                "reason": "system_time_anomaly"
            }))
            raise HTTPException(
                status_code=500,
                detail={"error": "internal_error", "detail": "System time anomaly detected"}
            )
        
        # Build JWT payload
        payload = {
            "iss": ISSUER_URL,
            "kid": KID,
            "sub": "user-1234",
            "over18": True,
            "method": "ID+face",
            "checks": ["id_scan", "selfie_match", "liveness"],
            "software": "FaceMatch 2.3.1 (model a1b2c3)",
            "policy_tag": "uk_adult_high",
            "iat": now,
            "exp": now + 86400  # 24 hours
        }
        
        # Create JWT
        token = jwt.JWT(
            header={"alg": "RS256", "kid": KID},
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)