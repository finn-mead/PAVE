import json
import logging
import hashlib
import hmac
import os
import base64
import asyncio
import re
import time
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import defaultdict

from fastapi import FastAPI, HTTPException, Header, Query, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from pydantic import BaseModel, Field, field_validator, model_validator
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Constants
DATA_FILE = Path(__file__).parent / "data" / "guest_list.json"
EVENTS_FILE = Path(__file__).parent / "data" / "events.jsonl"
LOG_SIGNING_SECRET = os.getenv("LOG_SIGNING_SECRET", "dev-secret")
EVENTS_HMAC_SECRET = os.getenv("EVENTS_HMAC_SECRET", "dev-events-secret")
EVENTS_INGEST_TOKEN = os.getenv("EVENTS_INGEST_TOKEN")
KEYS_DIR = Path(__file__).parent / "keys"
LOG_KEY_ID = "pave-log-1"
LOG_PRIV_PATH = KEYS_DIR / "log_private.pem"
LOG_PUB_JWK_PATH = KEYS_DIR / "log_public_jwk.json"

# Security config
PUBLIC_EVENTS_VIEW = os.getenv("PUBLIC_EVENTS_VIEW", "false").lower() == "true"
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "dev-admin-pass")
ADMIN_CSRF_TOKEN = os.getenv("ADMIN_CSRF_TOKEN", "dev-csrf-token")

# Global state
state: Dict[str, Any] = {}
LOG_PRIV: Ed25519PrivateKey = None
LOG_PUB: Ed25519PublicKey = None
events_lock = asyncio.Lock()

# Rate limiting state (IP -> {bucket, last_refill})
rate_limits = defaultdict(lambda: {"tokens": 0, "last_refill": time.time()})

# Security instances
security = HTTPBasic()

# Authentication and authorization functions
def verify_admin_auth(credentials: HTTPBasicCredentials = Depends(security)):
    """Verify admin credentials for Basic Auth"""
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASS:
        raise HTTPException(
            status_code=401,
            detail={"error": "unauthorized", "detail": "Invalid credentials"},
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

def verify_csrf_token(x_admin_csrf: Optional[str] = Header(None)):
    """Verify CSRF token for admin write operations"""
    if x_admin_csrf != ADMIN_CSRF_TOKEN:
        raise HTTPException(
            status_code=403,
            detail={"error": "csrf_invalid", "detail": "Invalid or missing X-Admin-CSRF header"}
        )
    return x_admin_csrf

def check_rate_limit(request: Request, max_requests: int, window_seconds: int = 60):
    """Token bucket rate limiter"""
    client_ip = request.client.host
    now = time.time()
    bucket = rate_limits[client_ip]
    
    # Refill tokens based on time elapsed
    time_elapsed = now - bucket["last_refill"]
    tokens_to_add = (time_elapsed / window_seconds) * max_requests
    bucket["tokens"] = min(max_requests, bucket["tokens"] + tokens_to_add)
    bucket["last_refill"] = now
    
    # Check if request can proceed
    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True
    else:
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limited", "detail": f"Rate limit exceeded: {max_requests} requests per {window_seconds}s"}
        )

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Basic security headers for all responses
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        
        # Admin-specific headers
        if request.url.path.startswith("/admin") or request.url.path == "/dashboard":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'"
            )
        
        # Public viewer headers
        elif request.url.path.startswith("/viewer"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "base-uri 'none'; form-action 'none'"
            )
        
        return response

class ErrorResponse(BaseModel):
    error: str
    detail: str

class SuspendResponse(BaseModel):
    ok: bool
    head: Dict[str, str]

# Events models
CANONICAL_REASONS = {
    "issuer_suspended", "expired", "method_not_allowed", "issuer_not_allowed", 
    "bad_signature", "jwt_malformed", "clock_skew", "policy_mismatch", "internal_error"
}

class EventV1(BaseModel):
    schema: str = Field(default="events.v1", pattern=r"^events\.v1$")
    ts: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    aud_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    issuer: str = Field(..., min_length=1)
    attested_issuer: Optional[str] = None
    method: str = Field(..., min_length=1)
    policy_tag: str = Field(..., min_length=1)
    outcome: str = Field(..., pattern=r"^(ok|fail)$")
    reason: Optional[str] = None
    verify_id: Optional[str] = None            # already exists – keep
    issuer_key_kid: Optional[str] = None

    # NEW optional enrichment fields
    head_digest: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    head_ts: Optional[str] = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
    software: Optional[str] = None
    alg: Optional[str] = None
    checks_count: Optional[int] = Field(default=None, ge=0, le=64)
    policy_version: Optional[str] = None
    verifier_version: Optional[str] = None

    @field_validator('reason')
    @classmethod
    def validate_reason_enum(cls, v, info):
        if hasattr(info, 'data') and info.data.get('outcome') == 'fail':
            if v not in CANONICAL_REASONS:
                raise ValueError(f'reason must be one of: {", ".join(sorted(CANONICAL_REASONS))}')
        return v

    @model_validator(mode="after")
    def reason_required_on_fail(self):
        if self.outcome == "fail" and not self.reason:
            raise ValueError("reason is required when outcome='fail'")
        return self

class EventsResponse(BaseModel):
    schema: str = "events.v1"
    items: List[EventV1]
    next: Optional[str] = None

class IngestResponse(BaseModel):
    ok: bool

class EventsAggregateResponse(BaseModel):
    schema: str = "events.aggregate.v1"
    window: str  # e.g., "1h"
    aggregates: Dict[str, Any]  # Flexible aggregate structure

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def ensure_log_key():
    global LOG_PRIV, LOG_PUB
    KEYS_DIR.mkdir(exist_ok=True)
    if LOG_PRIV_PATH.exists():
        LOG_PRIV = serialization.load_pem_private_key(LOG_PRIV_PATH.read_bytes(), password=None)
        LOG_PUB = LOG_PRIV.public_key()
    else:
        LOG_PRIV = Ed25519PrivateKey.generate()
        LOG_PUB = LOG_PRIV.public_key()
        pem = LOG_PRIV.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        LOG_PRIV_PATH.write_bytes(pem)
        logger.info(json.dumps({
            "event": "guestlist.logkey.generated",
            "kid": LOG_KEY_ID
        }))
    # Cache JWK public
    pub_bytes = LOG_PUB.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    jwk_pub = {
        "kty": "OKP",
        "crv": "Ed25519",
        "kid": LOG_KEY_ID,
        "x": b64url(pub_bytes)
    }
    LOG_PUB_JWK_PATH.write_text(json.dumps({"keys":[jwk_pub]}, indent=2))

def load_data():
    """Load guest list data from file"""
    global state
    try:
        with open(DATA_FILE, 'r') as f:
            state = json.load(f)
        
        logger.info(json.dumps({
            "event": "guestlist.start",
            "data_path": str(DATA_FILE),
            "issuers_count": len(state["issuers"])
        }))
        
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(json.dumps({
            "event": "guestlist.error",
            "op": "load_data",
            "error": str(e)
        }))
        raise HTTPException(
            status_code=500,
            detail={"error": "internal_error", "detail": f"Failed to load data: {e}"}
        )

def compute_head():
    """Compute and update the signed head"""
    global state
    
    # Create canonical JSON of issuers
    canonical = json.dumps(state["issuers"], separators=(",", ":"), sort_keys=True)
    canonical_bytes = canonical.encode('utf-8')
    
    # Compute digest
    digest = hashlib.sha256(canonical_bytes).hexdigest()

    # new head payload
    head_obj = {
        "ts": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "digest": digest,
        "key_id": LOG_KEY_ID
    }
    head_bytes = json.dumps(head_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = LOG_PRIV.sign(head_bytes)
    head_obj["sig"] = b64url(sig)

    state["log_signed_head"] = head_obj

    logger.info(json.dumps({
        "event": "guestlist.head.computed",
        "ts": head_obj["ts"],
        "digest": digest
    }))

def save_data():
    """Save guest list data to file"""
    try:
        # Atomic write
        temp_file = DATA_FILE.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(state, f, indent=2)
        temp_file.rename(DATA_FILE)
    except Exception as e:
        logger.error(json.dumps({
            "event": "guestlist.error",
            "op": "save_data",
            "error": str(e)
        }))
        raise

async def append_event(event: EventV1):
    """Atomically append event to events.jsonl"""
    async with events_lock:
        try:
            # Ensure data directory exists
            EVENTS_FILE.parent.mkdir(exist_ok=True)
            
            # Append event as single line
            with open(EVENTS_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event.model_dump(), separators=(',', ':')) + '\n')
            
        except Exception as e:
            logger.error(json.dumps({
                "event": "events.error",
                "op": "append_event", 
                "error": str(e)
            }))
            raise HTTPException(status_code=503, detail={"error": "append_failed", "detail": str(e)})

def read_events(limit: int = 100, since: Optional[str] = None, 
                issuer: Optional[str] = None, attested_issuer: Optional[str] = None,
                policy_tag: Optional[str] = None, outcome: Optional[str] = None,
                verify_id: Optional[str] = None) -> List[EventV1]:
    """Read and filter events from events.jsonl"""
    events = []
    
    if not EVENTS_FILE.exists():
        return events
    
    try:
        with open(EVENTS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event_data = json.loads(line)
                    event = EventV1(**event_data)
                    
                    # Apply filters
                    if since and event.ts < since:
                        continue
                    if issuer and event.issuer != issuer:
                        continue
                    if attested_issuer and event.attested_issuer != attested_issuer:
                        continue
                    if policy_tag and event.policy_tag != policy_tag:
                        continue
                    if outcome and event.outcome != outcome:
                        continue
                    if verify_id and event.verify_id != verify_id:
                        continue
                    
                    events.append(event)
                except Exception as e:
                    # Skip malformed lines
                    logger.warning(f"Skipping malformed event line: {e}")
                    continue
        
        # Sort by timestamp descending and apply limit
        events.sort(key=lambda e: e.ts, reverse=True)
        return events[:limit]
        
    except Exception as e:
        logger.error(json.dumps({
            "event": "events.error",
            "op": "read_events",
            "error": str(e)
        }))
        return []

def read_events_aggregate(window: str = "1h") -> Dict[str, Any]:
    """Read and aggregate events for public consumption"""
    aggregates = {
        "total_events": 0,
        "by_outcome": {"ok": 0, "fail": 0},
        "by_issuer": {},
        "by_method": {},
        "by_policy": {}
    }
    
    if not EVENTS_FILE.exists():
        return aggregates
    
    # Calculate time window
    window_seconds = 3600  # Default 1 hour
    if window == "1h":
        window_seconds = 3600
    elif window == "24h":
        window_seconds = 86400
    
    cutoff_time = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    cutoff_ts = datetime.fromisoformat(cutoff_time.replace('Z', '+00:00'))
    cutoff_ts = cutoff_ts.replace(second=0, microsecond=0)  # Round to minute
    cutoff_ts = cutoff_ts.replace(tzinfo=None)  # Remove timezone for comparison
    cutoff_ts = (cutoff_ts.timestamp() - window_seconds)
    cutoff_iso = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).isoformat().replace('+00:00', 'Z')
    
    try:
        with open(EVENTS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event_data = json.loads(line)
                    event = EventV1(**event_data)
                    
                    # Filter by time window
                    if event.ts < cutoff_iso:
                        continue
                    
                    # Aggregate data
                    aggregates["total_events"] += 1
                    aggregates["by_outcome"][event.outcome] += 1
                    
                    # Issuer aggregation (use attested_issuer or hostname)
                    issuer_label = event.attested_issuer
                    if not issuer_label:
                        try:
                            from urllib.parse import urlparse
                            issuer_label = urlparse(event.issuer).hostname
                        except:
                            issuer_label = "unknown"
                    
                    aggregates["by_issuer"][issuer_label] = aggregates["by_issuer"].get(issuer_label, 0) + 1
                    aggregates["by_method"][event.method] = aggregates["by_method"].get(event.method, 0) + 1
                    aggregates["by_policy"][event.policy_tag] = aggregates["by_policy"].get(event.policy_tag, 0) + 1
                    
                except Exception as e:
                    # Skip malformed lines
                    continue
                    
    except Exception as e:
        logger.error(json.dumps({
            "event": "events.error",
            "op": "read_events_aggregate",
            "error": str(e)
        }))
    
    return aggregates

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if LOG_SIGNING_SECRET == "dev-secret":
        logger.warning("Using default LOG_SIGNING_SECRET 'dev-secret' - not for production!")
    if EVENTS_HMAC_SECRET == "dev-events-secret":
        logger.warning("Using default EVENTS_HMAC_SECRET 'dev-events-secret' - not for production!")
    
    ensure_log_key()
    load_data()
    compute_head()
    save_data()
    yield
    # Shutdown (nothing needed)

app = FastAPI(title="PAVE Guest List Service", lifespan=lifespan)

# Custom exception handler to return 400 for POST body validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return 400 for POST requests (body validation), 422 for GET requests (query params)
    status_code = 400 if request.method == "POST" else 422
    
    # Convert errors to JSON serializable format
    errors = []
    for error in exc.errors():
        error_dict = dict(error)
        # Convert non-serializable objects to strings
        if 'ctx' in error_dict and 'error' in error_dict['ctx']:
            error_dict['ctx']['error'] = str(error_dict['ctx']['error'])
        errors.append(error_dict)
    
    return JSONResponse(
        status_code=status_code,
        content={"detail": errors}
    )

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:9001", 
        "http://localhost:9002"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False
)

# Static files mount for admin and public
ADMIN_STATIC_DIR = Path(__file__).parent / "static" / "admin"
PUBLIC_STATIC_DIR = Path(__file__).parent / "static" / "public"
app.mount("/static/admin", StaticFiles(directory=str(ADMIN_STATIC_DIR)), name="admin")
app.mount("/static/public", StaticFiles(directory=str(PUBLIC_STATIC_DIR)), name="public")

# Admin dashboard route (requires authentication)
@app.get("/dashboard", response_class=FileResponse)
async def dashboard(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(verify_admin_auth)
):
    """Serve the admin transparency dashboard"""
    # Rate limiting for admin access
    check_rate_limit(request, max_requests=10, window_seconds=60)
    
    dashboard_file = ADMIN_STATIC_DIR / "index.html"
    return FileResponse(
        str(dashboard_file), 
        media_type="text/html",
        headers={"Cache-Control": "no-store"}
    )

# Public events aggregate endpoint
@app.get("/public/events/aggregate", response_model=EventsAggregateResponse)
async def get_events_aggregate(
    request: Request,
    window: str = Query("1h", regex=r"^(1h|24h)$")
):
    """Get aggregated events data for public consumption"""
    # Server-side enforcement: only allow if PUBLIC_EVENTS_VIEW is enabled
    if not PUBLIC_EVENTS_VIEW:
        raise HTTPException(
            status_code=403,
            detail={"error": "events_disabled", "detail": "Event viewing not enabled in this environment"}
        )
    
    # Rate limiting for public aggregate access
    check_rate_limit(request, max_requests=12, window_seconds=60)
    
    aggregates = read_events_aggregate(window)
    return EventsAggregateResponse(
        window=window,
        aggregates=aggregates
    )

# Events endpoints
@app.post("/log/events", response_model=IngestResponse)
async def ingest_event(event: EventV1, x_events_auth: Optional[str] = Header(None)):
    """Ingest a verification event"""
    # Optional auth check
    if EVENTS_INGEST_TOKEN and x_events_auth != EVENTS_INGEST_TOKEN:
        raise HTTPException(status_code=401, detail={"error": "unauthorized", "detail": "invalid or missing X-Events-Auth"})
    
    try:
        await append_event(event)
        return IngestResponse(ok=True)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(json.dumps({
            "event": "events.error",
            "op": "ingest_event",
            "error": str(e)
        }))
        raise HTTPException(status_code=503, detail={"error": "append_failed", "detail": str(e)})

@app.get("/log/events", response_model=EventsResponse)
async def get_events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    since: Optional[str] = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"),
    issuer: Optional[str] = Query(None),
    attested_issuer: Optional[str] = Query(None), 
    policy_tag: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None, pattern=r"^(ok|fail)$"),
    verify_id: Optional[str] = Query(None),
    credentials: HTTPBasicCredentials = Depends(verify_admin_auth)
):
    """Get filtered events in descending timestamp order (admin only)"""
    # Rate limiting for admin events access
    check_rate_limit(request, max_requests=30, window_seconds=60)
    
    try:
        # Clamp limit to max 1000
        limit = min(limit, 1000)
        
        events = read_events(
            limit=limit,
            since=since,
            issuer=issuer,
            attested_issuer=attested_issuer,
            policy_tag=policy_tag,
            outcome=outcome,
            verify_id=verify_id
        )
        
        response = EventsResponse(items=events)
        
        # Set cache headers
        headers = {
            "Cache-Control": "no-store",
            "Content-Type": "application/json"
        }
        
        return JSONResponse(content=response.model_dump(), headers=headers)
        
    except Exception as e:
        logger.error(json.dumps({
            "event": "events.error", 
            "op": "get_events",
            "error": str(e)
        }))
        raise HTTPException(status_code=422, detail={"error": "query_error", "detail": str(e)})

@app.get("/log/head")
async def get_head():
    """Return the current signed head"""
    return state["log_signed_head"]

@app.get("/log/issuers")
async def list_issuers():
    """Return all issuers (array)"""
    return state["issuers"]

@app.get("/log/issuers/{kid}")
async def get_issuer(kid: str):
    """Return issuer entry by kid"""
    for issuer in state["issuers"]:
        # accept either kid in keys or top-level legacy kid
        if issuer.get("kid") == kid or any(k.get("kid")==kid for k in issuer.get("keys", [])):
            logger.info(json.dumps({
                "event": "guestlist.issuer.fetched",
                "kid": kid
            }))
            return issuer
    
    raise HTTPException(
        status_code=404,
        detail={"error": "unknown_kid", "detail": "unknown kid"}
    )

@app.get("/log/digest")
async def get_current_digest():
    """Return recomputed canonical digest of issuers (matches compute_head)"""
    canonical = json.dumps(state["issuers"], separators=(",", ":"), sort_keys=True).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    return {"digest": digest}

@app.get("/log/.well-known/jwks.json")
async def log_jwks():
    return JSONResponse(json.loads(LOG_PUB_JWK_PATH.read_text()))

@app.post("/admin/suspend/{kid}", response_model=SuspendResponse)
async def suspend_issuer(
    kid: str, 
    request: Request,
    credentials: HTTPBasicCredentials = Depends(verify_admin_auth),
    csrf_token: str = Depends(verify_csrf_token)
):
    """Suspend an issuer by kid"""
    # Rate limiting for admin operations
    check_rate_limit(request, max_requests=10, window_seconds=60)
    
    # Find issuer
    issuer = None
    for i in state["issuers"]:
        # accept either kid in keys or top-level legacy kid
        if i.get("kid") == kid or any(k.get("kid")==kid for k in i.get("keys", [])):
            issuer = i
            break
    
    if not issuer:
        raise HTTPException(
            status_code=404,
            detail={"error": "unknown_kid", "detail": "unknown kid"}
        )
    
    # Update issuer
    issuer["status"] = "suspended"
    issuer["updated_at"] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Recompute head and save
    compute_head()
    save_data()
    
    logger.info(json.dumps({
        "event": "guestlist.issuer.suspended",
        "kid": kid,
        "ts": issuer["updated_at"],
        "digest": state["log_signed_head"]["digest"]
    }))
    
    return SuspendResponse(ok=True, head=state["log_signed_head"])

@app.post("/admin/activate/{kid}", response_model=SuspendResponse)
async def activate_issuer(
    kid: str,
    request: Request,
    credentials: HTTPBasicCredentials = Depends(verify_admin_auth),
    csrf_token: str = Depends(verify_csrf_token)
):
    """Activate an issuer by kid"""
    # Rate limiting for admin operations
    check_rate_limit(request, max_requests=10, window_seconds=60)
    issuer = None
    for i in state["issuers"]:
        # accept either kid in keys or top-level legacy kid
        if i.get("kid") == kid or any(k.get("kid")==kid for k in i.get("keys", [])):
            issuer = i
            break
    if not issuer:
        raise HTTPException(status_code=404, detail={"error":"unknown_kid","detail":"unknown kid"})
    issuer["status"] = "active"
    issuer["updated_at"] = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    compute_head()
    save_data()
    logger.info(json.dumps({"event":"guestlist.issuer.activated","kid":kid,"ts":issuer["updated_at"],"digest":state["log_signed_head"]["digest"]}))
    return SuspendResponse(ok=True, head=state["log_signed_head"])

@app.get("/viewer", response_class=FileResponse)
async def public_viewer(request: Request):
    """Serve the public transparency viewer"""
    # Rate limiting for public viewer access
    check_rate_limit(request, max_requests=20, window_seconds=60)
    
    # No authentication required - this is the public interface
    viewer_file = PUBLIC_STATIC_DIR / "index.html"
    return FileResponse(
        str(viewer_file), 
        media_type="text/html",
        headers={"Cache-Control": "public, max-age=300"}  # 5 minute cache
    )

@app.get("/viewer/events", response_class=HTMLResponse)
async def events_viewer():
    """Legacy HTML viewer for events log (deprecated, use /viewer instead)"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PAVE Events Log Viewer</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 20px; }
            .header { background: #f0f8ff; padding: 16px; border-radius: 8px; margin-bottom: 20px; }
            .filters { margin: 20px 0; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
            .filters select, .filters input { padding: 6px 8px; border: 1px solid #ddd; border-radius: 4px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
            th { background: #f8f9fa; font-weight: 600; }
            .outcome-ok { color: #22c55e; }
            .outcome-fail { color: #ef4444; }
            .empty-state { text-align: center; padding: 40px; color: #666; }
            .error { background: #fee2e2; color: #dc2626; padding: 12px; border-radius: 4px; margin: 20px 0; }
            .short-hash { font-family: monospace; }
            .auto-refresh { margin-left: auto; font-size: 14px; color: #666; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>PAVE Events Log Viewer</h1>
            <p>Real-time verification events from the PAVE network</p>
        </div>
        
        <div class="filters">
            <label>Outcome: 
                <select id="outcome-filter">
                    <option value="">All</option>
                    <option value="ok">OK</option>
                    <option value="fail">Fail</option>
                </select>
            </label>
            <label>Issuer: 
                <select id="issuer-filter">
                    <option value="">All</option>
                </select>
            </label>
            <label>Policy: 
                <select id="policy-filter">
                    <option value="">All</option>
                </select>
            </label>
            <span class="auto-refresh">Auto-refresh: 10s</span>
        </div>
        
        <div id="error-container"></div>
        
        <table id="events-table">
            <thead>
                <tr>
                    <th>Time (UTC)</th>
                    <th>Site</th>
                    <th>Issuer</th>
                    <th>Method</th>
                    <th>Policy</th>
                    <th>Outcome</th>
                    <th>Reason</th>
                </tr>
            </thead>
            <tbody id="events-body">
            </tbody>
        </table>
        
        <div id="empty-state" class="empty-state" style="display: none;">
            No events yet. Run a verification to populate.
        </div>
        
        <script>
            let currentFilters = { outcome: '', issuer: '', policy: '' };
            let allEvents = [];
            
            function showError(message) {
                const container = document.getElementById('error-container');
                container.innerHTML = '<div class="error">' + message + ' (retrying in 5s...)</div>';
                setTimeout(() => container.innerHTML = '', 5000);
            }
            
            function updateFilters(events) {
                const issuers = new Set();
                const policies = new Set();
                
                events.forEach(event => {
                    const issuerName = event.attested_issuer || new URL(event.issuer).hostname;
                    const filterValue = event.attested_issuer || event.issuer; // Use full URL when no attested_issuer
                    issuers.add(JSON.stringify({name: issuerName, value: filterValue}));
                    policies.add(event.policy_tag);
                });
                
                const issuerSelect = document.getElementById('issuer-filter');
                const policySelect = document.getElementById('policy-filter');
                
                // Preserve current selection
                const currentIssuer = issuerSelect.value;
                const currentPolicy = policySelect.value;
                
                issuerSelect.innerHTML = '<option value="">All</option>';
                Array.from(issuers).map(JSON.parse).sort((a, b) => a.name.localeCompare(b.name)).forEach(issuer => {
                    const option = document.createElement('option');
                    option.value = issuer.value;
                    option.textContent = issuer.name;
                    if (issuer.value === currentIssuer) option.selected = true;
                    issuerSelect.appendChild(option);
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
            
            function renderEvents(events) {
                const tbody = document.getElementById('events-body');
                const emptyState = document.getElementById('empty-state');
                
                if (events.length === 0) {
                    tbody.innerHTML = '';
                    emptyState.style.display = 'block';
                    return;
                }
                
                emptyState.style.display = 'none';
                
                tbody.innerHTML = events.map(event => {
                    const issuerName = event.attested_issuer || new URL(event.issuer).hostname;
                    const shortHash = event.aud_hash.substring(0, 8);
                    const outcomeClass = event.outcome === 'ok' ? 'outcome-ok' : 'outcome-fail';
                    const outcomeIcon = event.outcome === 'ok' ? '✓' : '✗';
                    
                    return `
                        <tr>
                            <td>${new Date(event.ts).toLocaleString('en-US', {timeZone: 'UTC'})} UTC</td>
                            <td><span class="short-hash" title="${event.aud_hash}">${shortHash}</span></td>
                            <td>${issuerName}${event.attested_issuer ? ' <small>(adapter)</small>' : ''}</td>
                            <td>${event.method}</td>
                            <td>${event.policy_tag}</td>
                            <td class="${outcomeClass}">${outcomeIcon} ${event.outcome.toUpperCase()}</td>
                            <td>${event.reason || ''}</td>
                        </tr>
                    `;
                }).join('');
            }
            
            async function fetchEvents() {
                try {
                    const params = new URLSearchParams();
                    params.set('limit', '200');
                    if (currentFilters.outcome) params.set('outcome', currentFilters.outcome);
                    if (currentFilters.issuer) {
                        // If filter value looks like a URL, use issuer param; otherwise use attested_issuer
                        if (currentFilters.issuer.startsWith('http://') || currentFilters.issuer.startsWith('https://')) {
                            params.set('issuer', currentFilters.issuer);
                        } else {
                            params.set('attested_issuer', currentFilters.issuer);
                        }
                    }
                    if (currentFilters.policy) params.set('policy_tag', currentFilters.policy);
                    
                    const response = await fetch('/log/events?' + params.toString());
                    if (!response.ok) throw new Error('HTTP ' + response.status);
                    
                    const data = await response.json();
                    allEvents = data.items;
                    updateFilters(allEvents);
                    renderEvents(allEvents);
                    
                } catch (error) {
                    showError('Couldn\'t load events: ' + error.message);
                    setTimeout(fetchEvents, 5000);
                }
            }
            
            // Set up filter handlers
            document.getElementById('outcome-filter').addEventListener('change', (e) => {
                currentFilters.outcome = e.target.value;
                fetchEvents();
            });
            
            document.getElementById('issuer-filter').addEventListener('change', (e) => {
                currentFilters.issuer = e.target.value;
                fetchEvents();
            });
            
            document.getElementById('policy-filter').addEventListener('change', (e) => {
                currentFilters.policy = e.target.value;
                fetchEvents();
            });
            
            // Initial load and auto-refresh
            fetchEvents();
            setInterval(fetchEvents, 10000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.get("/robots.txt", response_class=Response)
async def robots_txt():
    """Robots.txt for privacy controls"""
    content = "User-agent: *\nDisallow: /admin/\nDisallow: /dashboard\nDisallow: /log/events\n"
    return Response(content=content, media_type="text/plain")

@app.get("/issuer/{kid}", response_class=HTMLResponse)
async def viewer(kid: str = "fastage-k1"):
    """Legacy viewer page for issuer and head (deprecated, use /viewer instead)"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PAVE Guest List Viewer</title>
        <style>
            body {{ font-family: monospace; margin: 40px; }}
            .section {{ margin: 20px 0; }}
            pre {{ background: #f5f5f5; padding: 15px; overflow-x: auto; }}
            .explanation {{ color: #666; font-size: 14px; margin: 10px 0; }}
        </style>
    </head>
    <body>
        <h1>PAVE Guest List Viewer</h1>
        <div class="explanation">
            Signed head prevents silent edits; suspension updates the head.
        </div>
        
        <div class="section">
            <h2>Issuer Entry (kid: {kid})</h2>
            <div id="issuer">Loading...</div>
        </div>
        
        <div class="section">
            <h2>Signed Head</h2>
            <div id="head">Loading...</div>
        </div>
        
        <div class="section">
            <h2>Digest Verification</h2>
            <div id="digest-check">Loading...</div>
        </div>
        
        <script>
            // Fetch issuer data
            fetch('/log/issuers/{kid}')
                .then(response => response.json())
                .then(data => {{
                    document.getElementById('issuer').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                }})
                .catch(error => {{
                    document.getElementById('issuer').innerHTML = '<pre>Error: ' + error.message + '</pre>';
                }});
            
            // Fetch head data and perform digest verification
            Promise.all([
                fetch('/log/head').then(r => r.json()),
                fetch('/log/digest').then(r => r.json())
            ])
            .then(([headData, digestData]) => {{
                document.getElementById('head').innerHTML = '<pre>' + JSON.stringify(headData, null, 2) + '</pre>';
                
                const match = headData.digest === digestData.digest;
                const badge = match ? 
                    '<span style="background: green; color: white; padding: 2px 6px; border-radius: 3px;">✓ VERIFIED</span>' :
                    '<span style="background: red; color: white; padding: 2px 6px; border-radius: 3px;">✗ MISMATCH</span>';
                    
                document.getElementById('digest-check').innerHTML = 
                    '<p>Head digest: <code>' + headData.digest + '</code></p>' +
                    '<p>Recomputed: <code>' + digestData.digest + '</code></p>' +
                    '<p>Status: ' + badge + '</p>';
            }})
            .catch(error => {{
                document.getElementById('head').innerHTML = '<pre>Error: ' + error.message + '</pre>';
                document.getElementById('digest-check').innerHTML = '<pre>Error: ' + error.message + '</pre>';
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)