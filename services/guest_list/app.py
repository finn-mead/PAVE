import json
import logging
import hashlib
import hmac
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Constants
DATA_FILE = Path(__file__).parent / "data" / "guest_list.json"
LOG_SIGNING_SECRET = os.getenv("LOG_SIGNING_SECRET", "dev-secret")

# Global state
state: Dict[str, Any] = {}

class ErrorResponse(BaseModel):
    error: str
    detail: str

class SuspendResponse(BaseModel):
    ok: bool
    head: Dict[str, str]

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
    
    # Compute HMAC signature
    sig = hmac.new(
        LOG_SIGNING_SECRET.encode('utf-8'),
        digest.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Update head
    now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    state["log_signed_head"] = {
        "ts": now,
        "digest": digest,
        "sig": sig
    }
    
    logger.info(json.dumps({
        "event": "guestlist.head.computed",
        "ts": now,
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    if LOG_SIGNING_SECRET == "dev-secret":
        logger.warning("Using default LOG_SIGNING_SECRET 'dev-secret' - not for production!")
    
    load_data()
    compute_head()
    save_data()
    yield
    # Shutdown (nothing needed)

app = FastAPI(title="PAVE Guest List Service", lifespan=lifespan)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:9001", 
        "http://localhost:9002", 
        "http://localhost:8003"
    ],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False
)

@app.get("/log/head")
async def get_head():
    """Return the current signed head"""
    return state["log_signed_head"]

@app.get("/log/issuers/{kid}")
async def get_issuer(kid: str):
    """Return issuer entry by kid"""
    for issuer in state["issuers"]:
        if issuer["kid"] == kid:
            logger.info(json.dumps({
                "event": "guestlist.issuer.fetched",
                "kid": kid
            }))
            return issuer
    
    raise HTTPException(
        status_code=404,
        detail={"error": "unknown_kid", "detail": "unknown kid"}
    )

@app.post("/admin/suspend/{kid}", response_model=SuspendResponse)
async def suspend_issuer(kid: str):
    """Suspend an issuer by kid"""
    # Find issuer
    issuer = None
    for i in state["issuers"]:
        if i["kid"] == kid:
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

@app.get("/viewer", response_class=HTMLResponse)
async def viewer(kid: str = "fastage-k1"):
    """Viewer page for issuer and head"""
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
            
            // Fetch head data
            fetch('/log/head')
                .then(response => response.json())
                .then(data => {{
                    document.getElementById('head').innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                }})
                .catch(error => {{
                    document.getElementById('head').innerHTML = '<pre>Error: ' + error.message + '</pre>';
                }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)