# services/wallet/app.py
import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

ALLOWED_EMBED_ORIGINS = [
    "http://localhost:9001",
    "http://localhost:9002",
]

app = FastAPI(title="PAVE Wallet (iframe)")

# This CORS is only for static asset fetches by the embedding pages (not strictly required for static files),
# but it doesn't harm. Real origin enforcement happens INSIDE wallet.js postMessage handler.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_EMBED_ORIGINS,
    allow_methods=["GET", "HEAD", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    resp = await call_next(request)
    # Only allow our two sites to frame the wallet iframe
    resp.headers["Content-Security-Policy"] = (
        "frame-ancestors " + " ".join(ALLOWED_EMBED_ORIGINS)
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    
    # Allow cross-origin for SDK, strict for everything else
    if request.url.path.startswith("/sdk/"):
        resp.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
    else:
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    
    return resp

@app.get("/verify-ui")
async def verify_ui():
    """Serve the top-level verification page"""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    verify_html = os.path.join(static_dir, "verify.html")
    return FileResponse(verify_html)

@app.get("/iframe.html")
async def serve_iframe():
    """Back-compat path: SDK expects /iframe.html at root"""
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    return FileResponse(os.path.join(static_dir, "iframe.html"))

@app.get("/sdk/wallet-client.js")
async def serve_shared_sdk():
    """Serve the shared SDK for sites to include"""
    sdk_path = os.path.join(os.path.dirname(__file__), "../../sdk/wallet-client.js")
    if not os.path.exists(sdk_path):
        raise HTTPException(status_code=404, detail="SDK file not found")
    return FileResponse(
        sdk_path,
        media_type="application/javascript",
        headers={"Cache-Control": "no-store"}
    )

# Mount static files at /static to avoid route conflicts
app.mount("/static", StaticFiles(directory=str((__file__[:__file__.rfind("/")]+"/static").replace("\\","/")), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)