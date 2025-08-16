# services/wallet/app.py
import json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    return resp

app.mount("/", StaticFiles(directory=str((__file__[:__file__.rfind("/")]+"/static").replace("\\","/")), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)