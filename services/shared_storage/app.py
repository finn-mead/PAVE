import json
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Global storage (in-memory for demo)
shared_storage: Dict[str, Any] = {}

class StorageRequest(BaseModel):
    value: Optional[str] = None

class StorageResponse(BaseModel):
    key: str
    value: Optional[str] = None
    exists: bool

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info(json.dumps({
        "event": "shared_storage.start",
        "port": 8004
    }))
    yield
    # Shutdown (nothing needed)

app = FastAPI(title="PAVE Shared Storage Service", lifespan=lifespan)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:9001", "http://localhost:9002"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False
)

@app.get("/storage/{key}")
async def get_value(key: str):
    """Get a value from shared storage"""
    value = shared_storage.get(key)
    exists = key in shared_storage
    
    logger.info(json.dumps({
        "event": "shared_storage.get",
        "key": key,
        "exists": exists
    }))
    
    return StorageResponse(
        key=key,
        value=value,
        exists=exists
    )

@app.post("/storage/{key}")
async def set_value(key: str, request: StorageRequest):
    """Set a value in shared storage"""
    shared_storage[key] = request.value
    
    logger.info(json.dumps({
        "event": "shared_storage.set",
        "key": key,
        "has_value": request.value is not None
    }))
    
    return StorageResponse(
        key=key,
        value=request.value,
        exists=True
    )

@app.put("/storage/{key}")
async def put_value(key: str, request: StorageRequest):
    """Set a value in shared storage (alternative endpoint)"""
    shared_storage[key] = request.value
    
    logger.info(json.dumps({
        "event": "shared_storage.put",
        "key": key,
        "has_value": request.value is not None
    }))
    
    return StorageResponse(
        key=key,
        value=request.value,
        exists=True
    )

@app.delete("/storage/{key}")
async def delete_value(key: str):
    """Delete a value from shared storage"""
    exists = key in shared_storage
    if exists:
        del shared_storage[key]
    
    logger.info(json.dumps({
        "event": "shared_storage.delete",
        "key": key,
        "existed": exists
    }))
    
    return StorageResponse(
        key=key,
        value=None,
        exists=False
    )

@app.get("/storage")
async def list_keys():
    """List all keys in shared storage"""
    keys = list(shared_storage.keys())
    
    logger.info(json.dumps({
        "event": "shared_storage.list",
        "count": len(keys)
    }))
    
    return {"keys": keys}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)
