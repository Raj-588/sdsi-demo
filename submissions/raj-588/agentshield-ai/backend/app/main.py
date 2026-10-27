"""FastAPI application entrypoint for AgentShield AI — IntentLock."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from app.api.routes import router
from app.core.config import get_settings
from app.db.init_db import init_db

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)

settings = get_settings()

REACT_INDEX = Path(__file__).resolve().parent.parent.parent / "frontend-react" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Idempotent: create tables + seed reference data on boot.
    init_db()
    yield


app = FastAPI(title=settings.app_name, version=settings.app_version, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl is not None and int(cl) > settings.max_request_bytes:
        return JSONResponse(status_code=413, content={"detail": "request too large"})
    return await call_next(request)


@app.get("/")
def root(request: Request):
    format_param = request.query_params.get("format")
    accept = request.headers.get("accept", "")

    # Only return JSON if explicitly asked for or if it's an API client specifying application/json
    if format_param == "json" or ("application/json" in accept and "text/html" not in accept):
        return {
            "status": "online",
            "app": settings.app_name,
            "version": settings.app_version,
            "demo_mode": settings.demo_mode,
            "ui": "http://localhost:8000/",
            "streamlit_dashboard": "http://localhost:8501",
            "docs": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "api_v1": "/api/v1",
        }

    if REACT_INDEX.exists():
        return FileResponse(REACT_INDEX)

    return {
        "status": "online",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/app")
def app_ui():
    if REACT_INDEX.exists():
        return FileResponse(REACT_INDEX)
    return HTMLResponse("<h1>React UI not found</h1>", status_code=404)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": settings.app_version,
        "demo_mode": settings.demo_mode,
    }


app.include_router(router)
