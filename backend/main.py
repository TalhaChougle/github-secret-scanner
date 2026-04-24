"""
GitHub Secret History Scanner — FastAPI Backend
"""

import json
import asyncio
import os
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from scanner import scan_repository, parse_repo
from patterns import PATTERNS, SEVERITY_ORDER

def load_env():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())

load_env()

DEFAULT_TOKEN = os.environ.get("GITHUB_TOKEN", None)

app = FastAPI(title="GitHub Secret Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "version": "1.0.0",
        "token_configured": DEFAULT_TOKEN is not None,
    }

@app.get("/api/patterns")
async def list_patterns():
    return [
        {
            "id": p["id"],
            "name": p["name"],
            "severity": p["severity"],
            "category": p["category"],
            "remediation": p["remediation"],
        }
        for p in PATTERNS
    ]

@app.get("/api/scan")
async def scan(
    repo: str = Query(...),
    token: str = Query(None),
    max_commits: int = Query(50, ge=1, le=500),
    deep: bool = Query(True),
):
    parsed = parse_repo(repo)
    if not parsed:
        raise HTTPException(status_code=400, detail="Invalid repository format.")

    owner, repo_name = parsed
    effective_token = token or DEFAULT_TOKEN

    async def event_generator():
        try:
            if effective_token:
                source = "provided token" if token else ".env file"
                yield f"data: {json.dumps({'type': 'progress', 'message': f'Token loaded from {source} — 5000 req/hr', 'percent': 2})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'progress', 'message': 'No token — add GITHUB_TOKEN to backend/.env to remove limit', 'percent': 2})}\n\n"

            async for event in scan_repository(
                owner=owner,
                repo=repo_name,
                token=effective_token,
                max_commits=max_commits,
                scan_all_history=deep,
            ):
                data = json.dumps(event)
                yield f"data: {data}\n\n"
                await asyncio.sleep(0)
        except Exception as e:
            error_event = json.dumps({"type": "error", "message": str(e)})
            yield f"data: {error_event}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

@app.post("/api/scan/text")
async def scan_text(request: Request):
    body = await request.json()
    content = body.get("content", "")
    filename = body.get("filename", "pasted_content")
    from patterns import scan_content
    findings = scan_content(content, filename)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    return {"findings": findings, "count": len(findings)}

@app.get("/api/stats")
async def stats():
    return {
        "total_patterns": len(PATTERNS),
        "token_configured": DEFAULT_TOKEN is not None,
        "categories": list({p["category"] for p in PATTERNS}),
        "severities": {
            "CRITICAL": sum(1 for p in PATTERNS if p["severity"] == "CRITICAL"),
            "HIGH": sum(1 for p in PATTERNS if p["severity"] == "HIGH"),
            "MEDIUM": sum(1 for p in PATTERNS if p["severity"] == "MEDIUM"),
            "LOW": sum(1 for p in PATTERNS if p["severity"] == "LOW"),
        }
    }

frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")