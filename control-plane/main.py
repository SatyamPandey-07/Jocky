"""Main entrypoint for JOCKY Control Plane server.

Runs FastAPI with:
- REST API (/api/...)
- WebSockets (/ws/...)
- Dashboard UI mounted at / and /dashboard
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

try:
    from .routes import router as api_router
except ImportError:
    from routes import router as api_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [control-plane] %(message)s")
logger = logging.getLogger("control-plane")

app = FastAPI(
    title="JOCKY Control Plane",
    description="Cross-Platform Declarative Forensic Framework Central Orchestrator",
    version="0.1.0",
)

# Enable CORS for API & Dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router)

DASHBOARD_DIR = Path("dashboard")


# --- WebSocket Hub for Real-time Telemetry & Agents ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


ws_manager = ConnectionManager()


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Echo or process incoming agent telemetry
            await ws_manager.broadcast({"type": "telemetry", "payload": data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# --- Dashboard Static & HTML Routes ---
@app.get("/", response_class=HTMLResponse)
async def serve_root():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>JOCKY Control Plane Running</h1><p>Dashboard not found.</p>")


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>JOCKY Dashboard</h1>")


def run(host: str = "0.0.0.0", port: int = 8000):
    logger.info(f"Starting JOCKY Control Plane on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JOCKY Control Plane")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    args = parser.parse_args()
    run(args.host, args.port)
