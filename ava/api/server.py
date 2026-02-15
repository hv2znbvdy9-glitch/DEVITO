"""REST API Server for AVA - SECURE VERSION (Devito Only)."""

from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import asyncio
from ava.core.engine import Engine
from ava.core.logging import logger
from ava.api.wellbeing import router as wellbeing_router, init_wellbeing_api
from ava.monitoring.metrics import MetricsCollector
from ava.security_middleware import apply_security_middleware
from ava.api.admin import admin_router, admin_page_router

# Data Models
class TaskCreate(BaseModel):
    """Create task request."""
    name: str
    description: Optional[str] = None

class TaskResponse(BaseModel):
    """Task response model."""
    id: str
    name: str
    description: Optional[str]
    completed: bool
    created_at: Optional[datetime]

class StatsResponse(BaseModel):
    """Statistics response."""
    total_tasks: int
    completed_tasks: int
    pending_tasks: int

# Initialize FastAPI
app = FastAPI(
    title="AVA Security System",
    description="AVA Wellbeing Platform - SECURE (Devito Only) 🔒🌟",
    version="3.0.0"
)

# ✅ SECURITY: Apply Security Middleware FIRST (before CORS)
apply_security_middleware(app)

# Enable CORS (restricted to localhost only)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "https://localhost:8443"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Limited methods
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

# Initialize metrics
metrics = MetricsCollector()

# Global engine
engine = Engine()
connected_clients: List[WebSocket] = []

# Include Routers
app.include_router(wellbeing_router)
app.include_router(admin_router)  # 🔒 Admin Console (Devito Only)
app.include_router(admin_page_router)

@app.on_event("startup")
async def startup_event():
    """Initialize AVA on startup."""
    logger.info("🚀 AVA API Server starting...")
    await init_wellbeing_api()
    logger.info("✅ Wellbeing API initialized")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("🛑 AVA API Server shutting down...")

# REST Endpoints
@app.get("/health")
async def health_check() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/tasks", response_model=TaskResponse)
async def create_task(task: TaskCreate) -> TaskResponse:
    """Create a new task."""
    try:
        created_task = engine.add_task(task.name, task.description)
        return TaskResponse(
            id=created_task.id,
            name=created_task.name,
            description=created_task.description,
            completed=created_task.completed,
            created_at=created_task.created_at
        )
    except Exception as e:
        logger.error(f"Error creating task: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/tasks", response_model=List[TaskResponse])
async def list_tasks(completed: Optional[bool] = None) -> List[TaskResponse]:
    """List all tasks."""
    tasks = engine.list_tasks(completed=completed)
    return [
        TaskResponse(
            id=t.id,
            name=t.name,
            description=t.description,
            completed=t.completed,
            created_at=t.created_at
        )
        for t in tasks
    ]

@app.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str) -> TaskResponse:
    """Get a specific task."""
    task = engine.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return TaskResponse(
        id=task.id,
        name=task.name,
        description=task.description,
        completed=task.completed,
        created_at=task.created_at
    )

@app.post("/tasks/{task_id}/complete")
async def complete_task(task_id: str) -> dict:
    """Mark a task as completed."""
    if engine.complete_task(task_id):
        return {"status": "completed", "task_id": task_id}
    raise HTTPException(status_code=404, detail="Task not found")

@app.get("/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """Get tasks statistics."""
    stats = engine.get_stats()
    return StatsResponse(
        total_tasks=stats["total_tasks"],
        completed_tasks=stats["completed_tasks"],
        pending_tasks=stats["pending_tasks"]
    )

# WebSocket for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await websocket.accept()
    connected_clients.append(websocket)
    logger.info(f"WebSocket client connected. Total: {len(connected_clients)}")
    
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_text(f"AVA received: {data}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        connected_clients.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(connected_clients)}")

async def broadcast_update(message: dict):
    """Broadcast update to all connected WebSocket clients."""
    for client in connected_clients:
        try:
            await client.send_json(message)
        except Exception as e:
            logger.error(f"Error broadcasting to client: {e}")

# Prometheus Metrics Endpoint
@app.get("/metrics")
async def get_metrics() -> str:
    """Get Prometheus metrics.
    
    Returns:
        Metrics in Prometheus format
    """
    from ava.monitoring.metrics import WellbeingMetrics
    
    wellbeing_metrics = WellbeingMetrics()
    return wellbeing_metrics.export_prometheus_format()


# Extended Stats with Wellbeing
@app.get("/stats/extended")
async def get_extended_stats() -> dict:
    """Get extended statistics including wellbeing.
    
    Returns:
        Extended stats dictionary
    """
    from ava.monitoring.metrics import WellbeingMetrics
    
    stats = engine.get_stats()
    wellbeing_metrics = WellbeingMetrics()
    
    return {
        "task_stats": {
            "total_tasks": stats["total_tasks"],
            "completed_tasks": stats["completed_tasks"],
            "pending_tasks": stats["pending_tasks"],
        },
        "wellbeing_metrics": wellbeing_metrics.get_wellbeing_metrics_summary(),
        "timestamp": datetime.now().isoformat()
    }