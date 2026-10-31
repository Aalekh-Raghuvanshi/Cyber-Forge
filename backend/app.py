"""
LLM Code Analyzer - FastAPI Application

A security-focused code analysis tool that combines LLM intelligence
with static analysis to identify vulnerabilities and suggest fixes.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from typing import Dict, Any
import os

from backend.routes.analyze import router as analyze_router
from backend.utils.rate_limit import setup_rate_limiting, limiter
from backend.utils.logger import get_logger, set_correlation_id, get_correlation_id
from backend.config import settings

logger = get_logger("app")


def extract_client_info(request: Request) -> Dict[str, Any]:
    """Extract client information for logging."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    return {
        "client_ip": client_ip,
        "user_agent": user_agent
    }

# Lifespan event handler (replaces deprecated on_event)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
    logger.info(
        "Starting LLM Code Analyser",
        llm_mode=settings.llm_mode,
        host=settings.host,
        port=settings.port
    )
    
    print(f"🚀 LLM Code Analyser starting...")
    print(f"📊 Mode: {settings.llm_mode}")
    if settings.llm_mode == "openai":
        print(f"🤖 Model: {settings.openai_model}")
    elif settings.llm_mode == "gemini":
        print(f"🤖 Model: {settings.gemini_model}")
    else:
        print(f"🤖 Model: {settings.ollama_model}")
    
    print(f"📖 API docs available at: http://{settings.host}:{settings.port}/docs")
    if os.path.exists(frontend_dist):
        print(f"🎨 Frontend available at: http://{settings.host}:{settings.port}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down LLM Code Analyser")
    print("👋 LLM Code Analyser shutting down...")

# Create FastAPI application
app = FastAPI(
    title="LLM Code Analyser",
    description="AI-powered code security analysis tool",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(analyze_router, prefix="/api", tags=["analysis"])

# Setup rate limiting
limiter = setup_rate_limiting(app)

# Check for built React frontend
frontend_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
frontend_assets = os.path.join(frontend_dist, "assets")

if os.path.exists(frontend_dist):
    # Serve static assets from React build
    if os.path.exists(frontend_assets):
        app.mount("/assets", StaticFiles(directory=frontend_assets), name="assets")
    
    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        """Serve React SPA - all routes go to index.html"""
        # Don't serve API routes or docs
        if full_path.startswith("api/") or full_path in ["docs", "redoc", "openapi.json"]:
            return None
        
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        
        # Fallback to index.html for SPA routing
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    async def root():
        """Return API info when frontend is not built."""
        return {
            "name": "LLM Code Analyser API",
            "version": "1.0.0",
            "docs": "/docs",
            "health": "/api/health",
            "note": "Run 'npm run build' in frontend/ to enable the web UI"
        }


# Startup logic moved to lifespan context manager above

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.app:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
