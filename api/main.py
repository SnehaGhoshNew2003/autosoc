import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.error_middleware import ErrorHandlerMiddleware
from api.routers import (
    investigations,
    pipeline,
    iocs,
    events,
    reports,
    graph,
    health,
)
from database.timescale_client import TimescaleClient
from api.routers import database

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

db: TimescaleClient = TimescaleClient()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: open DB pool and create schema.
    Shutdown: close DB pool gracefully.
    """
    logger.info("[AutoSOC] Starting up...")
    await db.connect()
    await db.create_schema()
    app.state.db = db
    logger.info("[AutoSOC] Database ready")
    yield
    logger.info("[AutoSOC] Shutting down...")
    await db.close()
    logger.info("[AutoSOC] Database closed")

app = FastAPI(
    title="AutoSOC API",
    description=(
        "AI-powered cybersecurity investigation pipeline. "
        "Submit evidence, run multi-agent analysis, retrieve results."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(LoggingMiddleware)
app.add_middleware(ErrorHandlerMiddleware)
app.include_router(health.router,          tags=["Health"])
app.include_router(pipeline.router,        prefix="/api/v1/pipeline",         tags=["Pipeline"])
app.include_router(investigations.router,  prefix="/api/v1/investigations",   tags=["Investigations"])
app.include_router(iocs.router,            prefix="/api/v1/iocs",             tags=["IOCs"])
app.include_router(events.router,          prefix="/api/v1/events",           tags=["Events"])
app.include_router(reports.router,         prefix="/api/v1/reports",          tags=["Reports"])
app.include_router(graph.router,           prefix="/api/v1/graph",            tags=["Graph"])
app.include_router(database.router,        prefix="/api/v1/database",         tags=["Database"])