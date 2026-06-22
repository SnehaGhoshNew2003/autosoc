
from fastapi import APIRouter, Depends
from api.models.schemas import HealthResponse
from api.dependencies.database import get_db
from database.timescale_client import TimescaleClient

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
async def health():
    """Returns 200 if the API process is alive."""
    return HealthResponse(status="ok", database="unknown")


@router.get("/health/ready", response_model=HealthResponse, summary="Readiness probe")
async def readiness(db: TimescaleClient = Depends(get_db)):
    """Returns 200 if the API can reach the database."""
    try:
        await db.list_investigations(limit=1)
        db_status = "ok"
    except Exception as e:
        db_status = f"error: {e}"
    return HealthResponse(
        status="ok" if db_status == "ok" else "degraded",
        database=db_status,
    )