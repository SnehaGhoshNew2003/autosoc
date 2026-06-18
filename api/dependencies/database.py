# api/dependencies/database.py
#
# FastAPI dependency injection for the shared DB client.
# Every router that needs DB access uses:
#
#     db: TimescaleClient = Depends(get_db)
#
# This pulls the single connection pool that was opened at startup,
# so there's no per-request connection overhead.

from fastapi import Request
from database.timescale_client import TimescaleClient


async def get_db(request: Request) -> TimescaleClient:
    """
    Return the shared TimescaleDB client from app state.
    The pool was opened in the lifespan handler in main.py.
    """
    return request.app.state.db