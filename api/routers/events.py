# api/routers/events.py
#
# GET /api/v1/events/{investigation_id}               — all kill-chain events
# GET /api/v1/events/{investigation_id}/stage/{stage} — filter by kill-chain stage

from fastapi import APIRouter, Depends, HTTPException
from api.dependencies.database import get_db
from api.models.schemas import EventListResponse, KillChainEventItem
from database.timescale_client import TimescaleClient

router = APIRouter()

_VALID_STAGES = {
    "reconnaissance", "weaponization", "delivery", "exploitation",
    "installation", "command_and_control", "exfiltration",
    "persistence", "unknown",
}


@router.get(
    "/{investigation_id}",
    response_model=EventListResponse,
    summary="Get all kill-chain events for an investigation",
)
async def get_events(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns all kill-chain events ordered by event_time ascending.
    Each event includes stage, technique, description, and involved IOCs.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = await db.get_events(investigation_id)
    items = [KillChainEventItem(**ev) for ev in events]
    return EventListResponse(events=items, total=len(items))


@router.get(
    "/{investigation_id}/stage/{stage}",
    response_model=EventListResponse,
    summary="Get events filtered by kill-chain stage",
)
async def get_events_by_stage(
    investigation_id: str,
    stage:            str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Filter events by kill-chain stage.
    Valid stages: reconnaissance, weaponization, delivery, exploitation,
    installation, command_and_control, exfiltration, persistence.
    """
    if stage not in _VALID_STAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid stage '{stage}'. Valid: {sorted(_VALID_STAGES)}",
        )

    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = await db.get_events(investigation_id, stage=stage)
    items = [KillChainEventItem(**ev) for ev in events]
    return EventListResponse(events=items, total=len(items))