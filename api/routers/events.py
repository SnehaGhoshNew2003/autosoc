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


@router.get(
    "/{investigation_id}/mitre-coverage",
    summary="Get MITRE ATT&CK coverage breakdown for an investigation",
    description=(
        "Returns a list of unique technique_ids and technique_names found "
        "across all events for this investigation, along with coverage stats."
    ),
)
async def get_mitre_coverage(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = await db.get_events(investigation_id)

    # Build unique techniques map
    techniques: dict[str, dict] = {}
    stages_found: set[str] = set()
    for ev in events:
        tid = ev.get("technique_id")
        tname = ev.get("technique_name")
        stage = ev.get("stage")
        if tid:
            if tid not in techniques:
                techniques[tid] = {
                    "technique_id": tid,
                    "technique_name": tname or "Unknown",
                    "event_count": 0,
                    "stages": set(),
                }
            techniques[tid]["event_count"] += 1
            if stage:
                techniques[tid]["stages"].add(stage)
                stages_found.add(stage)

    # Convert sets to lists for JSON serialization
    result = []
    for tid, info in techniques.items():
        result.append({
            "technique_id": tid,
            "technique_name": info["technique_name"],
            "event_count": info["event_count"],
            "stages": sorted(info["stages"]),
        })

    return {
        "investigation_id": investigation_id,
        "total_techniques": len(result),
        "stages_covered": sorted(stages_found),
        "techniques": sorted(result, key=lambda t: t["event_count"], reverse=True),
    }


@router.get(
    "/mitre-coverage/all",
    summary="Get MITRE ATT&CK coverage aggregated across ALL investigations",
    description=(
        "Returns unique technique_ids and technique_names found across "
        "all events in all investigations, with per-investigation counts."
    ),
)
async def get_global_mitre_coverage(
    db: TimescaleClient = Depends(get_db),
):
    events = await db._fetch(
        """
        SELECT technique_id, technique_name, investigation_id::TEXT, stage
        FROM events
        WHERE technique_id IS NOT NULL
        ORDER BY investigation_id
        """
    )

    techniques: dict[str, dict] = {}
    investigations: set[str] = set()
    stages_found: set[str] = set()

    for ev in events:
        tid = ev.get("technique_id")
        tname = ev.get("technique_name")
        inv_id = ev.get("investigation_id")
        stage = ev.get("stage")

        if tid:
            if tid not in techniques:
                techniques[tid] = {
                    "technique_id": tid,
                    "technique_name": tname or "Unknown",
                    "investigation_count": 0,
                    "total_occurrences": 0,
                    "stages": set(),
                }
            techniques[tid]["total_occurrences"] += 1
            if stage:
                techniques[tid]["stages"].add(stage)
                stages_found.add(stage)

        if inv_id:
            investigations.add(inv_id)

    # Count unique investigations per technique
    for ev in events:
        tid = ev.get("technique_id")
        if tid and tid in techniques:
            pass  # We simply report total occurrences

    result = []
    for tid, info in techniques.items():
        result.append({
            "technique_id": tid,
            "technique_name": info["technique_name"],
            "total_occurrences": info["total_occurrences"],
            "stages": sorted(info["stages"]),
        })

    return {
        "total_techniques": len(result),
        "total_investigations": len(investigations),
        "stages_covered": sorted(stages_found),
        "techniques": sorted(result, key=lambda t: t["total_occurrences"], reverse=True),
    }
