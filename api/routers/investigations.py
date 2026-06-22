import json
import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from api.dependencies.database import get_db
from api.models.schemas import (
    InvestigationDetail,
    InvestigationListResponse,
    InvestigationSummary,
    StatusResponse,
)
from database.timescale_client import TimescaleClient

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "",
    response_model=InvestigationListResponse,
    summary="List all investigations",
)
async def list_investigations(
    limit:  int               = Query(default=20, ge=1, le=100),
    db:     TimescaleClient   = Depends(get_db),
):
    """
    Returns the most recent investigations ordered by creation time.
    Use `limit` to control how many are returned (max 100).
    """
    investigations = await db.list_investigations(limit=limit)
    items = [InvestigationSummary(**inv) for inv in investigations]
    return InvestigationListResponse(investigations=items, total=len(items))


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetail,
    summary="Get full investigation detail",
)
async def get_investigation(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns everything about an investigation:
    metadata, all agent run results, kill-chain events, IOCs, and debate verdict.
    """
    full = await db.get_full_investigation(investigation_id)
    if not full["investigation"]:
        raise HTTPException(status_code=404, detail="Investigation not found")

    inv = full["investigation"]
    return InvestigationDetail(
        id=inv["id"],
        created_at=inv["created_at"],
        status=inv["status"],
        severity=inv.get("severity"),
        verdict=inv.get("verdict"),
        confidence=inv.get("confidence"),
        input_summary=inv.get("input_summary"),
        narrative=inv.get("narrative"),
        agent_runs=[
            {
                **{k: v for k, v in r.items() if k != "result_json"},
                "output": json.loads(r["result_json"]) if isinstance(r.get("result_json"), str) else r.get("result_json")
            }
            for r in full["agent_runs"]
            if r["agent_name"] != "raw_input"
        ],
        events=full["events"],
        iocs=full["iocs"],
        verdict_detail=full["verdict"],
    )


@router.delete(
    "/{investigation_id}",
    response_model=StatusResponse,
    summary="Delete an investigation",
)
async def delete_investigation(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Deletes an investigation and all associated data (CASCADE).
    This is irreversible.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    await db._execute(
        "DELETE FROM investigations WHERE id = $1::UUID",
        investigation_id,
    )
    return StatusResponse(
        status="deleted",
        message=f"Investigation {investigation_id} deleted.",
    )