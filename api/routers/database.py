import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from api.dependencies.database import get_db
from api.models.schemas import StatusResponse
from database.timescale_client import TimescaleClient

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get(
    "/stats",
    summary="Row counts for every table",
    description="Returns the number of rows in each TimescaleDB table.",
)
async def get_db_stats(db: TimescaleClient = Depends(get_db)):
    tables = [
        "investigations",
        "agent_runs",
        "events",
        "iocs",
        "debate_verdicts",
    ]
    stats = {}
    for table in tables:
        result = await db._fetch(f"SELECT COUNT(*) AS count FROM {table}")
        stats[table] = result[0]["count"] if result else 0
    return {"table_counts": stats}


@router.get(
    "/investigations",
    summary="List all investigations (raw DB rows)",
)
async def list_all_investigations_raw(
    limit:  int = Query(default=50, ge=1, le=500),
    db:     TimescaleClient = Depends(get_db),
):
    rows = await db._fetch(
        """
        SELECT id::TEXT, created_at, status, severity,
               verdict, confidence, input_summary, narrative
        FROM investigations
        ORDER BY created_at DESC
        LIMIT $1
        """,
        limit,
    )
    return {"investigations": rows, "total": len(rows)}


@router.get(
    "/agent-runs/{investigation_id}",
    summary="Get all agent runs for an investigation (raw DB rows)",
)
async def get_agent_runs_raw(
    investigation_id: str,
    include_results:  bool = Query(
        default=False,
        description="Include full result_json in response (can be large)"
    ),
    db: TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if include_results:
        rows = await db._fetch(
            """
            SELECT id::TEXT, investigation_id::TEXT, agent_name,
                   status, duration_ms, error_message, ran_at, result_json
            FROM agent_runs
            WHERE investigation_id = $1::UUID
            ORDER BY ran_at ASC
            """,
            investigation_id,
        )
    else:
        rows = await db._fetch(
            """
            SELECT id::TEXT, investigation_id::TEXT, agent_name,
                   status, duration_ms, error_message, ran_at
            FROM agent_runs
            WHERE investigation_id = $1::UUID
            ORDER BY ran_at ASC
            """,
            investigation_id,
        )
    return {"agent_runs": rows, "total": len(rows)}


@router.get(
    "/agent-runs/{investigation_id}/{agent_name}",
    summary="Get result_json for a specific agent run",
)
async def get_agent_result_raw(
    investigation_id: str,
    agent_name:       str,
    db:               TimescaleClient = Depends(get_db),
):
    rows = await db._fetch(
        """
        SELECT id::TEXT, investigation_id::TEXT, agent_name,
               status, duration_ms, error_message, ran_at, result_json
        FROM agent_runs
        WHERE investigation_id = $1::UUID
          AND agent_name = $2
        ORDER BY ran_at DESC
        LIMIT 1
        """,
        investigation_id, agent_name,
    )
    if not rows:
        raise HTTPException(
            status_code=404,
            detail=f"No run found for agent '{agent_name}' in investigation {investigation_id}",
        )
    return rows[0]


@router.get(
    "/events/{investigation_id}",
    summary="Get all events for an investigation (raw DB rows)",
)
async def get_events_raw(
    investigation_id: str,
    stage:            Optional[str] = Query(default=None),
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    events = await db.get_events(investigation_id, stage=stage)
    return {"events": events, "total": len(events)}


@router.get(
    "/iocs/{investigation_id}",
    summary="Get all IOCs for an investigation (raw DB rows)",
)
async def get_iocs_raw(
    investigation_id: str,
    ioc_type:         Optional[str] = Query(default=None),
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    iocs = await db.get_iocs(investigation_id, ioc_type=ioc_type)
    return {"iocs": iocs, "total": len(iocs)}


@router.get(
    "/iocs/all",
    summary="Get ALL IOCs across all investigations",
)
async def get_all_iocs_raw(
    ioc_type: Optional[str] = Query(default=None),
    limit:    int           = Query(default=200, ge=1, le=2000),
    db:       TimescaleClient = Depends(get_db),
):
    if ioc_type:
        rows = await db._fetch(
            """
            SELECT id::TEXT, investigation_id::TEXT, ioc_type,
                   value, source_agent, context, first_seen
            FROM iocs
            WHERE ioc_type = $1
            ORDER BY first_seen DESC
            LIMIT $2
            """,
            ioc_type, limit,
        )
    else:
        rows = await db._fetch(
            """
            SELECT id::TEXT, investigation_id::TEXT, ioc_type,
                   value, source_agent, context, first_seen
            FROM iocs
            ORDER BY first_seen DESC
            LIMIT $1
            """,
            limit,
        )
    return {"iocs": rows, "total": len(rows)}


@router.get(
    "/verdicts/{investigation_id}",
    summary="Get debate verdict for an investigation (raw DB row)",
)
async def get_verdict_raw(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    verdict = await db.get_debate_verdict(investigation_id)
    if not verdict:
        raise HTTPException(status_code=404, detail="No verdict found")
    return verdict


@router.delete(
    "/investigations/{investigation_id}",
    response_model=StatusResponse,
    summary="Hard delete an investigation and all its data",
)
async def delete_investigation(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    await db._execute(
        "DELETE FROM investigations WHERE id = $1::UUID",
        investigation_id,
    )
    logger.warning(f"[Database] Investigation {investigation_id} deleted")
    return StatusResponse(
        status="deleted",
        message=f"Investigation {investigation_id} and all associated data deleted.",
    )


@router.delete(
    "/clear",
    response_model=StatusResponse,
    summary="DANGER: Wipe ALL data from all tables",
    description=(
        "Deletes every row from investigations, agent_runs, events, iocs, "
        "and debate_verdicts. This is irreversible. "
        "Pass confirm=true as a query parameter to execute."
    ),
)
async def clear_all_data(
    confirm: bool = Query(default=False),
    db:      TimescaleClient = Depends(get_db),
):
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Pass ?confirm=true to confirm deletion of all data.",
        )

    await db._execute("DELETE FROM debate_verdicts")
    await db._execute("DELETE FROM iocs")
    await db._execute("DELETE FROM events")
    await db._execute("DELETE FROM agent_runs")
    await db._execute("DELETE FROM investigations")

    logger.warning("[Database] ALL data wiped from TimescaleDB")
    return StatusResponse(
        status="cleared",
        message="All TimescaleDB data deleted.",
    )