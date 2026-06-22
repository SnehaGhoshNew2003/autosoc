import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from api.dependencies.database import get_db
from api.models.schemas import (
    IOCHistoryResponse,
    IOCHistoryItem,
    IOCItem,
    IOCListResponse,
    IOCSearchRequest,
)
from database.timescale_client import TimescaleClient

router = APIRouter()
logger = logging.getLogger(__name__)

_VALID_IOC_TYPES = {
    "ip", "domain", "hash", "url", "file_path",
    "mutex", "email", "registry_key", "unknown",
}


@router.get(
    "/all",
    response_model=IOCListResponse,
    summary="Get ALL IOCs across all investigations and all types",
    description=(
        "Returns every IOC regardless of type. "
        "Used by the IOC Library 'All' tab."
    ),
)
async def get_all_iocs(
    limit: int = Query(default=500, ge=1, le=5000),
    db: TimescaleClient = Depends(get_db),
):
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
    total_row = await db._fetchrow("SELECT COUNT(*)::TEXT AS total FROM iocs")
    total = int(total_row["total"]) if total_row else 0
    items = [IOCItem(**r) for r in rows]
    return IOCListResponse(iocs=items, total=total)


@router.get(
    "/all/type/{ioc_type}",
    response_model=IOCListResponse,
    summary="Get all IOCs of a given type across ALL investigations",
    description=(
        "Returns every IOC of the specified type across all investigations. "
        "Useful for threat hunting: 'show me all IPs we've ever seen'."
    ),
)
async def get_all_iocs_by_type(
    ioc_type: str,
    limit: int = Query(default=100, ge=1, le=1000),
    db: TimescaleClient = Depends(get_db),
):
    if ioc_type not in _VALID_IOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IOC type '{ioc_type}'. Valid: {sorted(_VALID_IOC_TYPES)}",
        )
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
    total_row = await db._fetchrow(
        "SELECT COUNT(*)::TEXT AS total FROM iocs WHERE ioc_type = $1",
        ioc_type,
    )
    total = int(total_row["total"]) if total_row else 0
    items = [IOCItem(**r) for r in rows]
    return IOCListResponse(iocs=items, total=total)


@router.get(
    "/{investigation_id}",
    response_model=IOCListResponse,
    summary="Get IOCs for an investigation",
)
async def get_iocs(
    investigation_id: str,
    db: TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    iocs = await db.get_iocs(investigation_id)
    items = [IOCItem(**ioc) for ioc in iocs]
    return IOCListResponse(iocs=items, total=len(items))


@router.get(
    "/{investigation_id}/type/{ioc_type}",
    response_model=IOCListResponse,
    summary="Get IOCs filtered by type",
)
async def get_iocs_by_type(
    investigation_id: str,
    ioc_type: str,
    db: TimescaleClient = Depends(get_db),
):
    if ioc_type not in _VALID_IOC_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid IOC type '{ioc_type}'. Valid: {sorted(_VALID_IOC_TYPES)}",
        )
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    iocs = await db.get_iocs(investigation_id, ioc_type=ioc_type)
    items = [IOCItem(**ioc) for ioc in iocs]
    return IOCListResponse(iocs=items, total=len(items))


@router.post(
    "/search",
    response_model=IOCHistoryResponse,
    summary="Search for a specific IOC value across all investigations",
    description=(
        "Pass the exact IOC value (e.g. '103.77.192.88' or 'evil.com'). "
        "Returns every investigation where this value was seen."
    ),
)
async def search_ioc(
    request: IOCSearchRequest,
    db: TimescaleClient = Depends(get_db),
):
    results = await db.search_ioc_history(request.value)
    items = [IOCHistoryItem(**r) for r in results]
    return IOCHistoryResponse(value=request.value, occurrences=items, total=len(items))
