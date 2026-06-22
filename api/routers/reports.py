import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from api.dependencies.database import get_db
from api.models.schemas import DebateVerdictResponse, ReportResponse
from database.timescale_client import TimescaleClient

router = APIRouter()


@router.get(
    "/{investigation_id}",
    response_model=ReportResponse,
    summary="Get structured incident report",
)
async def get_report(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns the full structured incident report from the ReportGenerator agent,
    including executive summary, technical findings, IOCs, and remediation plan.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    runs = await db.get_agent_runs(investigation_id)
    report_run = next(
        (r for r in runs if r["agent_name"] == "ReportGenerator" and r["status"] == "complete"),
        None,
    )

    if not report_run or not report_run.get("result_json"):
        raise HTTPException(
            status_code=404,
            detail="Report not yet generated. Check /pipeline/{id}/status.",
        )

    result = report_run["result_json"]
    if isinstance(result, str):
        result = json.loads(result)

    return ReportResponse(
        investigation_id=investigation_id,
        formatted_markdown=result.get("formatted_markdown", ""),
        executive_summary=result.get("executive_summary"),
        technical_findings=result.get("technical_findings"),
        consolidated_iocs=result.get("consolidated_iocs"),
        remediation_plan=result.get("remediation_plan"),
    )


@router.get(
    "/{investigation_id}/markdown",
    response_class=PlainTextResponse,
    summary="Get raw markdown report",
    description="Returns the formatted_markdown field as plain text. "
                "Useful for rendering directly in a frontend.",
)
async def get_report_markdown(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    runs = await db.get_agent_runs(investigation_id)
    report_run = next(
        (r for r in runs if r["agent_name"] == "ReportGenerator" and r["status"] == "complete"),
        None,
    )

    if not report_run or not report_run.get("result_json"):
        raise HTTPException(status_code=404, detail="Report not yet generated.")

    result = report_run["result_json"]
    if isinstance(result, str):
        result = json.loads(result)

    md = result.get("formatted_markdown", "")
    if not md:
        raise HTTPException(status_code=404, detail="No markdown content in report.")

    return PlainTextResponse(content=md, media_type="text/markdown")


@router.get(
    "/{investigation_id}/verdict",
    response_model=DebateVerdictResponse,
    summary="Get multi-agent debate verdict",
)
async def get_verdict(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns the final verdict from the Red/Blue Team debate:
    verdict string, confidence score, and both teams' arguments.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    verdict = await db.get_debate_verdict(investigation_id)
    if not verdict:
        raise HTTPException(
            status_code=404,
            detail="Verdict not yet available. Check /pipeline/{id}/status.",
        )

    def _parse_list(val):
        if isinstance(val, str):
            try:
                return json.loads(val)
            except Exception:
                return []
        return val or []

    return DebateVerdictResponse(
        investigation_id=investigation_id,
        final_verdict=verdict.get("final_verdict"),
        confidence_score=verdict.get("confidence_score"),
        executive_summary=verdict.get("executive_summary"),
        red_team_evidence=_parse_list(verdict.get("red_team_evidence")),
        blue_team_evidence=_parse_list(verdict.get("blue_team_evidence")),
        created_at=verdict.get("created_at"),
    )