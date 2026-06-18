# api/routers/pipeline.py
#
# POST /api/v1/pipeline/run      — start a full investigation (async background)
# POST /api/v1/pipeline/run/sync — start and wait for result (blocking, for testing)
# GET  /api/v1/pipeline/{id}/status — poll investigation status
# POST /api/v1/pipeline/{id}/rerun  — rerun a previous investigation

import asyncio
import logging
import time
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from api.dependencies.database import get_db
from api.models.schemas import (
    PipelineRequest,
    PipelineStartResponse,
    PipelineStatusResponse,
    StatusResponse,
)
from database.timescale_client import TimescaleClient

# Import the full pipeline runner
from agents.log_correlation_agent   import LogCorrelationAgent
from agents.threat_intel_agent      import ThreatIntelAgent
from agents.malware_analysis_agent  import MalwareAnalysisAgent
from agents.timeline_reconstruction import TimelineReconstructionAgent
from agents.report_generator_agent  import ReportGeneratorAgent
from agents.multi_agent_debate      import MultiAgentDebate
from agents.summarizer_agent        import SummarizerAgent
from graph.attack_graph_builder     import AttackGraphBuilder
from graph.neo4j_client             import Neo4jClient

router = APIRouter()
logger = logging.getLogger(__name__)


# ── Internal pipeline runner ──────────────────────────────────── #

async def _run_full_pipeline(inv_id: str, inputs: dict, db: TimescaleClient):
    """
    Full pipeline execution.
    Called either directly (sync endpoint) or via BackgroundTasks (async endpoint).
    """
    try:
        # ── L1: Log Correlation ── #
        log_run_id = await db.start_agent_run(inv_id, "LogCorrelation")
        t = time.monotonic()
        log_result = await LogCorrelationAgent().run(inputs["log_sources"])
        await db.finish_agent_run(log_run_id, log_result, int((time.monotonic()-t)*1000))
        await db.save_iocs(inv_id, {"log": log_result})
        await asyncio.sleep(5)

        # ── L1: Threat Intel ── #
        intel_run_id = await db.start_agent_run(inv_id, "ThreatIntel")
        t = time.monotonic()
        intel_result = await ThreatIntelAgent().run(inputs["threat_evidence"])
        await db.finish_agent_run(intel_run_id, intel_result, int((time.monotonic()-t)*1000))
        await db.save_iocs(inv_id, {"threat_intel": intel_result})
        await asyncio.sleep(5)

        # ── L1: Malware Analysis ── #
        malware_run_id = await db.start_agent_run(inv_id, "MalwareAnalysis")
        t = time.monotonic()
        malware_result = await MalwareAnalysisAgent().run(inputs["malware_evidence"])
        await db.finish_agent_run(malware_run_id, malware_result, int((time.monotonic()-t)*1000))
        await db.save_iocs(inv_id, {"malware": malware_result})

        await asyncio.sleep(15)

        # ── L2: Timeline Reconstruction ── #
        tl_run_id = await db.start_agent_run(inv_id, "TimelineReconstruction")
        t = time.monotonic()
        timeline_result = await TimelineReconstructionAgent().run(
            log_correlation_result=log_result,
            threat_intel_result=intel_result,
        )
        await db.finish_agent_run(tl_run_id, timeline_result, int((time.monotonic()-t)*1000))
        await db.save_events(inv_id, timeline_result)
        await db.save_iocs(inv_id, {"timeline": timeline_result})

        # ── Attack Graph (Neo4j) ── #
        try:
            neo4j = Neo4jClient()
            neo4j.create_constraints()
            AttackGraphBuilder(neo4j).build_from_agents(
                threat_intel=intel_result,
                malware=malware_result,
                timeline=timeline_result,
            )
            neo4j.close()
        except Exception as e:
            logger.warning(f"[Pipeline] AttackGraph failed (non-fatal): {e}")

        await asyncio.sleep(15)

        # ── Debate ── #
        debate_run_id = await db.start_agent_run(inv_id, "MultiAgentDebate")
        t = time.monotonic()
        debate_result = await MultiAgentDebate().run(
            log_data=log_result,
            intel_data=intel_result,
            malware_data=malware_result,
            timeline_data=timeline_result,
        )
        await db.finish_agent_run(debate_run_id, debate_result, int((time.monotonic()-t)*1000))
        await db.save_debate_verdict(inv_id, debate_result)

        await asyncio.sleep(10)

        # ── Summarizer ── #
        summarizer = SummarizerAgent()
        log_summary      = await summarizer.summarize_log_correlation(log_result)
        await asyncio.sleep(3)
        intel_summary    = await summarizer.summarize_threat_intel(intel_result)
        await asyncio.sleep(3)
        malware_summary  = await summarizer.summarize_malware(malware_result)
        await asyncio.sleep(3)
        timeline_summary = await summarizer.summarize_timeline(timeline_result)

        summaries = {
            "log_summary":      log_summary,
            "intel_summary":    intel_summary,
            "malware_summary":  malware_summary,
            "timeline_summary": timeline_summary,
        }
        summarizer_run_id = await db.start_agent_run(inv_id, "Summarizer")
        await db.finish_agent_run(
            summarizer_run_id,
            {"_agent": "Summarizer", "_status": "complete", **summaries},
            0,
        )

        await asyncio.sleep(10)

        # ── Report Generator ── #
        report_run_id = await db.start_agent_run(inv_id, "ReportGenerator")
        t = time.monotonic()
        report_result = await ReportGeneratorAgent().run(summaries=summaries)
        await db.finish_agent_run(report_run_id, report_result, int((time.monotonic()-t)*1000))

        # ── Finalise ── #
        final_severity = timeline_result.get("severity", "unknown")
        debate_verdict = debate_result.get("final_verdict", "")
        debate_confidence = debate_result.get("confidence_score", 0)

        if (
            "true positive" in debate_verdict.lower()
            and debate_confidence >= 90
            and final_severity in ("low", "medium", "unknown")
        ):
            final_severity = "high"
            logger.info(
                f"[Pipeline] Severity elevated to 'high' "
                f"(debate confidence={debate_confidence}%, verdict='{debate_verdict}')"
            )

        await db.update_investigation(
            investigation_id=inv_id,
            status="complete",
            severity=final_severity,
            verdict=debate_result.get("final_verdict"),
            confidence=debate_result.get("confidence_score"),
            narrative=timeline_result.get("narrative"),
        )

    except Exception as e:
        logger.error(f"[Pipeline] Investigation {inv_id} failed: {e}")
        await db.update_investigation(
            investigation_id=inv_id,
            status="error",
        )


# ── Routes ────────────────────────────────────────────────────── #

@router.post(
    "/run",
    response_model=PipelineStartResponse,
    status_code=202,
    summary="Start investigation (async)",
    description=(
        "Starts a full pipeline investigation in the background. "
        "Returns immediately with an investigation_id. "
        "Poll GET /pipeline/{id}/status to track progress."
    ),
)
async def start_pipeline(
    request:          PipelineRequest,
    background_tasks: BackgroundTasks,
    db:               TimescaleClient = Depends(get_db),
):
    inv_id = await db.create_investigation(
        input_summary=request.input_summary
    )

    # Save raw inputs for potential rerun
    run_id = await db.start_agent_run(inv_id, "raw_input")
    await db.finish_agent_run(
        run_id=run_id,
        result={
            "_agent":           "raw_input",
            "_status":          "complete",
            "log_sources":      request.log_sources,
            "threat_evidence":  request.threat_evidence,
            "malware_evidence": request.malware_evidence,
        },
        duration_ms=0,
    )

    inputs = {
        "log_sources":      request.log_sources,
        "threat_evidence":  request.threat_evidence,
        "malware_evidence": request.malware_evidence,
    }

    background_tasks.add_task(_run_full_pipeline, inv_id, inputs, db)

    return PipelineStartResponse(
        investigation_id=inv_id,
        status="started",
        message="Investigation started. Poll /status for updates.",
    )


@router.post(
    "/run/sync",
    response_model=PipelineStartResponse,
    summary="Start investigation (blocking)",
    description=(
        "Runs the full pipeline synchronously. "
        "Blocks until complete. Use for testing only — "
        "can take 5-10 minutes for a full investigation."
    ),
)
async def start_pipeline_sync(
    request: PipelineRequest,
    db:      TimescaleClient = Depends(get_db),
):
    inv_id = await db.create_investigation(
        input_summary=request.input_summary
    )

    run_id = await db.start_agent_run(inv_id, "raw_input")
    await db.finish_agent_run(
        run_id=run_id,
        result={
            "_agent":           "raw_input",
            "_status":          "complete",
            "log_sources":      request.log_sources,
            "threat_evidence":  request.threat_evidence,
            "malware_evidence": request.malware_evidence,
        },
        duration_ms=0,
    )

    inputs = {
        "log_sources":      request.log_sources,
        "threat_evidence":  request.threat_evidence,
        "malware_evidence": request.malware_evidence,
    }

    await _run_full_pipeline(inv_id, inputs, db)

    return PipelineStartResponse(
        investigation_id=inv_id,
        status="complete",
        message="Investigation complete.",
    )


@router.get(
    "/{investigation_id}/status",
    response_model=PipelineStatusResponse,
    summary="Poll investigation status",
)
async def get_pipeline_status(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    agent_runs = await db.get_agent_runs(investigation_id)
    agent_statuses = [
        {
            "agent":      r["agent_name"],
            "status":     r["status"],
            "duration_ms": r.get("duration_ms"),
            "error":      r.get("error_message"),
        }
        for r in agent_runs
        if r["agent_name"] != "raw_input"
    ]

    return PipelineStatusResponse(
        investigation_id=investigation_id,
        status=inv["status"],
        severity=inv.get("severity"),
        verdict=inv.get("verdict"),
        confidence=inv.get("confidence"),
        agent_statuses=agent_statuses,
    )


@router.post(
    "/{investigation_id}/rerun",
    response_model=PipelineStartResponse,
    status_code=202,
    summary="Rerun a previous investigation",
    description="Fetches the original inputs from DB and reruns the full pipeline.",
)
async def rerun_pipeline(
    investigation_id: str,
    background_tasks: BackgroundTasks,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    # Fetch saved raw inputs
    runs = await db.get_agent_runs(investigation_id)
    raw_run = next((r for r in runs if r["agent_name"] == "raw_input"), None)
    if not raw_run or not raw_run.get("result_json"):
        raise HTTPException(status_code=400, detail="No saved inputs for this investigation")

    import json
    result = raw_run["result_json"]
    if isinstance(result, str):
        result = json.loads(result)

    inputs = {
        "log_sources":      result.get("log_sources", {}),
        "threat_evidence":  result.get("threat_evidence", ""),
        "malware_evidence": result.get("malware_evidence", ""),
    }

    # Create a new investigation for the rerun
    new_inv_id = await db.create_investigation(
        input_summary=f"Rerun of {investigation_id[:8]}... — {inv.get('input_summary', '')}"
    )

    background_tasks.add_task(_run_full_pipeline, new_inv_id, inputs, db)

    return PipelineStartResponse(
        investigation_id=new_inv_id,
        status="started",
        message=f"Rerun started as new investigation {new_inv_id}",
    )