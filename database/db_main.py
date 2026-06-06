# main.py  —  Pipeline orchestrator with TimescaleDB
#
# Shows exactly how the DB client slots into the pipeline you already have.
# Every agent result is saved immediately after it finishes — so if one
# agent crashes halfway through, nothing is lost.

import asyncio
import logging
import time
from dotenv import load_dotenv

from agents.log_correlation_agent           import LogCorrelationAgent
from agents.threat_intel_agent              import ThreatIntelAgent
from agents.malware_analysis_agent          import MalwareAnalysisAgent
from agents.timeline_reconstruction         import TimelineReconstructionAgent
from agents.report_generator_agent          import ReportGeneratorAgent
from agents.multi_agent_debate              import MultiAgentDebate
from timescale_client                       import TimescaleClient

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def run_pipeline(
    log_sources:    dict[str, str],     # {"auth.log": "...", "syslog": "..."}
    threat_evidence: str,               # raw text: emails, pcap summary, PDFs
    malware_evidence: str,              # binary metadata / strings / sandbox output
    input_summary:   str = "",          # brief description for the investigations table
) -> dict:
    """
    Full pipeline: L1 agents in parallel → L2 agents → Debate → Report → DB saves.
    Returns the complete investigation result dict.
    """

    # ── 1. Open DB connection ─────────────────────────────────────────── #
    db = TimescaleClient()
    await db.connect()
    await db.create_schema()   # idempotent — safe to call every run

    # ── 2. Create investigation record ────────────────────────────────── #
    # This is the parent row. Everything else links to this UUID.
    inv_id = await db.create_investigation(input_summary=input_summary)
    logger.info(f"Investigation started: {inv_id}")

    # ── 3. Run L1 agents IN PARALLEL ─────────────────────────────────── #
    # asyncio.gather starts all three at the same time.
    # Total wait = slowest agent, not sum of all three.

    log_run_id     = await db.start_agent_run(inv_id, "LogCorrelation")
    intel_run_id   = await db.start_agent_run(inv_id, "ThreatIntel")
    malware_run_id = await db.start_agent_run(inv_id, "MalwareAnalysis")

    async def run_log():
        t = time.monotonic()
        result = await LogCorrelationAgent().run(log_sources)
        await db.finish_agent_run(log_run_id, result, int((time.monotonic()-t)*1000))
        return result

    async def run_intel():
        t = time.monotonic()
        result = await ThreatIntelAgent().run(threat_evidence)
        await db.finish_agent_run(intel_run_id, result, int((time.monotonic()-t)*1000))
        return result

    async def run_malware():
        t = time.monotonic()
        result = await MalwareAnalysisAgent().run(malware_evidence)
        await db.finish_agent_run(malware_run_id, result, int((time.monotonic()-t)*1000))
        return result

    log_result, intel_result, malware_result = await asyncio.gather(
        run_log(), run_intel(), run_malware()
    )
    logger.info("L1 agents complete")

    # ── 4. Save L1 IOCs to DB ─────────────────────────────────────────── #
    await db.save_iocs(inv_id, {
        "log":          log_result,
        "threat_intel": intel_result,
        "malware":      malware_result,
    })

    # ── 5. Timeline Reconstruction (L2 — consumes L1 outputs) ────────── #
    timeline_run_id = await db.start_agent_run(inv_id, "TimelineReconstruction")
    t = time.monotonic()
    timeline_result = await TimelineReconstructionAgent().run(
        log_correlation_result=log_result,
        threat_intel_result=intel_result,
    )
    await db.finish_agent_run(
        timeline_run_id, timeline_result, int((time.monotonic()-t)*1000)
    )

    # Save kill-chain events from timeline to the events hypertable
    await db.save_events(inv_id, timeline_result)

    # Save timeline IOCs (may include new ones the timeline agent found)
    await db.save_iocs(inv_id, {"timeline": timeline_result})

    # ── 6. Multi-Agent Debate ─────────────────────────────────────────── #
    debate_run_id = await db.start_agent_run(inv_id, "MultiAgentDebate")
    t = time.monotonic()
    debate_result = await MultiAgentDebate().run(
        log_data=log_result,
        intel_data=intel_result,
        malware_data=malware_result,
        timeline_data=timeline_result,
    )
    await db.finish_agent_run(
        debate_run_id, debate_result, int((time.monotonic()-t)*1000)
    )
    await db.save_debate_verdict(inv_id, debate_result)

    # ── 7. Report Generator ───────────────────────────────────────────── #
    report_run_id = await db.start_agent_run(inv_id, "ReportGenerator")
    t = time.monotonic()
    report_result = await ReportGeneratorAgent().run(
        log_correlation_result=log_result,
        malware_result=malware_result,
        threat_intel_result=intel_result,
        timeline_result=timeline_result,
    )
    await db.finish_agent_run(
        report_run_id, report_result, int((time.monotonic()-t)*1000)
    )

    # ── 8. Final investigation update ────────────────────────────────── #
    await db.update_investigation(
        investigation_id=inv_id,
        status="complete",
        severity=timeline_result.get("severity"),
        verdict=debate_result.get("final_verdict"),
        confidence=debate_result.get("confidence_score"),
        narrative=timeline_result.get("narrative"),
    )

    await db.close()
    logger.info(f"Investigation complete: {inv_id}")

    return {
        "investigation_id": inv_id,
        "log":      log_result,
        "intel":    intel_result,
        "malware":  malware_result,
        "timeline": timeline_result,
        "debate":   debate_result,
        "report":   report_result,
    }