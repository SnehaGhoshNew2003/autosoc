import asyncio
import logging
import time
import json
import sys
from dotenv import load_dotenv

from agents.log_correlation_agent          import LogCorrelationAgent
from agents.threat_intel_agent             import ThreatIntelAgent
from agents.malware_analysis_agent         import MalwareAnalysisAgent
from agents.timeline_reconstruction  import TimelineReconstructionAgent
from agents.report_generator_agent         import ReportGeneratorAgent
from agents.multi_agent_debate             import MultiAgentDebate
from agents.summarizer_agent               import SummarizerAgent
from graph.attack_graph_builder            import AttackGraphBuilder
from graph.neo4j_client                    import Neo4jClient
from database.timescale_client             import TimescaleClient

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def collect_user_input() -> dict:
    print("\n" + "="*60)
    print("  AutoSOC — AI Cyber Investigation Pipeline")
    print("="*60)
    print("  Enter your evidence below.")
    print("  Press Enter to skip any field.\n")

    input_summary = input("Investigation title / brief description:\n> ").strip()
    if not input_summary:
        input_summary = "Untitled investigation"

    print("\n--- LOG SOURCES ---")
    print("Type source name then paste content. Press Enter twice to finish each one.")
    print("Available: auth.log, syslog, firewall, proxy, edr, email_gateway, dns")
    print("Type 'done' when finished.\n")

    log_sources = {}
    while True:
        source_name = input("Source name (or 'done'): ").strip().lower()
        if source_name == "done" or not source_name:
            break
        print(f"Paste {source_name} content (press Enter twice when done):")
        lines = []
        while True:
            line = input()
            if line == "" and lines and lines[-1] == "":
                break
            lines.append(line)
        content = "\n".join(lines).strip()
        if content:
            log_sources[source_name] = content
            print(f"  saved {source_name} ({len(content)} chars)\n")

    print("\n--- THREAT INTEL EVIDENCE ---")
    print("Press Enter twice when done.\n")
    threat_lines = []
    while True:
        line = input()
        if line == "" and threat_lines and threat_lines[-1] == "":
            break
        threat_lines.append(line)
    threat_evidence = "\n".join(threat_lines).strip()

    print("\n--- MALWARE EVIDENCE ---")
    print("Press Enter twice when done.\n")
    malware_lines = []
    while True:
        line = input()
        if line == "" and malware_lines and malware_lines[-1] == "":
            break
        malware_lines.append(line)
    malware_evidence = "\n".join(malware_lines).strip()

    print("\n" + "="*60)
    print(f"  Log sources    : {list(log_sources.keys()) or 'none'}")
    print(f"  Threat intel   : {'yes' if threat_evidence else 'none'}")
    print(f"  Malware sample : {'yes' if malware_evidence else 'none'}")
    print("="*60 + "\n")

    return {
        "input_summary":    input_summary,
        "log_sources":      log_sources,
        "threat_evidence":  threat_evidence,
        "malware_evidence": malware_evidence,
    }

async def save_raw_inputs(db: TimescaleClient, inv_id: str, inputs: dict):
    run_id = await db.start_agent_run(inv_id, "raw_input")
    await db.finish_agent_run(
        run_id=run_id,
        result={
            "_agent":           "raw_input",
            "_status":          "complete",
            "log_sources":      inputs["log_sources"],
            "threat_evidence":  inputs["threat_evidence"],
            "malware_evidence": inputs["malware_evidence"],
        },
        duration_ms=0,
    )


async def fetch_raw_inputs(db: TimescaleClient, inv_id: str) -> dict:
    runs = await db.get_agent_runs(inv_id)
    for run in runs:
        if run["agent_name"] == "raw_input" and run["status"] == "complete":
            result = run.get("result_json") or {}
            if isinstance(result, str):
                result = json.loads(result)
            return {
                "log_sources":      result.get("log_sources", {}),
                "threat_evidence":  result.get("threat_evidence", ""),
                "malware_evidence": result.get("malware_evidence", ""),
            }
    return {"log_sources": {}, "threat_evidence": "", "malware_evidence": ""}


async def fetch_agent_result(db: TimescaleClient, inv_id: str, agent_name: str) -> dict:
    runs = await db.get_agent_runs(inv_id)
    for run in runs:
        if run["agent_name"] == agent_name and run["status"] == "complete":
            result = run.get("result_json") or {}
            if isinstance(result, str):
                result = json.loads(result)
            return result
    logger.error(          
        f"[main] fetch_agent_result: no completed run for '{agent_name}' "
        f"in investigation {inv_id} — downstream agents will get error input"
    )
    return {
        "_agent":  agent_name,
        "_status": "error",
        "_error":  f"No completed result in DB for agent: {agent_name}",
    }

async def run_pipeline(inputs: dict = None) -> dict:

    db = TimescaleClient()
    await db.connect()
    await db.create_schema()

    if inputs is None:
        inputs = collect_user_input()

    inv_id = await db.create_investigation(
        input_summary=inputs.get("input_summary", "Untitled investigation")
    )
    logger.info(f"[main] Investigation created: {inv_id}")
    await save_raw_inputs(db, inv_id, inputs)

    print("\n[1/5] Running analysis agents (sequential)...")

    log_run_id = await db.start_agent_run(inv_id, "LogCorrelation")
    t = time.monotonic()
    log_result = await LogCorrelationAgent().run(inputs["log_sources"])
    await db.finish_agent_run(log_run_id, log_result, int((time.monotonic()-t)*1000))
    await db.save_iocs(inv_id, {"log": log_result})
    logger.info("[main] LogCorrelation done")
    await asyncio.sleep(5)

    intel_run_id = await db.start_agent_run(inv_id, "ThreatIntel")
    t = time.monotonic()
    intel_result = await ThreatIntelAgent().run(inputs["threat_evidence"])
    await db.finish_agent_run(intel_run_id, intel_result, int((time.monotonic()-t)*1000))
    await db.save_iocs(inv_id, {"threat_intel": intel_result})
    logger.info("[main] ThreatIntel done")
    await asyncio.sleep(5)

    malware_run_id = await db.start_agent_run(inv_id, "MalwareAnalysis")
    t = time.monotonic()
    malware_result = await MalwareAnalysisAgent().run(inputs["malware_evidence"])
    await db.finish_agent_run(malware_run_id, malware_result, int((time.monotonic()-t)*1000))
    await db.save_iocs(inv_id, {"malware": malware_result})
    logger.info("[main] MalwareAnalysis done")


    print("\n[2/5] Waiting 15s for token bucket to refill before Timeline...")
    await asyncio.sleep(15)

    print("\n[2/5] Running Timeline Reconstruction...")
    log_result   = await fetch_agent_result(db, inv_id, "LogCorrelation")
    intel_result = await fetch_agent_result(db, inv_id, "ThreatIntel")

    tl_run_id = await db.start_agent_run(inv_id, "TimelineReconstruction")
    t = time.monotonic()
    timeline_result = await TimelineReconstructionAgent().run(
        log_correlation_result=log_result,
        threat_intel_result=intel_result,
    )
    await db.finish_agent_run(tl_run_id, timeline_result, int((time.monotonic()-t)*1000))
    await db.save_events(inv_id, timeline_result)
    await db.save_iocs(inv_id, {"timeline": timeline_result})
    logger.info("[main] Timeline done")

    malware_result = await fetch_agent_result(db, inv_id, "MalwareAnalysis")
    neo4j = Neo4jClient()
    neo4j.create_constraints()
    AttackGraphBuilder(neo4j).build_from_agents(
        threat_intel=intel_result,
        malware=malware_result,
        timeline=timeline_result,
        investigation_id=inv_id,
    )
    neo4j.close()
    logger.info("[main] AttackGraph done")

    print("\n[3/5] Waiting 15s before Debate...")
    await asyncio.sleep(15)

    print("\n[3/5] Running Multi-Agent Debate...")
    debate_run_id = await db.start_agent_run(inv_id, "MultiAgentDebate")
    t = time.monotonic()
    debate_result = await MultiAgentDebate().run(
        log_data=await fetch_agent_result(db, inv_id, "LogCorrelation"),
        intel_data=await fetch_agent_result(db, inv_id, "ThreatIntel"),
        malware_data=await fetch_agent_result(db, inv_id, "MalwareAnalysis"),
        timeline_data=await fetch_agent_result(db, inv_id, "TimelineReconstruction"),
    )
    await db.finish_agent_run(debate_run_id, debate_result, int((time.monotonic()-t)*1000))
    await db.save_debate_verdict(inv_id, debate_result)
    logger.info("[main] Debate done")

    print("\n[4/5] Waiting 15s before Summarizer...")
    await asyncio.sleep(15)

    print("\n[4/5] Compressing outputs for Report Generator...")
    summarizer = SummarizerAgent()

    log_summary = await summarizer.summarize_log_correlation(
        await fetch_agent_result(db, inv_id, "LogCorrelation")
    )
    await asyncio.sleep(3)

    intel_summary = await summarizer.summarize_threat_intel(
        await fetch_agent_result(db, inv_id, "ThreatIntel")
    )
    await asyncio.sleep(3)

    malware_summary = await summarizer.summarize_malware(
        await fetch_agent_result(db, inv_id, "MalwareAnalysis")
    )
    await asyncio.sleep(3)

    timeline_summary = await summarizer.summarize_timeline(
        await fetch_agent_result(db, inv_id, "TimelineReconstruction")
    )

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
    logger.info("[main] Summarizer done")

    await asyncio.sleep(10)

    print("\n[5/5] Generating final report...")
    report_run_id = await db.start_agent_run(inv_id, "ReportGenerator")
    t = time.monotonic()
    report_result = await ReportGeneratorAgent().run(summaries=summaries)
    await db.finish_agent_run(report_run_id, report_result, int((time.monotonic()-t)*1000))
    logger.info("[main] Report done")

    await db.update_investigation(
        investigation_id=inv_id,
        status="complete",
        severity=timeline_result.get("severity"),
        verdict=debate_result.get("final_verdict"),
        confidence=debate_result.get("confidence_score"),
        narrative=timeline_result.get("narrative"),
    )

    print("\n" + "="*60)
    print("  Investigation Complete")
    print("="*60)
    print(f"  ID         : {inv_id}")
    print(f"  Severity   : {timeline_result.get('severity', 'unknown')}")
    print(f"  Verdict    : {debate_result.get('final_verdict', 'unknown')}")
    print(f"  Confidence : {debate_result.get('confidence_score', 0)}%")
    print(f"  Narrative  : {timeline_result.get('narrative', '')[:120]}...")
    print("="*60 + "\n")

    await db.close()
    return {"investigation_id": inv_id}

async def rerun_investigation(inv_id: str):
    db = TimescaleClient()
    await db.connect()
    inv = await db.get_investigation(inv_id)
    if not inv:
        print(f"Investigation {inv_id} not found.")
        await db.close()
        return
    print(f"\nRe-running: {inv_id}")
    inputs = await fetch_raw_inputs(db, inv_id)
    inputs["input_summary"] = inv.get("input_summary", "Re-run")
    await db.close()
    await run_pipeline(inputs=inputs)

if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "rerun":
        asyncio.run(rerun_investigation(sys.argv[2]))
    else:
        asyncio.run(run_pipeline())