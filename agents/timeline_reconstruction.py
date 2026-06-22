import logging
import asyncio
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm
from tenacity import retry, stop_after_attempt
from agents.base_agent import _GroqRateLimitWait

logger = logging.getLogger(__name__)

class KillChainEvent(BaseModel):
    """A single event placed on the kill-chain timeline."""
    timestamp:      str       = ""
    stage:          str       = "unknown"   
    description:    str       = ""          
    source:         str       = ""          
    actor:          str       = ""          
    technique_id:   str       = ""          
    technique_name: str       = ""         
    iocs_involved:  List[str] = []          
    confidence:     str       = "low"      


class KillChainStageSummary(BaseModel):
    """
    One row per kill-chain stage.
    Always 7 rows in the output — occurred=False for stages not seen.
    """
    stage:          str       = "unknown"
    occurred:       bool      = False       
    event_count:    int       = 0
    start_time:     str       = ""
    end_time:       str       = ""
    key_techniques: List[str] = []          
    summary:        str       = ""         

class AttackerProfile(BaseModel):
    """
    Synthesised attacker profile from threat intel + log evidence combined.
    The timeline agent sees both L1 outputs so it builds a richer profile
    than either the threat intel or log agent could alone.
    """
    primary_actor:      str       = "unknown"
    actor_aliases:      List[str] = []
    motivation:         str       = "unknown"      
    sophistication:     str       = "unknown"      
    dwell_time_minutes: int       = 0             
    initial_access:     str       = ""              
    objective:          str       = ""             


class TimelineGap(BaseModel):
    """
    A period where no events were logged but attacker activity is inferred.
    These are the gaps analysts need to dig into.
    """
    after_timestamp:    str = ""
    before_timestamp:   str = ""
    gap_minutes:        int = 0
    suspected_activity: str = ""    

class TimelineReconstructionOutput(BaseModel):
    """Full output of the Timeline Reconstruction agent."""

    timeline:                List[KillChainEvent]        = []
    stage_summaries:         List[KillChainStageSummary] = []
    attacker_profile:        AttackerProfile             = Field(default_factory=AttackerProfile)
    timeline_gaps:           List[TimelineGap]           = []
    lateral_movement:        bool = False
    privilege_escalation:    bool = False
    data_exfiltrated:        bool = False
    persistence_established: bool = False
    furthest_stage_reached:  str       = "unknown"
    all_techniques:          List[str] = []
    all_iocs:                List[str] = []
    severity:                str       = "unknown"
    narrative:               str       = ""

def build_timeline_agent() -> Agent:
    return Agent(
        role="Senior Threat Timeline Reconstruction Analyst",
        goal=(
            "Fuse correlated log events and threat intelligence into a precise "
            "chronological kill-chain timeline. Map every event to its ATT&CK technique "
            "and kill-chain stage. Identify the attacker's full path from initial access "
            "to their objective, surface gaps, and produce a narrative an executive can act on."
        ),
        backstory=(
            "You are a senior incident responder with 12 years reconstructing attack timelines "
            "for Fortune 500 breaches and nation-state intrusions. You have correlated thousands "
            "of log sources, threat intel feeds, and malware reports into single coherent attack "
            "narratives. You are obsessed with timestamps and causality — you never assume an "
            "event caused another without evidence linking them. You think in kill-chain stages "
            "and always cite the specific log line or IOC that supports each conclusion. "
            "You are the bridge between raw forensic data and boardroom-ready briefings."
        ),
        llm=get_llm(temperature=0.1),
        verbose=True,
        allow_delegation=False,
    )

def _compress_log_for_timeline(log_correlation: dict) -> str:
    """
    Extract only what timeline reconstruction actually needs from log output.
    Drops: source_coverage, per-event severity detail, raw ioc lists in events.
    Keeps: attack vector, flags, summary, top 10 events (timestamp+stage+desc+iocs),
           top 5 anomalies.
    Saves ~60% of the log correlation token budget.
    """
    lines = []
    lines.append(f"Attack vector: {log_correlation.get('attack_vector', 'unknown')}")
    lines.append(f"Lateral movement: {log_correlation.get('lateral_movement', False)}")
    lines.append(f"Exfil detected: {log_correlation.get('exfil_detected', False)}")
    lines.append(f"Confidence: {log_correlation.get('confidence', 'low')}")
    lines.append(f"IOCs: {', '.join(log_correlation.get('iocs', [])[:10])}")
    lines.append(f"Summary: {log_correlation.get('summary', '')}")

    events = log_correlation.get("events", [])[:10]  
    if events:
        lines.append("\nKEY EVENTS:")
        for ev in events:
            iocs = ev.get("iocs", [])
            lines.append(
                f"  [{ev.get('timestamp', '')}] [{ev.get('source', '?')}] "
                f"[{ev.get('kill_chain_stage', '?').upper()}] "
                f"{ev.get('description', '')} | iocs={iocs}"
            )

    anomalies = log_correlation.get("anomalies", [])[:5]  
    if anomalies:
        lines.append("\nANOMALIES:")
        for an in anomalies:
            lines.append(
                f"  [{an.get('risk_level', '?').upper()}] "
                f"{an.get('pattern', '')} — {an.get('evidence', '')}"
            )

    return "\n".join(lines)


def _compress_intel_for_timeline(threat_intel: dict) -> str:
    """
    Extract only what timeline reconstruction needs from threat intel output.
    Drops: full CVE descriptions, alias repetition, long evidence strings.
    Keeps: summary, actors (name+confidence), TTPs (id+name+tactic only),
           CVE ids, IOC lists, MITRE mapping.
    Saves ~70% of the threat intel token budget.
    """
    lines = []
    lines.append(f"Summary: {threat_intel.get('summary', '')}")

    actors = threat_intel.get("threat_actors", [])
    if actors:
        actor_str = ", ".join(
            f"{a.get('name', '?')} (conf={a.get('confidence', '?')})"
            for a in actors
        )
        lines.append(f"Threat actors: {actor_str}")

    ttps = threat_intel.get("ttps", [])[:8]  
    if ttps:
        lines.append("TTPs:")
        for t in ttps:
            lines.append(
                f"  {t.get('technique_id', '')} | "
                f"{t.get('technique_name', '')} | "
                f"tactic={t.get('tactic', '')}"
            )

    cves = threat_intel.get("cves", [])
    if cves:
        cve_str = ", ".join(
            f"{c.get('cve_id', '')} [{c.get('severity', '?')}]"
            for c in cves[:5] 
        )
        lines.append(f"CVEs: {cve_str}")

    iocs = threat_intel.get("iocs", {})
    all_iocs = (
        iocs.get("ips", [])[:5] +
        iocs.get("domains", [])[:5] +
        iocs.get("hashes", [])[:3] +
        iocs.get("urls", [])[:3]
    )
    lines.append(f"IOCs: {', '.join(all_iocs)}")

    mitre = threat_intel.get("mitre_attack", {})
    lines.append(
        f"MITRE tactics: {', '.join(mitre.get('tactics', []))} | "
        f"techniques: {', '.join(mitre.get('techniques', []))} | "
        f"phase: {mitre.get('kill_chain_phase', 'unknown')}"
    )

    return "\n".join(lines)


def build_timeline_task(
    agent:           Agent,
    log_correlation: dict,
    threat_intel:    dict,
) -> Task:
    """
    REFACTORED: Compresses both upstream outputs before building the prompt.
    Original passed full dicts as formatted strings (~6,000-8,000 tokens).
    This version passes compressed summaries (~800-1,200 tokens).
    Net saving: ~5,000-7,000 tokens per Timeline call.
    """
    log_block   = _compress_log_for_timeline(log_correlation)
    intel_block = _compress_intel_for_timeline(threat_intel)

    return Task(
        description=(
            "Reconstruct the full attack timeline from two compressed evidence sources.\n\n"

            "═══ LOG CORRELATION EVIDENCE ═══\n"
            f"{log_block}\n\n"

            "═══ THREAT INTELLIGENCE EVIDENCE ═══\n"
            f"{intel_block}\n\n"

            "═══ YOUR TASK ═══\n"
            "1. Fuse BOTH evidence sources into ONE unified chronological timeline.\n"
            "2. Map EVERY event to one of these 7 kill-chain stages:\n"
            "   reconnaissance | weaponization | delivery | exploitation |\n"
            "   installation | command_and_control | exfiltration\n"
            "3. For each event assign the matching MITRE ATT&CK technique_id and technique_name.\n"
            "4. Identify timeline_gaps — periods where activity is inferred but not logged.\n"
            "5. Build an attacker_profile from the combined evidence.\n"
            "6. Set boolean flags: lateral_movement, privilege_escalation,\n"
            "   data_exfiltrated, persistence_established.\n"
            "7. Set furthest_stage_reached to the deepest kill-chain stage observed.\n"
            "8. Write a 3-4 sentence executive narrative.\n\n"
            "RULES: Only include what the evidence supports. Never invent events.\n"
            "Every timeline event must have a stage. Unknown is acceptable if truly unclear."
        ),
        expected_output=(
            "A fully populated TimelineReconstructionOutput JSON with: "
            "timeline (events sorted by timestamp), "
            "stage_summaries (one entry per kill-chain stage), "
            "attacker_profile, timeline_gaps, "
            "lateral_movement / privilege_escalation / data_exfiltrated / "
            "persistence_established flags, "
            "furthest_stage_reached, all_techniques (deduplicated ATT&CK IDs), "
            "all_iocs (deduplicated), severity (critical|high|medium|low), "
            "and a 3-4 sentence executive narrative."
        ),
        agent=agent,
        output_pydantic=TimelineReconstructionOutput,
    )
class TimelineReconstructionAgent:
    """
    Layer 2 agent — first chain in the pipeline.

    Receives:
        log_correlation_result → full dict from LogCorrelationAgent.run()
        threat_intel_result    → full dict from ThreatIntelAgent.run()

    Returns:
        Validated TimelineReconstructionOutput dict
        plus _agent and _status metadata keys.
    """

    def __init__(self):
        self._agent = build_timeline_agent()
    @retry(stop=stop_after_attempt(4), wait=_GroqRateLimitWait())
    async def run(
        self,
        log_correlation_result: dict,
        threat_intel_result:    dict,
    ) -> dict:
        """
        Run timeline reconstruction by fusing the two L1 agent outputs.

        Args:
            log_correlation_result: Output dict from LogCorrelationAgent.run()
            threat_intel_result:    Output dict from ThreatIntelAgent.run()

        Returns:
            Dict with full timeline, stage summaries, attacker profile,
            boolean flags, narrative, and _agent/_status metadata.
        """

        if (log_correlation_result.get("_status") == "error" and
                threat_intel_result.get("_status") == "error"):
            return {
                **TimelineReconstructionOutput().model_dump(),
                "_agent":  "TimelineReconstruction",
                "_status": "error",
                "_error":  (
                    "Both upstream agents (LogCorrelation + ThreatIntel) failed. "
                    "Cannot reconstruct timeline without at least one evidence source."
                ),
            }

        if log_correlation_result.get("_status") == "error":
            logger.warning(
                "[TimelineReconstruction] LogCorrelation failed — "
                "running with ThreatIntel evidence only. Timeline may be incomplete."
            )
        if threat_intel_result.get("_status") == "error":
            logger.warning(
                "[TimelineReconstruction] ThreatIntel failed — "
                "running with LogCorrelation evidence only. Actor context will be missing."
            )

        try:
            task = build_timeline_task(
                agent=self._agent,
                log_correlation=log_correlation_result,
                threat_intel=threat_intel_result,
            )
            crew   = Crew(agents=[self._agent], tasks=[task], verbose=False)
            output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)
            result: TimelineReconstructionOutput = output.pydantic
            return {
                **result.model_dump(),
                "_agent":  "TimelineReconstruction",
                "_status": "complete",
            }

        except Exception as e:
            logger.error(f"[TimelineReconstruction] run() failed: {e}")
            raise