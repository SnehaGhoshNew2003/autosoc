# timeline_reconstruction_agent.py
#
# Layer 2 agent — consumes outputs from BOTH:
#   - LogCorrelationAgent  (correlated events, anomalies, IOCs)
#   - ThreatIntelAgent     (threat actors, TTPs, CVEs, MITRE mapping)
#
# Produces a chronological kill-chain narrative with every event
# tagged to one of the 7 kill-chain stages and mapped to ATT&CK.

import logging
import asyncio
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm

logger = logging.getLogger(__name__)


# ── Pydantic output schema ─────────────────────────────────────────────── #

class KillChainEvent(BaseModel):
    """A single event placed on the kill-chain timeline."""
    timestamp:      str       = ""
    stage:          str       = "unknown"   # one of the 7 kill-chain stages below
    description:    str       = ""          # what actually happened
    source:         str       = ""          # which log/evidence source this came from
    actor:          str       = ""          # threat actor name if identified
    technique_id:   str       = ""          # MITRE technique e.g. T1059.001
    technique_name: str       = ""          # human-readable technique name
    iocs_involved:  List[str] = []          # IPs, hashes, domains active at this step
    confidence:     str       = "low"       # high | medium | low


class KillChainStageSummary(BaseModel):
    """
    One row per kill-chain stage.
    Always 7 rows in the output — occurred=False for stages not seen.
    """
    stage:          str       = "unknown"
    occurred:       bool      = False       # did this stage actually happen?
    event_count:    int       = 0
    start_time:     str       = ""
    end_time:       str       = ""
    key_techniques: List[str] = []          # ATT&CK technique IDs seen at this stage
    summary:        str       = ""          # 1-sentence summary of this stage


class AttackerProfile(BaseModel):
    """
    Synthesised attacker profile from threat intel + log evidence combined.
    The timeline agent sees both L1 outputs so it builds a richer profile
    than either the threat intel or log agent could alone.
    """
    primary_actor:      str       = "unknown"
    actor_aliases:      List[str] = []
    motivation:         str       = "unknown"       # financial | espionage | disruption | unknown
    sophistication:     str       = "unknown"       # low | medium | high | nation-state
    dwell_time_minutes: int       = 0               # minutes from first to last observed event
    initial_access:     str       = ""              # how they got in
    objective:          str       = ""              # what they were trying to achieve


class TimelineGap(BaseModel):
    """
    A period where no events were logged but attacker activity is inferred.
    These are the gaps analysts need to dig into.
    """
    after_timestamp:    str = ""
    before_timestamp:   str = ""
    gap_minutes:        int = 0
    suspected_activity: str = ""    # what probably happened here based on surrounding evidence


class TimelineReconstructionOutput(BaseModel):
    """Full output of the Timeline Reconstruction agent."""

    # Every event, sorted chronologically, each tagged to a kill-chain stage
    timeline:                List[KillChainEvent]        = []

    # One summary per kill-chain stage (7 total)
    stage_summaries:         List[KillChainStageSummary] = []

    # Synthesised attacker profile
    attacker_profile:        AttackerProfile             = Field(default_factory=AttackerProfile)

    # Gaps in the timeline where activity is inferred but not logged
    timeline_gaps:           List[TimelineGap]           = []

    # Key boolean findings
    lateral_movement:        bool = False
    privilege_escalation:    bool = False
    data_exfiltrated:        bool = False
    persistence_established: bool = False

    # The furthest kill-chain stage the attacker reached
    furthest_stage_reached:  str       = "unknown"

    # All unique MITRE ATT&CK technique IDs across the full timeline
    all_techniques:          List[str] = []

    # All unique IOCs across the full timeline (deduplicated)
    all_iocs:                List[str] = []

    # Overall severity for the full attack sequence
    severity:                str       = "unknown"  # critical | high | medium | low

    # 3-4 sentence narrative readable by a non-technical executive
    narrative:               str       = ""


# ── Agent + Task factory ───────────────────────────────────────────────── #

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
        # Low temperature: timeline reconstruction needs precision, not creativity.
        verbose=True,
        allow_delegation=False,
    )


def build_timeline_task(
    agent:           Agent,
    log_correlation: dict,
    threat_intel:    dict,
) -> Task:
    """
    Build the CrewAI Task for timeline reconstruction.

    Fuses both L1 outputs into one structured prompt so the agent
    can cross-reference timestamps with actor/TTP context.
    """

    # ── Format the log correlation output ── #
    events_block = ""
    if log_correlation.get("events"):
        events_block = "CORRELATED EVENTS (from LogCorrelation agent):\n"
        for ev in log_correlation["events"]:
            events_block += (
                f"  [{ev.get('timestamp', 'N/A')}] "
                f"[{ev.get('source', '?')}] "
                f"[{ev.get('kill_chain_stage', '?').upper()}] "
                f"{ev.get('description', '')} "
                f"| severity={ev.get('severity', '?')} "
                f"| iocs={ev.get('iocs', [])}\n"
            )

    anomalies_block = ""
    if log_correlation.get("anomalies"):
        anomalies_block = "\nANOMALIES DETECTED:\n"
        for an in log_correlation["anomalies"]:
            anomalies_block += (
                f"  [{an.get('risk_level', '?').upper()}] "
                f"{an.get('pattern', '')} — {an.get('evidence', '')}\n"
            )

    log_summary = log_correlation.get("summary", "No log summary available.")
    log_iocs    = log_correlation.get("iocs", [])
    attack_vec  = log_correlation.get("attack_vector", "unknown")
    lateral_mv  = log_correlation.get("lateral_movement", False)
    exfil       = log_correlation.get("exfil_detected", False)

    # ── Format the threat intel output ── #
    actors_block = ""
    if threat_intel.get("threat_actors"):
        actors_block = "\nTHREAT ACTORS IDENTIFIED:\n"
        for actor in threat_intel["threat_actors"]:
            actors_block += (
                f"  {actor.get('name', 'Unknown')} "
                f"(confidence={actor.get('confidence', '?')}, "
                f"aliases={actor.get('aliases', [])})\n"
            )

    ttps_block = ""
    if threat_intel.get("ttps"):
        ttps_block = "\nTTPs (Tactics, Techniques, Procedures):\n"
        for ttp in threat_intel["ttps"]:
            ttps_block += (
                f"  {ttp.get('technique_id', '')} | "
                f"{ttp.get('technique_name', '')} | "
                f"tactic={ttp.get('tactic', '')} | "
                f"evidence={ttp.get('evidence', '')}\n"
            )

    cves_block = ""
    if threat_intel.get("cves"):
        cves_block = "\nCVEs REFERENCED:\n"
        for cve in threat_intel["cves"]:
            cves_block += (
                f"  {cve.get('cve_id', '')} "
                f"[{cve.get('severity', '?')}]: "
                f"{cve.get('description', '')}\n"
            )

    mitre      = threat_intel.get("mitre_attack", {})
    mitre_block = (
        f"\nMITRE ATT&CK MAPPING:\n"
        f"  Tactics:          {mitre.get('tactics', [])}\n"
        f"  Techniques:       {mitre.get('techniques', [])}\n"
        f"  Kill-chain phase: {mitre.get('kill_chain_phase', 'unknown')}\n"
    )

    intel_iocs    = threat_intel.get("iocs", {})
    intel_summary = threat_intel.get("summary", "No threat intel summary available.")

    return Task(
        description=(
            "You are reconstructing the full attack timeline from two evidence sources.\n\n"

            "═══ LOG CORRELATION EVIDENCE ═══\n"
            f"Attack vector:             {attack_vec}\n"
            f"Lateral movement detected: {lateral_mv}\n"
            f"Exfiltration detected:     {exfil}\n"
            f"Log IOCs:                  {log_iocs}\n"
            f"Log summary:               {log_summary}\n\n"
            f"{events_block}"
            f"{anomalies_block}\n"

            "═══ THREAT INTELLIGENCE EVIDENCE ═══\n"
            f"Threat intel summary: {intel_summary}\n"
            f"Threat intel IOCs:    {intel_iocs}\n"
            f"{actors_block}"
            f"{ttps_block}"
            f"{cves_block}"
            f"{mitre_block}\n"

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
            "lateral_movement / privilege_escalation / data_exfiltrated / persistence_established flags, "
            "furthest_stage_reached, all_techniques (deduplicated ATT&CK IDs), "
            "all_iocs (deduplicated), severity (critical|high|medium|low), "
            "and a 3-4 sentence executive narrative."
        ),
        agent=agent,
        output_pydantic=TimelineReconstructionOutput,
    )


# ── Public runner ──────────────────────────────────────────────────────── #

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

        # If BOTH upstream agents failed there is nothing to reconstruct from
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

        # If only one errored we still proceed — agent is instructed to only
        # cite what evidence supports, so partial input = partial (honest) output
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
            loop   = asyncio.get_event_loop()
            output = await loop.run_in_executor(None, crew.kickoff)

            result: TimelineReconstructionOutput = output.pydantic
            return {
                **result.model_dump(),
                "_agent":  "TimelineReconstruction",
                "_status": "complete",
            }

        except Exception as e:
            logger.error(f"[TimelineReconstruction] run() failed: {e}")
            return {
                **TimelineReconstructionOutput().model_dump(),
                "_agent":  "TimelineReconstruction",
                "_status": "error",
                "_error":  str(e),
            }