import logging
import asyncio
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm

logger = logging.getLogger(__name__)

# ── Pydantic Output Schema ─────────────────────────────────────────────── #

class ExecutiveSummary(BaseModel):
    incident_title:       str = ""
    severity:             str = "unknown"  # critical | high | medium | low
    primary_actor:        str = "unknown"
    dwell_time:           str = ""
    impact_assessment:    str = ""
    executive_narrative:  str = ""

class TechnicalFindings(BaseModel):
    attack_vector:          str       = "unknown"
    lateral_movement:       bool      = False
    privilege_escalation:   bool      = False
    data_exfiltration:      bool      = False
    persistence_mechanisms: bool      = False
    furthest_stage_reached: str       = "unknown"
    top_mitre_techniques:   List[str] = []

class RemediationAction(BaseModel):
    action:      str = ""
    priority:    str = "medium"   # critical | high | medium | low
    phase:       str = "containment"  # containment | eradication | long-term

class ReportGeneratorOutput(BaseModel):
    """Culminated blueprint representation of the entire security incident investigation."""
    executive_summary:   ExecutiveSummary       = Field(default_factory=ExecutiveSummary)
    technical_findings:  TechnicalFindings      = Field(default_factory=TechnicalFindings)
    consolidated_iocs:   List[str]              = []
    remediation_plan:    List[RemediationAction] = []
    formatted_markdown:  str                    = ""


# ── Agent + Task Factory ──────────────────────────────────────────────── #

def build_report_agent() -> Agent:
    return Agent(
        role="Lead Cybersecurity Incident Cyber-Reporting Officer",
        goal=(
            "Consolidate all technical findings, timelines, malware traits, and threat intelligence "
            "into a publication-grade C-level executive summary and an actionable technical incident report."
        ),
        backstory=(
            "You are a principal incident response leader who has authored forensic reports for global enterprise "
            "breaches, regulatory bodies, and internal executive boards. You excel at translating dense technical "
            "forensics (PCAPs, logs, malware disassembly) into crystal-clear business risk language while preserving "
            "rigorous evidentiary backing for security engineers. Your reports are flawlessly structured, professional, "
            "and provide explicit remediation playbooks."
        ),
        llm=get_llm(temperature=0.2),
        verbose=True,
        allow_delegation=False,
    )


def build_report_task(
    agent: Agent,
    log_correlation: dict,
    malware_analysis: dict,
    threat_intel: dict,
    timeline_reconstruction: dict,
) -> Task:
    """Fuses inputs from all upstream investigation agents into a massive multi-perspective context block."""
    
    context_str = "=== UPSTREAM AGENT ANALYSIS CONTEXT ===\n\n"
    
    # Extract Log Correlation data
    if log_correlation.get("_status") == "complete":
        context_str += "1. LOG CORRELATION FINDINGS:\n"
        context_str += f"  - Attack Vector: {log_correlation.get('attack_vector', 'unknown')}\n"
        context_str += f"  - Summary: {log_correlation.get('summary', '')}\n"
        context_str += f"  - Anomalies: {len(log_correlation.get('anomalies', []))} identified\n\n"
        
    # Extract Malware Analysis data
    if malware_analysis.get("_status") == "complete":
        clf = malware_analysis.get("classification", {})
        context_str += "2. MALWARE FORENSICS:\n"
        context_str += f"  - Type: {clf.get('type', 'unknown')} | Family: {clf.get('family', 'unknown')}\n"
        context_str += f"  - Threat Level: {malware_analysis.get('threat_level', 'unknown')}\n"
        context_str += f"  - Capabilities: {', '.join(malware_analysis.get('capabilities', []))}\n"
        context_str += f"  - Malware Summary: {malware_analysis.get('summary', '')}\n\n"

    # Extract Threat Intelligence data
    if threat_intel.get("_status") == "complete":
        context_str += "3. THREAT INTELLIGENCE & ATTRIBUTION:\n"
        context_str += f"  - Summary: {threat_intel.get('summary', '')}\n"
        actors = [a.get('name', 'unknown') for a in threat_intel.get('threat_actors', [])]
        context_str += f"  - Identified Actors: {', '.join(actors)}\n"
        cves = [cve.get('cve_id', '') for cve in threat_intel.get('cves', []) if cve.get('cve_id')]
        context_str += f"  - Exploited CVEs: {', '.join(cves)}\n\n"

    # Extract Timeline Reconstruction data
    if timeline_reconstruction.get("_status") == "complete":
        prof = timeline_reconstruction.get("attacker_profile", {})
        context_str += "4. TIMELINE & ATTACK FLOW:\n"
        context_str += f"  - Narrative: {timeline_reconstruction.get('narrative', '')}\n"
        context_str += f"  - Furthest Stage Reached: {timeline_reconstruction.get('furthest_stage_reached', 'unknown')}\n"
        context_str += f"  - Dwell Time: {prof.get('dwell_time_minutes', 0)} minutes\n"
        context_str += f"  - Operational Flags: Lateral Move={timeline_reconstruction.get('lateral_movement')}, PrivEsc={timeline_reconstruction.get('privilege_escalation')}, Exfil={timeline_reconstruction.get('data_exfiltrated')}, Persistence={timeline_reconstruction.get('persistence_established')}\n"
        context_str += f"  - Total Timeline Events: {len(timeline_reconstruction.get('timeline', []))}\n"
        context_str += f"  - Consolidated Techniques: {', '.join(timeline_reconstruction.get('all_techniques', []))}\n"
        context_str += f"  - Consolidated IOCs: {', '.join(timeline_reconstruction.get('all_iocs', []))}\n\n"

    return Task(
        description=(
            f"{context_str}"
            "═══ YOUR TASK ═══\n"
            "You must synthesize all provided cybersecurity forensics data into a single master incident report. "
            "1. Populate all JSON properties of the `ReportGeneratorOutput` schema exactly.\n"
            "2. Dedup and consolidate all indicators of compromise (IOCs) across logs, malware findings, and intel.\n"
            "3. Build an actionable, prioritized remediation plan featuring concrete Containment, Eradication, and Long-Term Recovery steps.\n"
            "4. Compose a comprehensive, beautifully structured C-level Markdown report block inside `formatted_markdown`. "
            "The Markdown report MUST contain:\n"
            "   - An Incident Overview executive dashboard layout with a clear title and severity metrics.\n"
            "   - Detailed Threat Actor Attribution and Kill-Chain Analysis.\n"
            "   - Technical breakdown of the malware footprint and system impacts (if found).\n"
            "   - Structured markdown tables showing the consolidated attack timeline and IOC lists.\n"
            "   - A prioritized table for remediation tasks.\n\n"
            "RULES: Ensure strict fidelity to the technical evidence. Never invent dates or hashes. "
            "If information is missing from upstream outputs, explicitly state it as 'Not Observed'."
        ),
        expected_output=(
            "A fully populated ReportGeneratorOutput JSON object containing highly professional, structured forensic reports, "
            "remediation metrics, and a stunning formatted_markdown publication-ready report text block."
        ),
        agent=agent,
        output_pydantic=ReportGeneratorOutput,
    )


# ── Public Runner ──────────────────────────────────────────────────────── #

class ReportGeneratorAgent:
    """
    Layer 3 agent — Culmination of the pipeline.
    Fuses outputs from LogCorrelation, MalwareAnalysis, ThreatIntel, and TimelineReconstruction
    into a unified corporate/technical forensic incident report.
    """

    def __init__(self):
        self._agent = build_report_agent()

    async def run(
        self,
        log_correlation_result: dict,
        malware_result:         dict,
        threat_intel_result:    dict,
        timeline_result:        dict,
    ) -> dict:
        """
        Synthesizes the entire workspace context to generate a comprehensive report.
        """
        # Verify if all upstream outputs errored out
        upstreams = [log_correlation_result, malware_result, threat_intel_result, timeline_result]
        if all(u.get("_status") == "error" for u in upstreams):
            return {
                **ReportGeneratorOutput().model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "error",
                "_error":  "All upstream investigations failed. Insufficient source telemetry to compile report.",
            }

        try:
            task = build_report_task(
                agent=self._agent,
                log_correlation=log_correlation_result,
                malware_analysis=malware_result,
                threat_intel=threat_intel_result,
                timeline_reconstruction=timeline_result
            )
            
            crew = Crew(agents=[self._agent], tasks=[task], verbose=False)
            loop = asyncio.get_event_loop()
            output = await loop.run_in_executor(None, crew.kickoff)
            
            result: ReportGeneratorOutput = output.pydantic
            return {
                **result.model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "complete",
            }
            
        except Exception as e:
            logger.error(f"[ReportGenerator] run() failed: {e}")
            return {
                **ReportGeneratorOutput().model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "error",
                "_error":  str(e),
            }