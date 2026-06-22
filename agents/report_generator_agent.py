import logging
import asyncio
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm, _GroqRateLimitWait
from tenacity import retry, stop_after_attempt

logger = logging.getLogger(__name__)

class ExecutiveSummary(BaseModel):
    incident_title:      str = ""
    severity:            str = "unknown"
    primary_actor:       str = "unknown"
    dwell_time:          str = ""
    impact_assessment:   str = ""
    executive_narrative: str = ""

class TechnicalFindings(BaseModel):
    attack_vector:          str       = "unknown"
    lateral_movement:       bool      = False
    privilege_escalation:   bool      = False
    data_exfiltration:      bool      = False
    persistence_mechanisms: bool      = False
    furthest_stage_reached: str       = "unknown"
    top_mitre_techniques:   List[str] = []

class RemediationAction(BaseModel):
    action:   str = ""
    priority: str = "medium"
    phase:    str = "containment"

class ReportStructuredOutput(BaseModel):
    """
    Structured fields only — NO formatted_markdown here.
    Keeping this small so the schema + input fits within 12k tokens.
    """
    executive_summary:  ExecutiveSummary        = Field(default_factory=ExecutiveSummary)
    technical_findings: TechnicalFindings       = Field(default_factory=TechnicalFindings)
    consolidated_iocs:  List[str]               = []
    remediation_plan:   List[RemediationAction] = []

class ReportGeneratorOutput(BaseModel):
    """Full output including markdown — assembled in Python, not by the LLM."""
    executive_summary:  ExecutiveSummary        = Field(default_factory=ExecutiveSummary)
    technical_findings: TechnicalFindings       = Field(default_factory=TechnicalFindings)
    consolidated_iocs:  List[str]               = []
    remediation_plan:   List[RemediationAction] = []
    formatted_markdown: str                     = ""

def build_report_agent() -> Agent:
    return Agent(
        role="Lead Cybersecurity Incident Reporting Officer",
        goal=(
            "Consolidate all technical findings into a structured incident report "
            "with executive summary, technical findings, IOCs, and remediation plan."
        ),
        backstory=(
            "You are a principal incident response leader who has authored forensic "
            "reports for global enterprise breaches and regulatory bodies. "
            "You translate dense technical forensics into crystal-clear business risk "
            "language with explicit remediation playbooks."
        ),
        llm=get_llm(temperature=0.2),
        verbose=True,
        allow_delegation=False,
    )

def build_markdown_agent() -> Agent:
    return Agent(
        role="Cybersecurity Report Writer",
        goal="Write a professional markdown incident report from structured findings.",
        backstory=(
            "You are a senior technical writer specialising in cybersecurity incident "
            "reports. You produce clear, professional markdown documents from structured "
            "data, always including tables for IOCs, timelines, and remediation steps."
        ),
        llm=get_llm(temperature=0.3),
        verbose=False,
        allow_delegation=False,
    )


def build_structured_task(agent: Agent, summaries: dict) -> Task:
    """
    Step 1: Generate structured JSON fields only.
    No formatted_markdown — keeps the schema small enough to fit in 12k tokens.
    """
    log_s      = summaries.get("log_summary",      "Not available.")
    intel_s    = summaries.get("intel_summary",    "Not available.")
    malware_s  = summaries.get("malware_summary",  "Not available.")
    timeline_s = summaries.get("timeline_summary", "Not available.")

    return Task(
        description=(
            "Synthesize these four security briefings into a structured incident report.\n\n"
            f"LOG CORRELATION:\n{log_s}\n\n"
            f"THREAT INTELLIGENCE:\n{intel_s}\n\n"
            f"MALWARE ANALYSIS:\n{malware_s}\n\n"
            f"ATTACK TIMELINE:\n{timeline_s}\n\n"
            "Populate: executive_summary, technical_findings, "
            "consolidated_iocs (deduplicated), and remediation_plan "
            "(Containment → Eradication → Recovery, prioritized).\n"
            "Never invent IOCs or hashes. State 'Not Observed' if data is missing."
        ),
        expected_output=(
            "A fully populated ReportStructuredOutput JSON with executive_summary, "
            "technical_findings, consolidated_iocs, and remediation_plan."
        ),
        agent=agent,
        output_pydantic=ReportStructuredOutput,
    )

def build_markdown_task(agent: Agent, structured: ReportStructuredOutput,
                        summaries: dict) -> Task:
    """
    Step 2: Generate markdown from the structured output.
    Plain text expected_output — no Pydantic schema overhead.
    """
    es  = structured.executive_summary
    tf  = structured.technical_findings
    iocs = structured.consolidated_iocs
    plan = structured.remediation_plan

    remediation_rows = "\n".join(
        f"| {r.priority.upper()} | {r.phase.title()} | {r.action} |"
        for r in plan
    )
    ioc_rows = "\n".join(f"| `{ioc}` |" for ioc in iocs)

    return Task(
        description=(
            "Write a professional markdown cybersecurity incident report "
            "from the structured data below.\n\n"

            f"INCIDENT TITLE: {es.incident_title}\n"
            f"SEVERITY: {es.severity}\n"
            f"PRIMARY ACTOR: {es.primary_actor}\n"
            f"DWELL TIME: {es.dwell_time}\n"
            f"IMPACT: {es.impact_assessment}\n"
            f"NARRATIVE: {es.executive_narrative}\n\n"

            f"ATTACK VECTOR: {tf.attack_vector}\n"
            f"FURTHEST STAGE: {tf.furthest_stage_reached}\n"
            f"LATERAL MOVEMENT: {tf.lateral_movement}\n"
            f"PRIVILEGE ESCALATION: {tf.privilege_escalation}\n"
            f"DATA EXFILTRATION: {tf.data_exfiltration}\n"
            f"PERSISTENCE: {tf.persistence_mechanisms}\n"
            f"MITRE TECHNIQUES: {', '.join(tf.top_mitre_techniques)}\n\n"

            f"CONSOLIDATED IOCs:\n{ioc_rows or 'None'}\n\n"

            f"REMEDIATION PLAN:\n{remediation_rows or 'None'}\n\n"

            "REQUIRED SECTIONS:\n"
            "1. # Incident Overview (title, severity badge, key metrics table)\n"
            "2. ## Threat Actor Attribution\n"
            "3. ## Kill-Chain Analysis\n"
            "4. ## Malware Footprint\n"
            "5. ## Consolidated IOC Table\n"
            "6. ## Prioritized Remediation Table\n\n"
            "Use markdown tables. Never invent data not present above."
        ),
        expected_output=(
            "A complete professional markdown incident report with all six sections, "
            "IOC table, and remediation table. Plain markdown text only."
        ),
        agent=agent,
    )

class ReportGeneratorAgent:
    def __init__(self):
        self._struct_agent   = build_report_agent()
        self._markdown_agent = build_markdown_agent()

    @retry(stop=stop_after_attempt(4), wait=_GroqRateLimitWait())
    async def _generate_structured(self, summaries: dict) -> ReportStructuredOutput:
        """Step 1 — structured JSON fields, small schema, fits in 12k."""
        task   = build_structured_task(self._struct_agent, summaries)
        crew   = Crew(agents=[self._struct_agent], tasks=[task], verbose=False)
        output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)
        return output.pydantic 

    @retry(stop=stop_after_attempt(4), wait=_GroqRateLimitWait())
    async def _generate_markdown(self, structured: ReportStructuredOutput,
                                 summaries: dict) -> str:
        """Step 2 — plain text markdown, no Pydantic schema overhead."""
        task   = build_markdown_task(self._markdown_agent, structured, summaries)
        crew   = Crew(agents=[self._markdown_agent], tasks=[task], verbose=False)
        output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)
        return str(output).strip() 
    
    async def run(self, summaries: dict) -> dict:
        """
        Two-step generation:
          1. Structured fields (JSON + small Pydantic schema) — fits in 12k
          2. Markdown narrative (plain text, no schema overhead) — fits in 12k
        Assembled into ReportGeneratorOutput in Python.
        """
        all_failed = all(
            "failed:" in summaries.get(k, "failed:")
            for k in ("log_summary", "intel_summary",
                      "malware_summary", "timeline_summary")
        )
        if all_failed:
            return {
                **ReportGeneratorOutput().model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "error",
                "_error":  "All upstream summaries indicate agent failures.",
            }

        try:
            structured = await self._generate_structured(summaries)
            await asyncio.sleep(8)
            markdown = await self._generate_markdown(structured, summaries)

            return {
                **ReportGeneratorOutput(
                    executive_summary  = structured.executive_summary,
                    technical_findings = structured.technical_findings,
                    consolidated_iocs  = structured.consolidated_iocs,
                    remediation_plan   = structured.remediation_plan,
                    formatted_markdown = markdown,
                ).model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "complete",
            }

        except Exception as e:
            logger.error(f"[ReportGenerator] run() exhausted all retries: {e}")
            return {
                **ReportGeneratorOutput().model_dump(),
                "_agent":  "ReportGenerator",
                "_status": "error",
                "_error":  str(e),
            }