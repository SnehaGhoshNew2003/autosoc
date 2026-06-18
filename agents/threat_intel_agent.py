import logging
import asyncio
from typing import List
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm       
from tenacity import retry, stop_after_attempt
from agents.base_agent import _GroqRateLimitWait

logger = logging.getLogger(__name__)

class ThreatActor(BaseModel):
    name:       str       = ""
    confidence: str       = "low"   
    aliases:    List[str] = []

class TTP(BaseModel):
    technique_id:   str = ""     
    technique_name: str = ""
    tactic:         str = ""
    evidence:       str = ""

class CVE(BaseModel):
    cve_id:      str = ""
    severity:    str = "unknown"   
    description: str = ""

class IOCs(BaseModel):
    ips:     List[str] = []
    domains: List[str] = []
    hashes:  List[str] = []
    urls:    List[str] = []

class MitreAttack(BaseModel):
    tactics:          List[str] = []
    techniques:       List[str] = []
    kill_chain_phase: str       = "unknown"

class ThreatIntelOutput(BaseModel):
    threat_actors: List[ThreatActor] = []
    ttps:          List[TTP]         = []
    cves:          List[CVE]         = []
    iocs:          IOCs              = Field(default_factory=IOCs)
    mitre_attack:  MitreAttack       = Field(default_factory=MitreAttack)
    severity:      str               = "unknown"
    summary:       str               = ""

def build_threat_intel_agent() -> Agent:
    return Agent(
        role="Senior Threat Intelligence Analyst",
        goal=(
            "Analyze evidence to identify threat actors, TTPs, CVEs, and IOCs. "
            "Map all findings to the MITRE ATT&CK framework accurately."
        ),
        backstory=(
            "You are a veteran threat intelligence analyst with 15 years at a top-tier SOC. "
            "You have tracked APT groups, reverse-engineered campaigns, and briefed executives "
            "on nation-state threats. You think in kill chains and always cite your evidence."
        ),
        llm=get_llm(temperature=0.2),     
        verbose=True,
        allow_delegation=False,
    )


def build_threat_intel_task(agent: Agent, evidence: str) -> Task:
    return Task(
        description=(
            f"Analyze the following evidence for threat intelligence:\n\n"
            f"{evidence}\n\n"
            "Extract all threat actors, TTPs, CVEs, IOCs, and MITRE ATT&CK mappings. "
            "Be precise — only report what the evidence supports."
        ),
        expected_output=(
            "A fully populated ThreatIntelOutput JSON with threat_actors, ttps, cves, "
            "iocs, mitre_attack, severity, and a 2-3 sentence summary."
        ),
        agent=agent,
        output_pydantic=ThreatIntelOutput,
    )

class ThreatIntelAgent:
    def __init__(self):
        self._agent = build_threat_intel_agent()
    @retry(stop=stop_after_attempt(4), wait=_GroqRateLimitWait())
    async def run(self, evidence: str) -> dict:
        """
        Run threat intelligence analysis on raw evidence.

        Args:
            evidence: Raw text from packets, logs, emails, PDFs, etc.

        Returns:
            Validated dict with threat actors, TTPs, CVEs, IOCs, MITRE mapping.
        """
        try:
            task   = build_threat_intel_task(self._agent, evidence)
            crew   = Crew(agents=[self._agent], tasks=[task], verbose=False)
            output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)

            result: ThreatIntelOutput = output.pydantic
            return {
                **result.model_dump(),
                "_agent":  "ThreatIntel",
                "_status": "complete",
            }

        except Exception as e:
            logger.error(f"[ThreatIntel] run() failed: {e}")
            raise