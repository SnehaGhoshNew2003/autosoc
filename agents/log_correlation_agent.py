#logcorrelation.agent
import logging
from typing import List, Optional
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm
import asyncio

logger = logging.getLogger(__name__)

class CorrelatedEvent(BaseModel):
    timestamp:        str       = ""
    source:           str       = ""          
    description:      str       = ""
    kill_chain_stage: str       = "unknown"   
    severity:         str       = "low"       
    iocs:             List[str] = []


class AnomalyDetail(BaseModel):
    pattern:     str = ""    
    evidence:    str = ""    
    risk_level:  str = "low" 


class SourceCoverage(BaseModel):
    source_name:  str = ""
    event_count:  int = 0
    earliest:     str = ""
    latest:       str = ""


class LogCorrelationOutput(BaseModel):
    events:           List[CorrelatedEvent] = []
    anomalies:        List[AnomalyDetail]  = []
    source_coverage:  List[SourceCoverage] = []
    attack_vector:    str                  = "unknown"   
    lateral_movement: bool                 = False
    exfil_detected:   bool                 = False
    iocs:             List[str]            = []         
    confidence:       str                  = "low"     
    summary:          str                  = ""


def build_log_correlation_agent() -> Agent:
    return Agent(
        role="Senior SOC Log Correlation Analyst",
        goal=(
            "Correlate raw logs from multiple sources into a structured attack timeline, "
            "identify kill-chain stages, extract IOCs, and surface anomalies."
        ),
        backstory=(
            "You are a senior SOC analyst with 10 years correlating SIEM alerts, "
            "firewall logs, auth events, and endpoint telemetry. You reconstruct "
            "full attack sequences from fragmented log data across sources, "
            "linking events by timestamp, IP, and username to map attacker behaviour. "
            "You never guess — every finding is tied to a concrete log line."
        ),
        llm=get_llm(temperature=0.1),
        verbose=True,
        allow_delegation=False,
    )


def build_log_correlation_task(agent: Agent, evidence: str) -> Task:
    return Task(
        description=(
            f"Correlate the following log data from one or more sources:\n\n"
            f"{evidence}\n\n"
            "Sources may include: auth.log, syslog, firewall, proxy, endpoint EDR, "
            "email gateway, DNS, or SIEM exports. "
            "Link events across sources by shared IP, username, or time window. "
            "Identify the full kill-chain sequence, lateral movement, persistence, "
            "exfiltration attempts, and all IOCs."
        ),
        expected_output=(
            "A fully populated LogCorrelationOutput JSON with correlated events sorted "
            "by timestamp, anomalies with evidence, source coverage stats, attack vector, "
            "lateral movement flag, exfil flag, deduplicated IOC list, confidence level, "
            "and a 2-3 sentence summary of the attack sequence."
        ),
        agent=agent,
        output_pydantic=LogCorrelationOutput,
    )

class LogCorrelationAgent:
    def __init__(self):
        self._agent = build_log_correlation_agent()

    async def run(self, log_sources: dict[str, str]) -> dict:
        
        formatted = "\n\n".join(
            f"=== SOURCE: {name.upper()} ===\n{content.strip()}"
            for name, content in log_sources.items()
            if content and content.strip()
        )

        if not formatted:
            return {
                **LogCorrelationOutput().model_dump(),
                "_agent":  "LogCorrelation",
                "_status": "error",
                "_error":  "No log content provided",
            }

        try:
            task   = build_log_correlation_task(self._agent, formatted)
            crew   = Crew(agents=[self._agent], tasks=[task], verbose=False)
            loop   = asyncio.get_event_loop()
            output = await loop.run_in_executor(None, crew.kickoff)

            result: LogCorrelationOutput = output.pydantic
            return {
                **result.model_dump(),
                "_agent":  "LogCorrelation",
                "_status": "complete",
            }

        except Exception as e:
            logger.error(f"[LogCorrelation] run() failed: {e}")
            return {
                **LogCorrelationOutput().model_dump(),
                "_agent":  "LogCorrelation",
                "_status": "error",
                "_error":  str(e),
            }