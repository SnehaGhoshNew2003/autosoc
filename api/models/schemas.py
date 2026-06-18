# api/models/schemas.py
#
# All Pydantic request and response models for the API.
# Kept separate from the agent Pydantic models so the API
# contract is independent of internal agent implementation.

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Shared ────────────────────────────────────────────────────── #

class StatusResponse(BaseModel):
    status: str
    message: str


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None


# ── Pipeline ──────────────────────────────────────────────────── #

class PipelineRequest(BaseModel):
    """
    Full evidence submission to start an investigation.
    All fields are optional — the pipeline handles missing data gracefully.
    """
    input_summary:    str                 = Field(
        default="Untitled investigation",
        description="Brief description of the investigation"
    )
    log_sources:      Dict[str, str]      = Field(
        default_factory=dict,
        description="Dict of log source name → raw log content. "
                    "Keys: auth.log, syslog, firewall, proxy, edr, email_gateway, dns"
    )
    threat_evidence:  str                 = Field(
        default="",
        description="Raw threat intelligence text: IPs, domains, threat reports"
    )
    malware_evidence: str                 = Field(
        default="",
        description="Malware evidence: binary metadata, strings, sandbox logs"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "input_summary": "Suspicious attachment opened by employee",
                "log_sources": {
                    "email_gateway": "2026-06-01 09:10:15 Email from attacker@evil.com\n"
                                     "2026-06-01 09:10:16 Attachment: invoice.exe",
                    "edr": "2026-06-01 09:11:01 powershell.exe spawned\n"
                           "2026-06-01 09:11:20 payload.exe created"
                },
                "threat_evidence": "IP: 185.220.101.45 — known C2\nDomain: evil-update.com",
                "malware_evidence": "File: invoice.exe\nSHA256: abc123\nBehavior: downloads payload, adds Run Key"
            }
        }


class PipelineStartResponse(BaseModel):
    investigation_id: str
    status:           str = "started"
    message:          str


class PipelineStatusResponse(BaseModel):
    investigation_id: str
    status:           str
    severity:         Optional[str]
    verdict:          Optional[str]
    confidence:       Optional[int]
    agent_statuses:   List[Dict[str, Any]]


# ── Investigations ────────────────────────────────────────────── #

class InvestigationSummary(BaseModel):
    id:            str
    created_at:    datetime
    status:        str
    severity:      Optional[str]
    verdict:       Optional[str]
    confidence:    Optional[int]
    input_summary: Optional[str]


class InvestigationDetail(BaseModel):
    id:            str
    created_at:    datetime
    status:        str
    severity:      Optional[str]
    verdict:       Optional[str]
    confidence:    Optional[int]
    input_summary: Optional[str]
    narrative:     Optional[str]
    agent_runs:    List[Dict[str, Any]]
    events:        List[Dict[str, Any]]
    iocs:          List[Dict[str, Any]]
    verdict_detail: Optional[Dict[str, Any]]


class InvestigationListResponse(BaseModel):
    investigations: List[InvestigationSummary]
    total:          int


# ── IOCs ──────────────────────────────────────────────────────── #

class IOCItem(BaseModel):
    id:               Optional[str]
    investigation_id: Optional[str]
    ioc_type:         str
    value:            str
    source_agent:     Optional[str]
    context:          Optional[str]
    first_seen:       Optional[datetime]


class IOCListResponse(BaseModel):
    iocs:  List[IOCItem]
    total: int


class IOCSearchRequest(BaseModel):
    value: str = Field(
        description="Exact IOC value to search for across all investigations. "
                    "Example: '103.77.192.88' or 'evil.com'. "
                    "This is NOT the IOC type — use GET /iocs/{inv_id}/type/{type} for that."
    )

class IOCHistoryItem(BaseModel):
    value:            str
    ioc_type:         str
    source_agent:     Optional[str]
    first_seen:       Optional[datetime]
    investigation_id: str
    created_at:       Optional[datetime]
    verdict:          Optional[str]


class IOCHistoryResponse(BaseModel):
    value:        str
    occurrences:  List[IOCHistoryItem]
    total:        int


# ── Events ────────────────────────────────────────────────────── #

class KillChainEventItem(BaseModel):
    id:               Optional[str]
    investigation_id: Optional[str]
    event_time:       Optional[datetime]
    stage:            Optional[str]
    description:      Optional[str]
    source:           Optional[str]
    actor:            Optional[str]
    technique_id:     Optional[str]
    technique_name:   Optional[str]
    confidence:       Optional[str]
    iocs_involved:    Optional[List[str]]


class EventListResponse(BaseModel):
    events: List[KillChainEventItem]
    total:  int


# ── Reports ───────────────────────────────────────────────────── #

class ReportResponse(BaseModel):
    investigation_id:   str
    formatted_markdown: str
    executive_summary:  Optional[Dict[str, Any]]
    technical_findings: Optional[Dict[str, Any]]
    consolidated_iocs:  Optional[List[str]]
    remediation_plan:   Optional[List[Dict[str, Any]]]


# ── Debate ────────────────────────────────────────────────────── #

class DebateVerdictResponse(BaseModel):
    investigation_id:     str
    final_verdict:        Optional[str]
    confidence_score:     Optional[int]
    executive_summary:    Optional[str]
    red_team_evidence:    Optional[List[str]]
    blue_team_evidence:   Optional[List[str]]
    created_at:           Optional[datetime]


# ── Graph ─────────────────────────────────────────────────────── #

class GraphStatsResponse(BaseModel):
    investigation_id: str
    node_counts:      Dict[str, int]
    relationship_counts: Dict[str, int]
    attack_path:      List[Dict[str, Any]]


# ── Health ────────────────────────────────────────────────────── #

class HealthResponse(BaseModel):
    status:   str
    database: str
    version:  str = "1.0.0"