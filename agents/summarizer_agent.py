import logging
import asyncio
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm
from tenacity import retry, stop_after_attempt
from agents.base_agent import _GroqRateLimitWait
logger = logging.getLogger(__name__)


def build_summarizer_agent() -> Agent:
    return Agent(
        role="Forensic Evidence Summarizer",
        goal=(
            "Compress verbose cybersecurity agent outputs into tight, "
            "information-dense summaries. Preserve every critical finding. "
            "Cut all repetition and verbose JSON structure."
        ),
        backstory=(
            "You are a senior SOC editor who takes raw forensic agent outputs "
            "and distils them into precise briefing notes for executive reports. "
            "You never omit a threat finding, IOC, or MITRE technique. "
            "You cut word count ruthlessly while keeping every fact intact."
        ),
        llm=get_llm(temperature=0.1),
        verbose=False,
        allow_delegation=False,
    )


class SummarizerAgent:
    """
    Compresses all four upstream agent outputs before they are
    passed to the Report Generator.

    Usage in main.py / orchestrator:

        summarizer = SummarizerAgent()
        summaries = await summarizer.summarize_all(
            log_result=log_result,
            intel_result=intel_result,
            malware_result=malware_result,
            timeline_result=timeline_result,
        )
        # Then pass summaries to ReportGeneratorAgent.run()
    """

    def __init__(self):
        self._agent = build_summarizer_agent()
    @retry(stop=stop_after_attempt(4), wait=_GroqRateLimitWait())
    async def _run_task(self, description: str, expected_output: str) -> str:
        """
        Run a single summarization task and return the text output.
        Returns the raw string — no JSON parsing needed because
        summaries are plain text paragraphs, not structured data.
        """
        task = Task(
            description=description,
            expected_output=expected_output,
            agent=self._agent,
        )
        crew = Crew(agents=[self._agent], tasks=[task], verbose=False)
        loop = asyncio.get_event_loop()
        output = await loop.run_in_executor(None, crew.kickoff)
        return str(output).strip()
    async def summarize_log_correlation(self, result: dict) -> str:
        """
        Compress LogCorrelation output.
        Extracts: attack vector, key events, anomalies, IOCs, flags.
        Drops: source_coverage details, per-event severity repetition.
        """
        if result.get("_status") == "error":
            return f"LogCorrelation failed: {result.get('_error', 'unknown error')}"

        attack_vec  = result.get("attack_vector", "unknown")
        summary     = result.get("summary", "")
        lateral     = result.get("lateral_movement", False)
        exfil       = result.get("exfil_detected", False)
        confidence  = result.get("confidence", "low")
        iocs        = result.get("iocs", [])
        anomalies   = result.get("anomalies", [])
        events      = result.get("events", [])

        event_lines = "\n".join(
            f"  [{ev.get('timestamp', '')}] [{ev.get('kill_chain_stage', '?').upper()}] "
            f"{ev.get('description', '')} (severity={ev.get('severity', '?')})"
            for ev in events[:20]  
        )
        if len(events) > 20:
            event_lines += f"\n  ... and {len(events) - 20} more events"

        anomaly_lines = "\n".join(
            f"  [{an.get('risk_level', '?').upper()}] {an.get('pattern', '')} — {an.get('evidence', '')}"
            for an in anomalies
        )

        description = (
            f"Summarize this log correlation forensic output into a tight 4-6 sentence paragraph.\n\n"
            f"ATTACK VECTOR: {attack_vec}\n"
            f"LATERAL MOVEMENT: {lateral}\n"
            f"EXFILTRATION DETECTED: {exfil}\n"
            f"CONFIDENCE: {confidence}\n"
            f"IOCs: {', '.join(iocs[:15])}\n"
            f"AGENT SUMMARY: {summary}\n\n"
            f"KEY EVENTS:\n{event_lines}\n\n"
            f"ANOMALIES:\n{anomaly_lines}\n\n"
            "RULES:\n"
            "- Include the attack vector, all IOCs, all anomalies, and the key event sequence.\n"
            "- Include the lateral movement and exfiltration flags explicitly.\n"
            "- Do not omit any IOC or anomaly.\n"
            "- Write plain prose — no JSON, no bullet points, no markdown.\n"
            "- Maximum 100 words."
        )

        return await self._run_task(
            description=description,
            expected_output=(
                "A 4-6 sentence plain prose summary of the log correlation findings. "
                "All IOCs, anomalies, and key events included. Maximum 100 words."
            ),
        )

    async def summarize_threat_intel(self, result: dict) -> str:
        """
        Compress ThreatIntel output.
        Extracts: actors, TTPs, CVEs, IOCs, MITRE mapping, severity.
        Drops: nested confidence details, alias repetition.
        """
        if result.get("_status") == "error":
            return f"ThreatIntel failed: {result.get('_error', 'unknown error')}"

        actors   = result.get("threat_actors", [])
        ttps     = result.get("ttps", [])
        cves     = result.get("cves", [])
        iocs     = result.get("iocs", {})
        mitre    = result.get("mitre_attack", {})
        severity = result.get("severity", "unknown")
        summary  = result.get("summary", "")

        actor_lines = ", ".join(
            f"{a.get('name', 'unknown')} (confidence={a.get('confidence', '?')})"
            for a in actors
        ) or "None identified"

        ttp_lines = "\n".join(
            f"  {t.get('technique_id', '')} | {t.get('technique_name', '')} | "
            f"tactic={t.get('tactic', '')} | evidence={t.get('evidence', '')}"
            for t in ttps[:10]
        )

        cve_lines = ", ".join(
            f"{c.get('cve_id', '')} [{c.get('severity', '?')}]"
            for c in cves
        ) or "None"

        all_iocs = (
            iocs.get("ips", []) +
            iocs.get("domains", []) +
            iocs.get("hashes", []) +
            iocs.get("urls", [])
        )

        description = (
            f"Summarize this threat intelligence output into a tight 4-6 sentence paragraph.\n\n"
            f"SEVERITY: {severity}\n"
            f"THREAT ACTORS: {actor_lines}\n"
            f"CVEs: {cve_lines}\n"
            f"ALL IOCs: {', '.join(all_iocs[:20])}\n"
            f"MITRE TACTICS: {', '.join(mitre.get('tactics', []))}\n"
            f"MITRE TECHNIQUES: {', '.join(mitre.get('techniques', []))}\n"
            f"AGENT SUMMARY: {summary}\n\n"
            f"TTPs:\n{ttp_lines}\n\n"
            "RULES:\n"
            "- Include severity, all threat actors, all CVEs, and all IOCs.\n"
            "- Include every MITRE technique ID mentioned.\n"
            "- Write plain prose — no JSON, no bullet points, no markdown.\n"
            "- Maximum 100 words."
        )

        return await self._run_task(
            description=description,
            expected_output=(
                "A 4-6 sentence plain prose summary of threat intelligence findings. "
                "All actors, CVEs, IOCs, and MITRE techniques included. Maximum 150 words."
            ),
        )

    async def summarize_malware(self, result: dict) -> str:
        """
        Compress MalwareAnalysis output.
        Extracts: classification, capabilities, evasion, IOCs, MITRE techniques.
        Drops: full import lists, raw string dumps, nested behavioral detail.
        """
        if result.get("_status") == "error":
            return f"MalwareAnalysis failed: {result.get('_error', 'unknown error')}"

        clf          = result.get("classification", {})
        static       = result.get("static_analysis", {})
        behavioral   = result.get("behavioral_analysis", {})
        capabilities = result.get("capabilities", [])
        evasion      = result.get("sandbox_evasion", {})
        iocs         = result.get("iocs", {})
        mitre_techs  = result.get("mitre_techniques", [])
        threat_level = result.get("threat_level", "unknown")
        summary      = result.get("summary", "")

        all_iocs = (
            iocs.get("ips", []) +
            iocs.get("domains", []) +
            iocs.get("hashes", []) +
            iocs.get("file_paths", []) +
            iocs.get("mutexes", [])
        )

        mitre_lines = ", ".join(
            f"{m.get('technique_id', '')} ({m.get('technique_name', '')})"
            for m in mitre_techs
        ) or "None mapped"

        persistence = behavioral.get("persistence_mechanisms", [])
        processes   = behavioral.get("processes_spawned", [])
        registry    = behavioral.get("registry_modifications", [])

        description = (
            f"Summarize this malware analysis output into a tight 4-6 sentence paragraph.\n\n"
            f"CLASSIFICATION: type={clf.get('type', '?')} family={clf.get('family', '?')} "
            f"confidence={clf.get('confidence', '?')}\n"
            f"THREAT LEVEL: {threat_level}\n"
            f"PACKED: {static.get('packed', False)} | PACKER: {static.get('packer', 'none')}\n"
            f"CAPABILITIES: {', '.join(capabilities)}\n"
            f"SANDBOX EVASION: detected={evasion.get('detected', False)} "
            f"techniques={evasion.get('techniques', [])}\n"
            f"PERSISTENCE: {persistence}\n"
            f"PROCESSES SPAWNED: {processes}\n"
            f"REGISTRY MODIFICATIONS: {registry}\n"
            f"MITRE TECHNIQUES: {mitre_lines}\n"
            f"ALL IOCs: {', '.join(all_iocs[:15])}\n"
            f"AGENT SUMMARY: {summary}\n\n"
            "RULES:\n"
            "- Include malware type, family, threat level, capabilities, and evasion techniques.\n"
            "- Include all MITRE technique IDs and all IOCs.\n"
            "- Include persistence mechanisms explicitly.\n"
            "- Write plain prose — no JSON, no bullet points, no markdown.\n"
            "- Maximum 100 words."
        )

        return await self._run_task(
            description=description,
            expected_output=(
                "A 4-6 sentence plain prose summary of the malware analysis. "
                "All MITRE techniques, IOCs, and persistence mechanisms included. "
                "Maximum 100 words."
            ),
        )

    async def summarize_timeline(self, result: dict) -> str:
        """
        Compress TimelineReconstruction output.
        Extracts: narrative, furthest stage, flags, attacker profile, key techniques.
        Drops: per-event detail, stage summary repetition, timeline gap detail.
        """
        if result.get("_status") == "error":
            return f"TimelineReconstruction failed: {result.get('_error', 'unknown error')}"

        narrative      = result.get("narrative", "")
        furthest       = result.get("furthest_stage_reached", "unknown")
        severity       = result.get("severity", "unknown")
        lateral        = result.get("lateral_movement", False)
        priv_esc       = result.get("privilege_escalation", False)
        exfil          = result.get("data_exfiltrated", False)
        persistence    = result.get("persistence_established", False)
        techniques     = result.get("all_techniques", [])
        iocs           = result.get("all_iocs", [])
        profile        = result.get("attacker_profile", {})
        timeline       = result.get("timeline", [])
        stage_summaries = result.get("stage_summaries", [])

        active_stages = [
            f"{s.get('stage', '?').upper()}: {s.get('summary', '')}"
            for s in stage_summaries
            if s.get("occurred", False)
        ]

        description = (
            f"Summarize this attack timeline reconstruction into a tight 4-6 sentence paragraph.\n\n"
            f"NARRATIVE: {narrative}\n\n"
            f"SEVERITY: {severity}\n"
            f"FURTHEST STAGE: {furthest}\n"
            f"FLAGS: lateral_movement={lateral} | privilege_escalation={priv_esc} | "
            f"data_exfiltrated={exfil} | persistence_established={persistence}\n\n"
            f"ATTACKER PROFILE:\n"
            f"  actor={profile.get('primary_actor', 'unknown')}\n"
            f"  motivation={profile.get('motivation', 'unknown')}\n"
            f"  sophistication={profile.get('sophistication', 'unknown')}\n"
            f"  dwell_time={profile.get('dwell_time_minutes', 0)} minutes\n"
            f"  initial_access={profile.get('initial_access', 'unknown')}\n"
            f"  objective={profile.get('objective', 'unknown')}\n\n"
            f"ACTIVE KILL-CHAIN STAGES ({len(timeline)} total events):\n"
            + "\n".join(f"  {s}" for s in active_stages) + "\n\n"
            f"ALL MITRE TECHNIQUES: {', '.join(techniques)}\n"
            f"ALL IOCs: {', '.join(iocs[:20])}\n\n"
            "RULES:\n"
            "- Include severity, furthest stage reached, and all four boolean flags explicitly.\n"
            "- Include the attacker profile details.\n"
            "- Include all MITRE technique IDs and all IOCs.\n"
            "- Write plain prose — no JSON, no bullet points, no markdown.\n"
            "- Maximum 100 words."
        )

        return await self._run_task(
            description=description,
            expected_output=(
                "A 4-6 sentence plain prose summary of the attack timeline. "
                "Severity, flags, attacker profile, all MITRE techniques and IOCs included. "
                "Maximum 100 words."
            ),
        )

    async def summarize_all(
        self,
        log_result:      dict,
        intel_result:    dict,
        malware_result:  dict,
        timeline_result: dict,
    ) -> dict:
        """
        Summarize all four upstream agent outputs concurrently.
        Returns a dict of plain-text summaries ready for the Report Generator.

        All four summarizations run in parallel — same pattern as L1 agents.
        Total wait = slowest summarization, not sum of all four.

        Returns:
            {
                "log_summary":     str,  # ~100 words
                "intel_summary":   str,  # ~100 words
                "malware_summary": str,  # ~100 words
                "timeline_summary": str, # ~100 words
            }
        """
        logger.info("[Summarizer] Compressing all agent outputs in parallel...")

        log_summary     = await self.summarize_log_correlation(log_result)
        await asyncio.sleep(5)
        intel_summary   = await self.summarize_threat_intel(intel_result)
        await asyncio.sleep(5)
        malware_summary = await self.summarize_malware(malware_result)
        await asyncio.sleep(5)
        timeline_summary = await self.summarize_timeline(timeline_result)

        logger.info("[Summarizer] All outputs compressed")

        return {
            "log_summary":      log_summary,
            "intel_summary":    intel_summary,
            "malware_summary":  malware_summary,
            "timeline_summary": timeline_summary,
        }