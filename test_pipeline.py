# test_pipeline.py
import asyncio
import json
import logging
logging.basicConfig(level=logging.ERROR)  # suppress verbose logs

from agents.threat_intel_agent import ThreatIntelAgent
from agents.malware_analysis_agent import MalwareAnalysisAgent
from agents.log_correlation_agent import LogCorrelationAgent
from agents.timeline_reconstruction import TimelineReconstructionAgent
from graph.neo4j_client import Neo4jClient
from graph.attack_graph_builder import AttackGraphBuilder

# ── Sample evidence (same attack from 3 angles) ───────────────────────── #

THREAT_INTEL_EVIDENCE = r"""
Email header analysis:
From: support@micros0ft-update.com
To: finance@targetcorp.com
Subject: Urgent: Account Verification Required

Attachment: invoice_2024.exe
SHA256: 4a5d6f7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e

Network connections observed:
185.220.101.45:443 (POST /gate.php)
185.220.101.46:8080 (GET /config)

Registry key created:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater = C:\Users\Public\svchost32.exe
"""

MALWARE_EVIDENCE = r"""
File: invoice_2024.exe
MD5:    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
SHA256: 4a5d6f7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e
File type: PE32 executable (GUI) Intel 80386
Packer: UPX detected

Suspicious strings:
- cmd.exe /c whoami
- powershell -enc JAB...
- C:\Users\Public\svchost32.exe
- /gate.php
- Mozilla/4.0 (compatible; MSIE 6.0)

Imports: WinExec, CreateRemoteThread, VirtualAllocEx, WriteProcessMemory

Sandbox behavior:
- Spawned: cmd.exe, powershell.exe
- Created: C:\Users\Public\svchost32.exe
- Registry: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
- Network: 185.220.101.45:443 POST /gate.php
- Sleeps 30s before execution (sandbox evasion)
"""

LOG_EVIDENCE = {
    "auth.log": """
2024-01-15 02:13:44 Failed password for admin from 185.220.101.45 port 4532 ssh2
2024-01-15 02:13:51 Failed password for admin from 185.220.101.45 port 4532 ssh2
2024-01-15 02:14:02 Failed password for root from 185.220.101.45 port 4532 ssh2
2024-01-15 02:14:18 Accepted password for admin from 185.220.101.45 port 4532 ssh2
2024-01-15 02:14:19 session opened for user admin from 185.220.101.45
""",
    "syslog": """
2024-01-15 02:14:25 admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
2024-01-15 02:15:01 svchost32.exe started as SYSTEM
2024-01-15 02:15:44 crontab modified by root: @reboot /usr/bin/svchost32
""",
    "firewall": """
2024-01-15 02:15:55 ALLOW TCP 10.0.0.5 -> 185.220.101.45:443 BYTES=48291
2024-01-15 02:16:02 ALLOW TCP 10.0.0.5 -> 185.220.101.46:8080 BYTES=1024
2024-01-15 02:22:17 ALLOW TCP 10.0.0.5 -> 45.33.32.156:443 BYTES=204800
"""
}


# ── Step runners ───────────────────────────────────────────────────────── #

async def run_l1_agents():
    """Run all 3 Layer 1 agents sequentially (Groq TPM limit)."""

    print("\n" + "="*60)
    print("LAYER 1 — PARALLEL ANALYSIS")
    print("="*60)

    # ThreatIntel
    print("\n[1/3] Running ThreatIntelAgent...")
    intel_result = await ThreatIntelAgent().run(THREAT_INTEL_EVIDENCE)
    status = intel_result.get("_status")
    print(f"  → Status: {status} | Severity: {intel_result.get('severity')}")
    print(f"  → Actors: {[a['name'] for a in intel_result.get('threat_actors', [])]}")
    print(f"  → IOCs: {intel_result.get('iocs', {})}")
    assert status == "complete", f"ThreatIntel failed: {intel_result.get('_error')}"
    print("  ✅ ThreatIntel passed")

    print("\n⏳ Waiting 30s (TPM limit)...")
    await asyncio.sleep(30)

    # MalwareAnalysis
    print("\n[2/3] Running MalwareAnalysisAgent...")
    malware_result = await MalwareAnalysisAgent().run(MALWARE_EVIDENCE)
    status = malware_result.get("_status")
    clf = malware_result.get("classification", {})
    print(f"  → Status: {status} | Type: {clf.get('type')} | Threat: {malware_result.get('threat_level')}")
    print(f"  → Packed: {malware_result.get('static_analysis', {}).get('packed')}")
    print(f"  → Evasion: {malware_result.get('sandbox_evasion', {})}")
    assert status == "complete", f"MalwareAnalysis failed: {malware_result.get('_error')}"
    print("  ✅ MalwareAnalysis passed")

    print("\n⏳ Waiting 30s (TPM limit)...")
    await asyncio.sleep(30)

    # LogCorrelation
    print("\n[3/3] Running LogCorrelationAgent...")
    log_result = await LogCorrelationAgent().run(LOG_EVIDENCE)
    status = log_result.get("_status")
    print(f"  → Status: {status} | Events: {len(log_result.get('events', []))}")
    print(f"  → Lateral movement: {log_result.get('lateral_movement')}")
    print(f"  → Exfil detected:   {log_result.get('exfil_detected')}")
    print(f"  → Confidence:       {log_result.get('confidence')}")
    assert status == "complete", f"LogCorrelation failed: {log_result.get('_error')}"
    print("  ✅ LogCorrelation passed")

    return intel_result, malware_result, log_result


async def run_l2_timeline(log_result, intel_result):
    """Run Layer 2 Timeline agent."""

    print("\n" + "="*60)
    print("LAYER 2 — TIMELINE RECONSTRUCTION")
    print("="*60)

    print("\n⏳ Waiting 30s (TPM limit)...")
    await asyncio.sleep(30)

    print("\n[1/1] Running TimelineReconstructionAgent...")
    timeline_result = await TimelineReconstructionAgent().run(
        log_correlation_result=log_result,
        threat_intel_result=intel_result,
    )
    status = timeline_result.get("_status")
    print(f"  → Status:           {status}")
    print(f"  → Events:           {len(timeline_result.get('timeline', []))}")
    print(f"  → Furthest stage:   {timeline_result.get('furthest_stage_reached')}")
    print(f"  → Severity:         {timeline_result.get('severity')}")
    print(f"  → Lateral movement: {timeline_result.get('lateral_movement')}")
    print(f"  → Exfil:            {timeline_result.get('data_exfiltrated')}")
    print(f"  → Persistence:      {timeline_result.get('persistence_established')}")
    print(f"\n  Narrative:\n  {timeline_result.get('narrative')}")
    assert status == "complete", f"Timeline failed: {timeline_result.get('_error')}"
    print("\n  ✅ Timeline passed")

    return timeline_result


def run_graph(intel_result, malware_result, timeline_result):
    """Write all agent outputs to Neo4j."""

    print("\n" + "="*60)
    print("STEP 6 — ATTACK GRAPH + NEO4J")
    print("="*60)

    client = Neo4jClient()
    assert client.verify_connection(), "Neo4j connection failed"
    print("\n  ✅ Neo4j connected")

    client.create_constraints()
    print("  ✅ Constraints ready")

    # Clear previous test data
    client.clear_all()
    print("  ✅ Previous data cleared")

    builder = AttackGraphBuilder(client)
    builder.build_from_agents(
        threat_intel=intel_result,
        malware=malware_result,
        timeline=timeline_result,
    )

    # Verify what was written
    iocs = client.get_all_iocs()
    path = client.get_attack_path()
    print(f"\n  → IPs in graph:     {len(iocs['ips'])}")
    print(f"  → Domains in graph: {len(iocs['domains'])}")
    print(f"  → Hashes in graph:  {len(iocs['hashes'])}")
    print(f"  → Timeline events:  {len(path)}")

    assert len(iocs["ips"]) > 0,  "No IPs written to graph"
    assert len(path) > 0,         "No timeline events written to graph"

    client.close()
    print("\n  ✅ Graph build passed")


# ── Summary ────────────────────────────────────────────────────────────── #

def print_summary(intel, malware, log, timeline):
    print("\n" + "="*60)
    print("FULL PIPELINE SUMMARY")
    print("="*60)
    rows = [
        ("ThreatIntel",   intel.get("_status"),    f"severity={intel.get('severity')}"),
        ("MalwareAnalysis", malware.get("_status"), f"type={malware.get('classification',{}).get('type')}"),
        ("LogCorrelation",  log.get("_status"),     f"events={len(log.get('events',[]))}"),
        ("Timeline",        timeline.get("_status"), f"stage={timeline.get('furthest_stage_reached')}"),
        ("Neo4j",           "complete",              "graph written"),
    ]
    for name, status, detail in rows:
        icon = "✅" if status == "complete" else "❌"
        print(f"  {icon} {name:<20} {status:<10} {detail}")


# ── Entry point ────────────────────────────────────────────────────────── #

async def main():
    print("\n🚀 Running full pipeline test (Steps 2-6)...\n")

    # L1
    intel_result, malware_result, log_result = await run_l1_agents()

    # L2
    timeline_result = await run_l2_timeline(log_result, intel_result)

    # Graph
    run_graph(intel_result, malware_result, timeline_result)

    # Summary
    print_summary(intel_result, malware_result, log_result, timeline_result)

    print("\n🎉 Steps 2-6 fully verified. Ready for Step 7.\n")


if __name__ == "__main__":
    asyncio.run(main())