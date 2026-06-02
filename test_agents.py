# test_agents.py
import asyncio
import json
import logging
logging.basicConfig(level=logging.INFO)

from agents.threat_intel_agent             import ThreatIntelAgent
from agents.malware_analysis_agent         import MalwareAnalysisAgent
from agents.log_correlation_agent          import LogCorrelationAgent
from agents.timeline_reconstruction  import TimelineReconstructionAgent


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

async def test_threat_intel():
    print("\n" + "="*60)
    print("TESTING: ThreatIntelAgent")
    print("="*60)
    agent  = ThreatIntelAgent()
    result = await agent.run(THREAT_INTEL_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete",    f"Expected complete, got: {result.get('_error')}"
    assert result["severity"] != "unknown",    "Severity should be detected"
    assert len(result["iocs"]["ips"]) > 0,     "Should detect IPs as IOCs"
    print(" ThreatIntel passed")
    return result


async def test_malware():
    print("\n" + "="*60)
    print("TESTING: MalwareAnalysisAgent")
    print("="*60)
    agent  = MalwareAnalysisAgent()
    result = await agent.run(MALWARE_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete",                 f"Expected complete, got: {result.get('_error')}"
    assert result["classification"]["type"] != "unknown",   "Should classify malware type"
    assert result["static_analysis"]["packed"] == True,     "Should detect UPX packing"
    print(" MalwareAnalysis passed")
    return result


async def test_log_correlation():
    print("\n" + "="*60)
    print("TESTING: LogCorrelationAgent")
    print("="*60)
    agent  = LogCorrelationAgent()
    result = await agent.run(LOG_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete", f"Expected complete, got: {result.get('_error')}"
    assert len(result["events"]) > 0,       "Should extract correlated events"
    assert result["lateral_movement"] == True or result["exfil_detected"] == True
    print(" LogCorrelation passed")
    return result


async def test_timeline_reconstruction(
    log_result:   dict | None = None,
    intel_result: dict | None = None,
):
    """
    Test the Timeline Reconstruction agent.

    Can be called two ways:
      1. Standalone — runs its own LogCorrelation + ThreatIntel first,
         then passes their outputs into the timeline agent.
      2. With pre-computed results — pass log_result and intel_result
         directly (used by test_all to avoid re-running L1 agents).
    """
    print("\n" + "="*60)
    print("TESTING: TimelineReconstructionAgent")
    print("="*60)

    if log_result is None or intel_result is None:
        print("\n⚙️  Running upstream agents first (needed as input for timeline)...\n")

        log_agent   = LogCorrelationAgent()
        intel_agent = ThreatIntelAgent()

        print("  → Running LogCorrelationAgent...")
        log_result = await log_agent.run(LOG_EVIDENCE)
        print(f"  → LogCorrelation status: {log_result['_status']}")

        print("\n⏳ Waiting 30s (TPM rate limit)...\n")
        await asyncio.sleep(30)

        print("  → Running ThreatIntelAgent...")
        intel_result = await intel_agent.run(THREAT_INTEL_EVIDENCE)
        print(f"  → ThreatIntel status: {intel_result['_status']}")

        print("\n⏳ Waiting 30s (TPM rate limit)...\n")
        await asyncio.sleep(30)

    print("\n  → Running TimelineReconstructionAgent with L1 outputs...")
    agent  = TimelineReconstructionAgent()
    result = await agent.run(
        log_correlation_result=log_result,
        threat_intel_result=intel_result,
    )

    print(json.dumps(result, indent=2))

    assert result["_status"] == "complete", \
        f"Expected complete, got: {result.get('_error')}"

    assert len(result["timeline"]) > 0, \
        "Timeline should contain at least one event"

    assert result["furthest_stage_reached"] != "unknown", \
        "Should identify the furthest kill-chain stage reached"

    assert result["narrative"] != "", \
        "Should produce an executive narrative"

    assert len(result["stage_summaries"]) > 0, \
        "Should produce stage summaries"

    assert len(result["all_techniques"]) > 0, \
        "Should identify at least one MITRE ATT&CK technique"
    ACCEPTED_STAGES = {
        "reconnaissance",
        "weaponization",
        "delivery",
        "exploitation",
        "installation",
        "command_and_control",
        "exfiltration",
        "privilege_escalation",
        "persistence",
        "lateral_movement",
        "defense_evasion",
        "collection",
        "impact",
        "unknown",
    }

    bad_stages = [
        ev.get("stage")
        for ev in result["timeline"]
        if ev.get("stage") not in ACCEPTED_STAGES
    ]
    assert not bad_stages, \
        f"Timeline events have unrecognised stage names: {bad_stages}"

    has_technique = any(ev.get("technique_id") for ev in result["timeline"])
    assert has_technique, \
        "At least one timeline event should have a MITRE technique ID"

    print(f"\n Timeline summary:")
    print(f"   Events reconstructed  : {len(result['timeline'])}")
    print(f"   Furthest stage        : {result['furthest_stage_reached']}")
    print(f"   Severity              : {result['severity']}")
    print(f"   ATT&CK techniques     : {result['all_techniques']}")
    print(f"   Lateral movement      : {result['lateral_movement']}")
    print(f"   Privilege escalation  : {result['privilege_escalation']}")
    print(f"   Exfiltration          : {result['data_exfiltrated']}")
    print(f"   Persistence           : {result['persistence_established']}")
    print(f"\n Executive narrative:\n   {result['narrative']}")
    print("\nTimelineReconstruction passed")
    return result


async def test_all():
    """
    Runs all 4 agents in pipeline order.

    Order:
      1. LogCorrelation        (L1 — independent)
      2. ThreatIntel           (L1 — independent)
      3. MalwareAnalysis       (L1 — independent)
      4. TimelineReconstruction (L2 — consumes 1 + 2)

    L1 outputs are reused for the Timeline agent — no duplicate API calls.
    """
    print("\n Running all agent tests in pipeline order...\n")

    results      = []
    log_result   = None
    intel_result = None

    log_result = await test_log_correlation()
    results.append(("LogCorrelation", log_result))
    print("\n Waiting 30s before next agent (TPM limit)...\n")
    await asyncio.sleep(30)

    intel_result = await test_threat_intel()
    results.append(("ThreatIntel", intel_result))
    print("\n⏳ Waiting 30s before next agent (TPM limit)...\n")
    await asyncio.sleep(30)

    malware_result = await test_malware()
    results.append(("MalwareAnalysis", malware_result))
    print("\n⏳ Waiting 30s before next agent (TPM limit)...\n")
    await asyncio.sleep(30)

    timeline_result = await test_timeline_reconstruction(
        log_result=log_result,
        intel_result=intel_result,
    )
    results.append(("TimelineReconstruction", timeline_result))

    print("\n" + "="*60)
    print("FINAL SUMMARY — ALL AGENTS")
    print("="*60)
    for name, result in results:
        if isinstance(result, Exception):
            print(f"  {name:<28} FAILED — {result}")
        else:
            key = (
                result.get("severity")
                or result.get("threat_level")
                or result.get("furthest_stage_reached")
                or "n/a"
            )
            print(
                f"  {name:<28} "
                f"status={result.get('_status'):<10} "
                f"key={key}"
            )


if __name__ == "__main__":
    import sys
    target = sys.argv[1].lower() if len(sys.argv) > 1 else "all"

    if   target == "threat_intel": asyncio.run(test_threat_intel())
    elif target == "malware":       asyncio.run(test_malware())
    elif target == "log":           asyncio.run(test_log_correlation())
    elif target == "timeline":      asyncio.run(test_timeline_reconstruction())
    else:                           asyncio.run(test_all())