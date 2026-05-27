# test_agents.py
import asyncio
import json
import logging
logging.basicConfig(level=logging.INFO)

from agents.threat_intel_agent import ThreatIntelAgent
from agents.malware_analysis_agent import MalwareAnalysisAgent
from agents.log_correlation_agent import LogCorrelationAgent

# ── Sample evidence ────────────────────────────────────────────────────── #

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


# ── Test runners ───────────────────────────────────────────────────────── #

async def test_threat_intel():
    print("\n" + "="*60)
    print("TESTING: ThreatIntelAgent")
    print("="*60)
    agent = ThreatIntelAgent()
    result = await agent.run(THREAT_INTEL_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete", f"Expected complete, got: {result.get('_error')}"
    assert result["severity"] != "unknown", "Severity should be detected"
    assert len(result["iocs"]["ips"]) > 0, "Should detect IPs as IOCs"
    print("✅ ThreatIntel passed")
    return result

async def test_malware():
    print("\n" + "="*60)
    print("TESTING: MalwareAnalysisAgent")
    print("="*60)
    agent = MalwareAnalysisAgent()
    result = await agent.run(MALWARE_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete", f"Expected complete, got: {result.get('_error')}"
    assert result["classification"]["type"] != "unknown", "Should classify malware type"
    assert result["static_analysis"]["packed"] == True, "Should detect UPX packing"
    print("✅ MalwareAnalysis passed")
    return result

async def test_log_correlation():
    print("\n" + "="*60)
    print("TESTING: LogCorrelationAgent")
    print("="*60)
    agent = LogCorrelationAgent()
    result = await agent.run(LOG_EVIDENCE)
    print(json.dumps(result, indent=2))
    assert result["_status"] == "complete", f"Expected complete, got: {result.get('_error')}"
    assert len(result["events"]) > 0, "Should extract correlated events"
    assert result["lateral_movement"] == True or result["exfil_detected"] == True
    print("✅ LogCorrelation passed")
    return result

async def test_all():
    print("\n🚀 Running all agent tests...\n")
    results = []
    tests = [
        ("ThreatIntel",     test_threat_intel),
        ("MalwareAnalysis", test_malware),
        ("LogCorrelation",  test_log_correlation),
    ]
    for name, test_fn in tests:
        result = await test_fn()
        results.append((name, result))
        print(f"\n⏳ Waiting 30s before next agent (TPM limit)...\n")
        await asyncio.sleep(30)
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    for name, result in results:
        if isinstance(result, Exception):
            print(f"❌ {name}: FAILED — {result}")
        else:
            print(f"✅ {name}: {result.get('_status')} | severity/threat_level: "
                  f"{result.get('severity') or result.get('threat_level', 'n/a')}")


# ── Entry point ────────────────────────────────────────────────────────── #


if __name__ == "__main__":
    asyncio.run(test_all())