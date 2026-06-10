import asyncio
import json
import logging
logging.basicConfig(level=logging.INFO)

from timescale_client import TimescaleClient, _infer_ioc_type

MOCK_TIMELINE = {
    "_status": "complete",
    "_agent":  "TimelineReconstruction",
    "severity": "high",
    "narrative": "Attacker brute-forced SSH, escalated privileges, and exfiltrated data.",
    "furthest_stage_reached": "exfiltration",
    "lateral_movement": True,
    "privilege_escalation": True,
    "data_exfiltrated": True,
    "persistence_established": True,
    "all_techniques": ["T1110", "T1059", "T1041"],
    "all_iocs": ["185.220.101.45", "10.0.0.5", "45.33.32.156", "svchost32.exe"],
    "timeline": [
        {
            "timestamp":      "2024-01-15 02:13:44",
            "stage":          "reconnaissance",
            "description":    "Failed SSH login from 185.220.101.45",
            "source":         "AUTH.LOG",
            "actor":          "unknown",
            "technique_id":   "T1110",
            "technique_name": "Brute Force",
            "iocs_involved":  ["185.220.101.45"],
            "confidence":     "high",
        },
        {
            "timestamp":      "2024-01-15 02:14:18",
            "stage":          "exploitation",
            "description":    "Successful SSH login from 185.220.101.45",
            "source":         "AUTH.LOG",
            "actor":          "unknown",
            "technique_id":   "T1110",
            "technique_name": "Brute Force",
            "iocs_involved":  ["185.220.101.45"],
            "confidence":     "high",
        },
        {
            "timestamp":      "2024-01-15 02:22:17",
            "stage":          "exfiltration",
            "description":    "Large outbound transfer to 45.33.32.156",
            "source":         "FIREWALL",
            "actor":          "unknown",
            "technique_id":   "T1041",
            "technique_name": "Exfiltration Over C2 Channel",
            "iocs_involved":  ["45.33.32.156", "10.0.0.5"],
            "confidence":     "high",
        },
    ],
}

MOCK_THREAT_INTEL = {
    "_status": "complete",
    "_agent":  "ThreatIntel",
    "severity": "high",
    "iocs": {
        "ips":     ["185.220.101.45", "185.220.101.46"],
        "domains": ["micros0ft-update.com"],
        "hashes":  ["4a5d6f7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e"],
        "urls":    ["/gate.php"],
    },
}

MOCK_MALWARE = {
    "_status": "complete",
    "_agent":  "MalwareAnalysis",
    "classification": {"type": "trojan", "family": "invoice_dropper"},
    "threat_level": "high",
    "iocs": {
        "ips":        ["185.220.101.45"],
        "domains":    [],
        "hashes":     ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"],
        "file_paths": ["C:\\Users\\Public\\svchost32.exe"],
        "mutexes":    [],
    },
}

MOCK_LOG = {
    "_status": "complete",
    "_agent":  "LogCorrelation",
    "iocs": ["185.220.101.45", "10.0.0.5", "185.220.101.46"],
}

MOCK_DEBATE = {
    "_status":               "complete",
    "_agent":                "MultiAgentDebate",
    "final_verdict":         "Confirmed True Positive",
    "confidence_score":      88,
    "executive_summary":     "SSH brute force leading to data exfiltration confirmed.",
    "key_red_team_evidence": ["Successful login after 3 failures", "Large outbound transfer"],
    "key_blue_team_evidence":["No CVE exploited", "Could be admin activity"],
}

async def test_connection():
    print("\n" + "="*50)
    print("TEST: DB connection and schema")
    print("="*50)
    db = TimescaleClient()
    await db.connect()
    await db.create_schema()
    print(" Connected and schema created")
    await db.close()


async def test_full_investigation_lifecycle():
    print("\n" + "="*50)
    print("TEST: Full investigation lifecycle")
    print("="*50)

    db = TimescaleClient()
    await db.connect()

    inv_id = await db.create_investigation(
        input_summary="Test investigation: SSH brute force"
    )
    print(f"  Created investigation: {inv_id}")
    assert inv_id, "Should return a UUID"
    log_run_id = await db.start_agent_run(inv_id, "LogCorrelation")
    await db.finish_agent_run(log_run_id, MOCK_LOG, duration_ms=1200)
    print(f"  Agent run saved: LogCorrelation")

    intel_run_id = await db.start_agent_run(inv_id, "ThreatIntel")
    await db.finish_agent_run(intel_run_id, MOCK_THREAT_INTEL, duration_ms=2300)
    print(f"  Agent run saved: ThreatIntel")
    await db.save_events(inv_id, MOCK_TIMELINE)
    print(f"  Events saved: {len(MOCK_TIMELINE['timeline'])}")
    await db.save_iocs(inv_id, {
        "log":          MOCK_LOG,
        "threat_intel": MOCK_THREAT_INTEL,
        "malware":      MOCK_MALWARE,
        "timeline":     MOCK_TIMELINE,
    })
    print(f"  IOCs saved")

    await db.save_debate_verdict(inv_id, MOCK_DEBATE)
    print(f"  Debate verdict saved")

    await db.update_investigation(
        investigation_id=inv_id,
        status="complete",
        severity="high",
        verdict="Confirmed True Positive",
        confidence=88,
        narrative=MOCK_TIMELINE["narrative"],
    )
    print(f"  Investigation updated to complete")

    full = await db.get_full_investigation(inv_id)
    assert full["investigation"]["status"] == "complete",  "Status should be complete"
    assert len(full["events"]) == 3,                       "Should have 3 events"
    assert len(full["iocs"]) > 0,                          "Should have IOCs"
    assert full["verdict"]["confidence_score"] == 88,      "Confidence should be 88"
    assert len(full["agent_runs"]) == 2,                   "Should have 2 agent runs"

    print(f"\n  Investigation read back:")
    print(f"    status     = {full['investigation']['status']}")
    print(f"    severity   = {full['investigation']['severity']}")
    print(f"    events     = {len(full['events'])}")
    print(f"    iocs       = {len(full['iocs'])}")
    print(f"    agent_runs = {len(full['agent_runs'])}")
    print(f"    verdict    = {full['verdict']['final_verdict']}")

    print("\n Full lifecycle test passed")

    await db.close()
    return inv_id


async def test_ioc_history_search(inv_id: str):
    print("\n" + "="*50)
    print("TEST: IOC history search across investigations")
    print("="*50)

    db = TimescaleClient()
    await db.connect()

    results = await db.search_ioc_history("185.220.101.45")
    assert len(results) > 0, "Should find this IP in at least one investigation"
    print(f"  Found '185.220.101.45' in {len(results)} investigation(s)")
    for r in results:
        print(f"    → inv={r['investigation_id'][:8]}... verdict={r['verdict']}")

    print(" IOC history search passed")
    await db.close()


async def test_ioc_type_inference():
    print("\n" + "="*50)
    print("TEST: IOC type inference")
    print("="*50)

    cases = [
        ("185.220.101.45",                                               "ip"),
        ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",                           "hash"),
        ("4a5d6f7e8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e", "hash"),
        ("micros0ft-update.com",                                         "domain"),
        ("https://evil.com/gate.php",                                    "url"),
        ("C:\\Users\\Public\\svchost32.exe",                             "file_path"),
        ("/usr/bin/svchost32",                                           "file_path"),
        ("somethingrandom",                                              "unknown"),
    ]

    for value, expected in cases:
        got = _infer_ioc_type(value)
        status = "✅" if got == expected else "❌"
        print(f"  {status} '{value[:40]:<40}' → {got} (expected {expected})")
        assert got == expected, f"Expected {expected} got {got} for {value}"

    print(" IOC type inference passed")


async def test_list_investigations():
    print("\n" + "="*50)
    print("TEST: List investigations")
    print("="*50)

    db = TimescaleClient()
    await db.connect()

    investigations = await db.list_investigations(limit=10)
    print(f"  Found {len(investigations)} investigation(s)")
    for inv in investigations:
        print(f"    → {inv['id'][:8]}... status={inv['status']} severity={inv['severity']}")

    assert len(investigations) > 0, "Should have at least one investigation from previous tests"
    print(" List investigations passed")
    await db.close()


async def test_all():
    print("\n Running all DB tests...\n")

    await test_connection()
    await test_ioc_type_inference()
    inv_id = await test_full_investigation_lifecycle()
    await test_ioc_history_search(inv_id)
    await test_list_investigations()

    print("\n" + "="*50)
    print(" ALL DB TESTS PASSED")
    print("="*50)


if __name__ == "__main__":
    asyncio.run(test_all())