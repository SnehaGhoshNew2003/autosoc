import os
import pytest
# Adjust this import if your folder structure uses a different naming convention
from agents.report_generator_agent import ReportGeneratorAgent

@pytest.fixture
def mock_upstream_success_data():
    """Provides a complete set of mock forensic context data from upstream agents."""
    return {
        "log_correlation": {
            "_status": "complete",
            "attack_vector": "Spearphishing Link",
            "summary": "Initial access gained via malicious link execution.",
            "anomalies": [{"pattern": "Unusual PowerShell", "risk_level": "high"}],
            "all_techniques": ["T1566.001", "T1059.001"],
            "dwell_time_minutes": 120,
        },
        "malware_analysis": {
            "_status": "complete",
            "type": "unknown",
            "family": "unknown",
            "threat_level": "critical",
            "capabilities": ["credential_stealing", "keylogging"],
            "summary": "Malicious binary establishing persistence via registry modification."
        },
        "threat_intel": {
            "_status": "complete",
            "summary": "Campaign matched against known APT29 playbooks.",
            "identified_actors": ["APT29"],
            "exploited_cves": ["CVE-2023-38831"]
        },
        "timeline_reconstruction": {
            "_status": "complete",
            "narrative": "Attacker compromised user workstation, installed malware, and attempted exfiltration.",
            "furthest_stage_reached": "unknown",
            "dwell_time": "0 minutes",
            "operational_flags": {
                "Lateral Move": "None", 
                "PrivEsc": "None", 
                "Exfil": "None", 
                "Persistence": "None"
            },
            "total_timeline_events": 0,
            "consolidated_techniques": ["T1566.001", "T1059.001"],
            "consolidated_iocs": ["192.168.1.50", "bad-domain.com", "098f6bcd4621d373cade4e832627b4f6"]
        }
    }

@pytest.mark.asyncio
@pytest.mark.integration
async def test_report_generator_live_llm(mock_upstream_success_data):
    """
    [INTEGRATION] Invokes the live LLM (requires GROQ_API_KEY).
    Run explicitly via: pytest -v -m integration -s
    """
    if not os.getenv("GROQ_API_KEY"):
        pytest.skip("Skipping live LLM test: GROQ_API_KEY environment variable not set.")

    agent = ReportGeneratorAgent()
    result = await agent.run(
        log_correlation_result=mock_upstream_success_data["log_correlation"],
        malware_result=mock_upstream_success_data["malware_analysis"],
        threat_intel_result=mock_upstream_success_data["threat_intel"],
        timeline_result=mock_upstream_success_data["timeline_reconstruction"]
    )

    # Print out the generated report during test execution
    print("\n" + "="*40 + " GENERATED MARKDOWN REPORT " + "="*40)
    print(result.get("formatted_markdown"))
    print("=" * 107 + "\n")

    # Assert model fulfilled structured output boundaries
    assert result is not None
    assert result.get("_status") == "complete"