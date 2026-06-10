# AutoSOC — AI Cyber Investigation

An autonomous, multi-agent cybersecurity investigation platform. You feed in raw forensic evidence (logs, malware reports, threat-intel feeds) and a pipeline of specialized AI agents collaborates end-to-end to investigate the incident, reconstruct the kill chain, run an adversarial debate, and produce an executive incident report — with a confidence-scored final verdict.

## Architecture

A sequential chain of [CrewAI](https://github.com/crewAIInc/crewAI) agents, each with a domain-specific role and a strict Pydantic output schema. The LLM backend is Groq (default model: `groq/llama-3.3-70b-versatile`).

### Pipeline

| # | Agent | Role | Output |
|---|---|---|---|
| 1 | `LogCorrelationAgent` | Senior SOC Log Correlation Analyst | Correlates multi-source logs (auth, syslog, firewall, EDR, DNS, proxy, email) into a kill-chain sequence with IOCs and anomalies |
| 2 | `ThreatIntelAgent` | Senior Threat Intelligence Analyst | Extracts threat actors, TTPs, CVEs, and maps everything to MITRE ATT&CK |
| 3 | `MalwareAnalysisAgent` | Senior Malware Reverse Engineer | Classifies the sample, extracts static/behavioral IOCs, persistence, sandbox-evasion, MITRE techniques |
| 4 | `TimelineReconstructionAgent` | Senior Threat Timeline Reconstruction Analyst | Fuses the L1 outputs into a chronological kill-chain timeline with attacker profile and gaps |
| 5 | `SummarizerAgent` | Forensic Evidence Summarizer | Compresses verbose L1 outputs so the downstream agents stay within token limits |
| 6 | `MultiAgentDebate` | Red Team ↔ Blue Team ↔ CISO Judge | Adversarial debate → final confidence-scored `ThreatVerdict` |
| 7 | `ReportGeneratorAgent` | Incident Reporting Officer + Markdown Writer | Structured incident report (executive summary, technical findings, IOCs, remediation) + rendered markdown |

### Adversarial verdict reconciliation

`multi_agent_debate.py` doesn't trust any single LLM. Three sub-agents argue it out:

- **Red Team** — argues aggressively that the evidence is a true, severe attack.
- **Blue Team** — argues it is benign, a misconfiguration, or a false positive.
- **CISO Judge** — weighs both arguments against the evidence bundle and emits a `ThreatVerdict` containing the final verdict label, a `0–100` confidence score, the strongest red/blue arguments, and a 2-sentence executive summary.

CrewAI's `context=[...]` task chaining is used so the Blue Team sees the Red Team's output and the Judge sees both.

## Repository layout

```
agents/                    # 7 specialized CrewAI agents + base_agent.py
  base_agent.py            # LLM factory, Groq rate-limit-aware tenacity retry, chat history
  log_correlation_agent.py
  threat_intel_agent.py
  malware_analysis_agent.py
  timeline_reconstruction.py
  summarizer_agent.py
  multi_agent_debate.py
  report_generator_agent.py
graph/                     # Neo4j client + attack-graph builder (no LLM, pure plumbing)
  neo4j_client.py
  attack_graph_builder.py
database/                  # TimescaleDB (asyncpg) + main orchestrator
  timescale_client.py
  db_main.py               # CLI: collect evidence → run pipeline → persist → report
  test_db.py
tests/                     # pytest (asyncio_mode = auto)
.env.example               # Neo4j, Groq, Neon/TimescaleDB credentials
requirements.txt
```

## Persistence layer

- **Neo4j** (`graph/`) — attack graph: threat actors, techniques, CVEs, malware, and relationships like `USES_TECHNIQUE`, `EXPLOITS`, `ATTRIBUTED_TO`. Built by `AttackGraphBuilder` from the L1 agent outputs (pure plumbing, no LLM).
- **TimescaleDB** (`database/`, currently hosted on **Neon**) — time-series storage of investigations, per-agent runs (with start/finish/duration), IOCs, events, and final debate verdicts.

The orchestrator in `database/db_main.py`:

1. Prompts for evidence (log sources, threat-intel text, malware text).
2. Persists the raw inputs.
3. Runs the L1 agents sequentially, recording each run in the DB.
4. Runs Timeline Reconstruction + builds the Neo4j attack graph.
5. Runs the Multi-Agent Debate and saves the verdict.
6. Summarizes all L1 outputs and feeds them to the Report Generator.
7. Updates the investigation row with the final severity, verdict, confidence, and narrative.

It also supports a `rerun` mode — `python -m database.db_main rerun <investigation_id>` — that reloads the original raw inputs and re-executes the pipeline.

## Resilience

- **Groq rate-limit handling** — `base_agent._GroqRateLimitWait` parses Groq's "try again in Xm Ys" error string and backs off intelligently (down to the second) for both daily-quota and TPM throttling. The orchestrator also inserts deliberate `asyncio.sleep` pauses between heavy agent calls to keep the token bucket happy.
- **Per-source log truncation** — each log source is head/tail-truncated to 3 000 chars before correlation so one huge source can't crowd out the others.
- **Summarization boundary** — the Summarizer sits between L1 and L2 so the timeline/report agents stay within context budget.
- **Graceful degradation** — agent failures return a `_status: error` envelope with the error string instead of crashing the whole pipeline.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Copy `.env.example` to `.env` and fill in:
   - `GROQ_API_KEY`, `GROQ_MODEL` (defaults to `groq/llama-3.3-70b-versatile`)
   - `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`
   - Either local `TIMESCALE_*` vars or the Neon `DATABASE_URL`
3. Run a fresh investigation:
   ```bash
   python -m database.db_main
   ```
4. Or re-run an existing investigation from the DB:
   ```bash
   python -m database.db_main rerun <investigation_id>
   ```

## Testing

```bash
pytest
```

`pytest-asyncio` is configured with `asyncio_mode = auto`. The `integration` marker is reserved for tests that require a live LLM API key.