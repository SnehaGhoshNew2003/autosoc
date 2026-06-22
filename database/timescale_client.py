import os
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import asyncpg
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class TimescaleClient:
    """
    Async TimescaleDB client using a connection pool.

    A connection pool means we don't open/close a DB connection for every
    query — we keep N connections open and reuse them. This is critical
    when 6 agents are all trying to write results at the same time.

    Usage pattern (in main.py / orchestrator):

        client = TimescaleClient()
        await client.connect()           # open pool once at startup
        ...
        await client.close()             # close pool at shutdown

    All methods are async — they use `await` so the event loop stays free.
    """

    def __init__(self):
        self._pool: Optional[asyncpg.Pool] = None
        self._dsn = os.getenv("DATABASE_URL")
        if not self._dsn:
            self._dsn = (
                f"postgresql://{os.getenv('TIMESCALE_USER')}"
                f":{os.getenv('TIMESCALE_PASSWORD')}"
                f"@{os.getenv('TIMESCALE_HOST')}"
                f":{os.getenv('TIMESCALE_PORT')}"
                f"/{os.getenv('TIMESCALE_DB')}"
            )
        self._database_name = self._parse_database_name()

    def _parse_database_name(self) -> str:
        """Extract database name from DSN."""
        # Prefer TIMESCALE_DB env var if set
        timescale_db = os.getenv("TIMESCALE_DB")
        if timescale_db:
            return timescale_db
        if not self._dsn:
            return "unknown"
        try:
            parsed = urlparse(self._dsn)
            dbname = parsed.path.lstrip("/")
            return dbname if dbname else "unknown"
        except Exception:
            return "unknown"

    def get_database_name(self) -> str:
        """Return the configured database name."""
        return self._database_name

    async def connect(self, min_size: int = 2, max_size: int = 10):
        """
        Open the connection pool.
        min_size = connections always kept open (ready immediately)
        max_size = maximum concurrent connections allowed
        Call this once at application startup.
        """
        self._pool = await asyncpg.create_pool(
            dsn=self._dsn,
            min_size=min_size,
            max_size=max_size,
        )
        logger.info(f"[TimescaleDB] Pool opened (min={min_size}, max={max_size})")

    async def close(self):
        """Close the pool. Call once at shutdown."""
        if self._pool:
            await self._pool.close()
            logger.info("[TimescaleDB] Pool closed")

    async def _execute(self, query: str, *args):
        """Run a single write query (INSERT, UPDATE, DELETE)."""
        async with self._pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def _fetch(self, query: str, *args) -> list:
        """Run a read query and return all rows as a list of dicts."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(r) for r in rows]

    async def _fetchrow(self, query: str, *args) -> Optional[dict]:
        """Run a read query and return one row (or None)."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def create_schema(self):
        """
        Create all tables and hypertables.
        Idempotent — safe to call on every startup.
        Uses IF NOT EXISTS everywhere so re-running never errors.

        TABLE DESIGN DECISIONS:
          investigations  — one row per investigation run (the parent)
          agent_runs      — one row per agent per investigation (6 rows per run)
          events          — every kill-chain event from the timeline agent
          iocs            — every IOC extracted across all agents, deduplicated
          debate_verdicts — the final multi-agent debate output

        events and iocs are converted to TimescaleDB hypertables because
        they're the tables analysts will query by time range most often.
        """
        async with self._pool.acquire() as conn:
            await conn.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    status          TEXT NOT NULL DEFAULT 'running',
                    -- status values: running | complete | error
                    input_summary   TEXT,
                    -- brief description of what evidence was submitted
                    severity        TEXT,
                    -- final severity after debate: critical|high|medium|low
                    verdict         TEXT,
                    -- final verdict string from MultiAgentDebate
                    confidence      INT,
                    -- 0-100 confidence score from debate
                    narrative       TEXT
                    -- executive narrative from ReportGenerator
                );
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_runs (
                    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    ran_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    agent_name        TEXT NOT NULL,
                    -- values: LogCorrelation | ThreatIntel | MalwareAnalysis |
                    --         TimelineReconstruction | AttackGraph |
                    --         ReportGenerator | MultiAgentDebate
                    status            TEXT NOT NULL DEFAULT 'running',
                    -- values: running | complete | error
                    duration_ms       INT,
                    -- how long the agent took in milliseconds
                    error_message     TEXT,
                    result_json       JSONB
                    -- the full dict returned by agent.run()
                    -- JSONB lets you query inside the JSON with Postgres operators
                );
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id                UUID DEFAULT gen_random_uuid(),
                    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    event_time        TIMESTAMPTZ NOT NULL,
                    -- ↑ This is the hypertable partition column
                    stage             TEXT,
                    description       TEXT,
                    source            TEXT,
                    actor             TEXT,
                    technique_id      TEXT,
                    technique_name    TEXT,
                    confidence        TEXT,
                    iocs_involved     TEXT[],
                    -- PostgreSQL array — stores ["185.220.101.45", "10.0.0.5"]
                    PRIMARY KEY (id, event_time)
                    -- Composite PK required for TimescaleDB hypertables
                );
            """)

            try:
                await conn.execute("""
                    SELECT create_hypertable(
                        'events', 'event_time',
                        if_not_exists => TRUE
                    );
                """)
                logger.info("[TimescaleDB] events hypertable ready")
            except Exception as e:
                logger.debug(f"[TimescaleDB] events hypertable already exists: {e}")

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id                UUID DEFAULT gen_random_uuid(),
                    investigation_id  UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    first_seen        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    -- ↑ Hypertable partition column
                    ioc_type          TEXT NOT NULL,
                    -- ip | domain | hash | url | file_path | mutex
                    value             TEXT NOT NULL,
                    source_agent      TEXT,
                    -- which agent found this IOC
                    context           TEXT,
                    -- optional: what malware family used this IP, etc.
                    PRIMARY KEY (id, first_seen),
                    UNIQUE (investigation_id, ioc_type, value)
                    -- Prevent duplicate IOCs per investigation
                );
            """)

            try:
                await conn.execute("""
                    SELECT create_hypertable(
                        'iocs', 'first_seen',
                        if_not_exists => TRUE
                    );
                """)
                logger.info("[TimescaleDB] iocs hypertable ready")
            except Exception as e:
                logger.debug(f"[TimescaleDB] iocs hypertable already exists: {e}")

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS debate_verdicts (
                    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    investigation_id      UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    final_verdict         TEXT,
                    confidence_score      INT,
                    executive_summary     TEXT,
                    red_team_evidence     JSONB,
                    -- list of red team argument strings
                    blue_team_evidence    JSONB,
                    -- list of blue team argument strings
                    full_result_json      JSONB
                    -- the complete debate result dict
                );
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_runs_investigation
                ON agent_runs (investigation_id);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_investigation
                ON events (investigation_id, event_time DESC);
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_value
                ON iocs (value);
                -- Fast lookup: "has this IP appeared before?"
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_iocs_type
                ON iocs (ioc_type, first_seen DESC);
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_conversations (
                    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    title             TEXT NOT NULL DEFAULT 'New Chat',
                    is_deleted        BOOLEAN NOT NULL DEFAULT FALSE,
                    investigation_id  UUID REFERENCES investigations(id) ON DELETE SET NULL
                );
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    conversation_id UUID NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
                    role            TEXT NOT NULL,
                    content         TEXT NOT NULL,
                    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_conv_active
                ON chat_conversations (is_deleted, updated_at DESC);
            """)

            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_msg_conv
                ON chat_messages (conversation_id, created_at ASC);
            """)

        logger.info("[TimescaleDB] Schema ready")

    async def reclassify_all_iocs(self):
        """
        Re-infer ioc_type for all existing IOCs based on their actual value.
        Fixes misclassifications from old code that overrode agent labels.
        Safe to call on every startup — only updates rows where type changed.
        """
        rows = await self._fetch("SELECT id::TEXT, value FROM iocs")
        logger.info(f"[TimescaleDB] reclassify_all_iocs: found {len(rows)} rows in iocs table")
        updated = 0
        for row in rows:
            correct_type = _infer_ioc_type(row["value"])
            result = await self._execute(
                "UPDATE iocs SET ioc_type = $1 WHERE id = $2::UUID AND ioc_type != $1",
                correct_type, row["id"],
            )
            if result == "UPDATE 1":
                updated += 1
        if updated:
            logger.info(f"[TimescaleDB] Reclassified {updated} IOC types based on actual values")
        else:
            logger.info(f"[TimescaleDB] No IOC types needed reclassification (0 updates out of {len(rows)} rows)")

    async def create_investigation(self, input_summary: str = "") -> str:
        """
        Create a new investigation record and return its UUID as a plain string.
        Call this before running any agents — the UUID is passed to
        all subsequent save_ calls to link results to this investigation.
        """
        row = await self._fetchrow(
            """
            INSERT INTO investigations (input_summary)
            VALUES ($1)
            RETURNING id::TEXT
            """,
            input_summary,
        )
        investigation_id = row["id"]
        logger.info(f"[TimescaleDB] Investigation created: {investigation_id}")
        return investigation_id

    async def update_investigation(
        self,
        investigation_id: str,
        status:    str  = "complete",
        severity:  str  = None,
        verdict:   str  = None,
        confidence: int = None,
        narrative: str  = None,
    ):
        """
        Update the top-level investigation record after all agents finish.
        Called by the orchestrator at the end of the pipeline.
        """
        await self._execute(
            """
            UPDATE investigations
            SET status     = $1,
                severity   = COALESCE($2, severity),
                verdict    = COALESCE($3, verdict),
                confidence = COALESCE($4, confidence),
                narrative  = COALESCE($5, narrative)
            WHERE id = $6::UUID
            """,
            status, severity, verdict, confidence, narrative,
            investigation_id,
        )
        logger.info(f"[TimescaleDB] Investigation updated: {investigation_id} → {status}")

    async def start_agent_run(
        self,
        investigation_id: str,
        agent_name:       str,
    ) -> str:
        """
        Record that an agent has started running.
        Returns the agent_run UUID as a plain string so you can update
        it when it finishes.

        Usage in orchestrator:
            run_id = await db.start_agent_run(inv_id, "LogCorrelation")
            result = await log_agent.run(evidence)
            await db.finish_agent_run(run_id, result)
        """
        row = await self._fetchrow(
            """
            INSERT INTO agent_runs (investigation_id, agent_name, status)
            VALUES ($1::UUID, $2, 'running')
            RETURNING id::TEXT
            """,
            investigation_id, agent_name,
        )
        return row["id"]

    async def finish_agent_run(
        self,
        run_id:      str,
        result:      dict,
        duration_ms: int = 0,
    ):
        """
        Update an agent run with its result once it finishes.
        Stores the full result dict as JSONB so nothing is ever lost.
        """
        status        = result.get("_status", "error")
        error_message = result.get("_error")

        await self._execute(
            """
            UPDATE agent_runs
            SET status        = $1,
                result_json   = $2,
                duration_ms   = $3,
                error_message = $4
            WHERE id = $5::UUID
            """,
            status,
            json.dumps(result),   
            duration_ms,
            error_message,
            run_id,
        )

    async def save_events(
        self,
        investigation_id: str,
        timeline_result:  dict,
    ):
        """
        Bulk-insert all kill-chain events from the TimelineReconstruction output.
        Uses asyncpg's executemany for efficiency — one round trip, N inserts.

        Why parse the timestamp:
            The model returns timestamps as strings like "2024-01-15 02:13:44".
            PostgreSQL TIMESTAMPTZ requires a real datetime object or ISO string.
            We parse it here so invalid timestamps fail loudly rather than
            silently storing garbage.
        """
        events = timeline_result.get("timeline", [])
        if not events:
            logger.warning("[TimescaleDB] save_events: no events to save")
            return

        rows = []
        for ev in events:
            ts_str = ev.get("timestamp", "")
            try:
                event_time = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                try:
                    event_time = datetime.fromisoformat(ts_str).replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    logger.warning(f"[TimescaleDB] Unparseable timestamp: '{ts_str}', using NOW()")
                    event_time = datetime.now(timezone.utc)

            rows.append((
                investigation_id,
                event_time,
                ev.get("stage", "unknown"),
                ev.get("description", ""),
                ev.get("source", ""),
                ev.get("actor", ""),
                ev.get("technique_id", ""),
                ev.get("technique_name", ""),
                ev.get("confidence", "low"),
                ev.get("iocs_involved", []), 
            ))

        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO events (
                    investigation_id, event_time, stage, description,
                    source, actor, technique_id, technique_name,
                    confidence, iocs_involved
                )
                VALUES ($1::UUID, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT DO NOTHING
                """,
                rows,
            )
        logger.info(f"[TimescaleDB] Saved {len(rows)} events for {investigation_id}")


    async def save_iocs(
        self,
        investigation_id: str,
        agent_results:    dict,
    ):
        """
        Extract and save all IOCs from all agent results.
        De-duplicates per investigation via the UNIQUE constraint
        (investigation_id, ioc_type, value).

        Pulls IOCs from:
          - ThreatIntelAgent:       result["iocs"]["ips/domains/hashes/urls"]
          - MalwareAnalysisAgent:   result["iocs"]["ips/domains/hashes/file_paths"]
          - TimelineReconstruction: result["all_iocs"] (flat list, needs type inference)
          - LogCorrelationAgent:    result["iocs"] (flat list, needs type inference)

        agent_results should be a dict like:
            {
                "threat_intel":  <ThreatIntelAgent output dict>,
                "malware":       <MalwareAnalysisAgent output dict>,
                "timeline":      <TimelineReconstructionAgent output dict>,
                "log":           <LogCorrelationAgent output dict>,
            }
        """
        rows = []


        def _add(ioc_type: str, value: str, source_agent: str, context: str = ""):
            value = value.strip()
            if not value:
                return

            if ":" in value:
                ip_candidate = value.split(":")[0]
                parts = ip_candidate.split(".")
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    value = ip_candidate   
                    ioc_type = "ip"        

            if ioc_type == "unknown":
                ioc_type = _infer_ioc_type(value)

            rows.append((investigation_id, ioc_type, value, source_agent, context))

        ti = agent_results.get("threat_intel", {})
        if ti.get("_status") == "complete":
            iocs = ti.get("iocs", {})
            for ip     in iocs.get("ips",     []): _add("ip",     ip,     "ThreatIntel")
            for domain in iocs.get("domains", []): _add("domain", domain, "ThreatIntel")
            for h      in iocs.get("hashes",  []): _add("hash",   h,      "ThreatIntel")
            for url    in iocs.get("urls",    []): _add("url",    url,    "ThreatIntel")

        mal = agent_results.get("malware", {})
        if mal.get("_status") == "complete":
            iocs   = mal.get("iocs", {})
            family = mal.get("classification", {}).get("family", "unknown")
            for ip   in iocs.get("ips",        []): _add("ip",        ip,   "MalwareAnalysis", f"malware:{family}")
            for dom  in iocs.get("domains",    []): _add("domain",    dom,  "MalwareAnalysis", f"malware:{family}")
            for h    in iocs.get("hashes",     []): _add("hash",      h,    "MalwareAnalysis", f"malware:{family}")
            for path in iocs.get("file_paths", []): _add("file_path", path, "MalwareAnalysis", f"malware:{family}")
            for mut  in iocs.get("mutexes",    []): _add("mutex",     mut,  "MalwareAnalysis", f"malware:{family}")

        log = agent_results.get("log", {})
        if log.get("_status") == "complete":
            for ioc in log.get("iocs", []):
                ioc_type = _infer_ioc_type(ioc)
                _add(ioc_type, ioc, "LogCorrelation")

        tl = agent_results.get("timeline", {})
        if tl.get("_status") == "complete":
            for ioc in tl.get("all_iocs", []):
                ioc_type = _infer_ioc_type(ioc)
                _add(ioc_type, ioc, "TimelineReconstruction")

        if not rows:
            logger.warning("[TimescaleDB] save_iocs: no IOCs to save")
            return

        async with self._pool.acquire() as conn:
            await conn.executemany(
                """
                INSERT INTO iocs (
                    investigation_id, ioc_type, value, source_agent, context
                )
                VALUES ($1::UUID, $2, $3, $4, $5)
                ON CONFLICT (investigation_id, ioc_type, value) DO NOTHING
                """,
                rows,
            )
        logger.info(f"[TimescaleDB] Saved {len(rows)} IOC rows for {investigation_id}")

    async def save_debate_verdict(
        self,
        investigation_id: str,
        debate_result:    dict,
    ):
        """
        Save the Multi-Agent Debate verdict.
        Also updates the parent investigation row with the final severity/verdict.
        """
        await self._execute(
            """
            INSERT INTO debate_verdicts (
                investigation_id, final_verdict, confidence_score,
                executive_summary, red_team_evidence,
                blue_team_evidence, full_result_json
            )
            VALUES ($1::UUID, $2, $3, $4, $5, $6, $7)
            """,
            investigation_id,
            debate_result.get("final_verdict"),
            debate_result.get("confidence_score"),
            debate_result.get("executive_summary"),
            json.dumps(debate_result.get("key_red_team_evidence",  [])),
            json.dumps(debate_result.get("key_blue_team_evidence", [])),
            json.dumps(debate_result),
        )

        await self.update_investigation(
            investigation_id=investigation_id,
            status="complete",
            verdict=debate_result.get("final_verdict"),
            confidence=debate_result.get("confidence_score"),
        )
        logger.info(f"[TimescaleDB] Debate verdict saved for {investigation_id}")

    async def get_investigation(self, investigation_id: str) -> Optional[dict]:
        """
        Fetch a single investigation by ID.
        UUID columns cast to TEXT so callers always receive plain strings.
        """
        return await self._fetchrow(
            """
            SELECT id::TEXT,
                   created_at,
                   status,
                   severity,
                   verdict,
                   confidence,
                   input_summary,
                   narrative
            FROM investigations
            WHERE id = $1::UUID
            """,
            investigation_id,
        )

    async def list_investigations(self, limit: int = 50) -> list:
        """
        List the most recent investigations.
        Used by the Streamlit history page.
        UUID cast to TEXT so callers can safely do string ops like [:8].
        """
        return await self._fetch(
            """
            SELECT id::TEXT,
                   created_at,
                   status,
                   severity,
                   verdict,
                   confidence,
                   input_summary
            FROM investigations
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )

    async def get_agent_runs(self, investigation_id: str) -> list:
        """
        Get all agent runs for an investigation.
        Used to show the per-agent status panel in the UI.
        Both UUID columns cast to TEXT.
        """
        return await self._fetch(
            """
            SELECT id::TEXT,
                   investigation_id::TEXT,
                   agent_name,
                   status,
                   duration_ms,
                   error_message,
                   ran_at,
                   result_json
            FROM agent_runs
            WHERE investigation_id = $1::UUID
            ORDER BY ran_at ASC
            """,
            investigation_id,
        )

    async def get_events(
        self,
        investigation_id: str,
        stage:            Optional[str] = None,
    ) -> list:
        """
        Get kill-chain events for an investigation.
        Optionally filter by stage (e.g. "exfiltration").

        This is where TimescaleDB shines — even with millions of events
        across many investigations, the hypertable partition makes this
        query fast because it only opens the relevant time chunk.

        Both UUID columns cast to TEXT.
        """
        base_query = """
            SELECT id::TEXT,
                   investigation_id::TEXT,
                   event_time,
                   stage,
                   description,
                   source,
                   actor,
                   technique_id,
                   technique_name,
                   confidence,
                   iocs_involved
            FROM events
            WHERE investigation_id = $1::UUID
        """
        if stage:
            return await self._fetch(
                base_query + " AND stage = $2 ORDER BY event_time ASC",
                investigation_id, stage,
            )
        return await self._fetch(
            base_query + " ORDER BY event_time ASC",
            investigation_id,
        )

    async def get_iocs(
        self,
        investigation_id: str,
        ioc_type:         Optional[str] = None,
    ) -> list:
        """
        Get IOCs for an investigation, optionally filtered by type.
        e.g. get_iocs(inv_id, ioc_type="ip") returns only IP addresses.
        Both UUID columns cast to TEXT.
        """
        base_query = """
            SELECT id::TEXT,
                   investigation_id::TEXT,
                   ioc_type,
                   value,
                   source_agent,
                   context,
                   first_seen
            FROM iocs
            WHERE investigation_id = $1::UUID
        """
        if ioc_type:
            return await self._fetch(
                base_query + " AND ioc_type = $2 ORDER BY first_seen ASC",
                investigation_id, ioc_type,
            )
        return await self._fetch(
            base_query + " ORDER BY ioc_type, first_seen ASC",
            investigation_id,
        )

    async def search_ioc_history(self, value: str) -> list:
        """
        Search for an IOC value across ALL investigations.
        Answers the analyst question: 'Has this IP appeared in any past case?'
        investigation_id cast to TEXT so callers can safely slice it (e.g. [:8]).
        """
        return await self._fetch(
            """
            SELECT i.value,
                   i.ioc_type,
                   i.source_agent,
                   i.first_seen,
                   inv.id::TEXT        AS investigation_id,
                   inv.created_at,
                   inv.verdict
            FROM iocs i
            JOIN investigations inv ON i.investigation_id = inv.id
            WHERE i.value = $1
            ORDER BY i.first_seen DESC
            """,
            value,
        )

    async def get_debate_verdict(self, investigation_id: str) -> Optional[dict]:
        """
        Get the debate verdict for an investigation.
        Both UUID columns cast to TEXT.
        """
        return await self._fetchrow(
            """
            SELECT id::TEXT,
                   investigation_id::TEXT,
                   created_at,
                   final_verdict,
                   confidence_score,
                   executive_summary,
                   red_team_evidence,
                   blue_team_evidence,
                   full_result_json
            FROM debate_verdicts
            WHERE investigation_id = $1::UUID
            """,
            investigation_id,
        )

    async def create_conversation(self, title: str = "New Chat", investigation_id: Optional[str] = None) -> str:
        row = await self._fetchrow(
            """
            INSERT INTO chat_conversations (title, investigation_id)
            VALUES ($1, $2::UUID)
            RETURNING id::TEXT
            """,
            title, investigation_id,
        )
        return row["id"]

    async def list_conversations(self, include_deleted: bool = False) -> list:
        if include_deleted:
            return await self._fetch(
                "SELECT id::TEXT, created_at, updated_at, title, is_deleted, investigation_id::TEXT "
                "FROM chat_conversations ORDER BY updated_at DESC"
            )
        return await self._fetch(
            "SELECT id::TEXT, created_at, updated_at, title, is_deleted, investigation_id::TEXT "
            "FROM chat_conversations WHERE is_deleted = FALSE ORDER BY updated_at DESC"
        )

    async def get_conversation(self, conversation_id: str) -> Optional[dict]:
        return await self._fetchrow(
            "SELECT id::TEXT, created_at, updated_at, title, is_deleted, investigation_id::TEXT "
            "FROM chat_conversations WHERE id = $1::UUID",
            conversation_id,
        )

    async def soft_delete_conversation(self, conversation_id: str) -> bool:
        result = await self._execute(
            "UPDATE chat_conversations SET is_deleted = TRUE, updated_at = NOW() "
            "WHERE id = $1::UUID",
            conversation_id,
        )
        return result == "UPDATE 1"

    async def update_conversation_title(self, conversation_id: str, title: str):
        await self._execute(
            "UPDATE chat_conversations SET title = $1, updated_at = NOW() WHERE id = $2::UUID",
            title, conversation_id,
        )

    async def add_chat_message(self, conversation_id: str, role: str, content: str) -> str:
        row = await self._fetchrow(
            """
            INSERT INTO chat_messages (conversation_id, role, content)
            VALUES ($1::UUID, $2, $3)
            RETURNING id::TEXT
            """,
            conversation_id, role, content,
        )
        return row["id"]

    async def get_chat_messages(self, conversation_id: str) -> list:
        return await self._fetch(
            "SELECT id::TEXT, role, content, created_at "
            "FROM chat_messages WHERE conversation_id = $1::UUID ORDER BY created_at ASC",
            conversation_id,
        )

    async def get_full_investigation(self, investigation_id: str) -> dict:
        """
        Fetch everything about an investigation in one call.
        Used by the Streamlit UI to re-open a past investigation.
        Returns a nested dict with investigation, agent_runs, events, iocs, verdict.
        All UUID columns in every sub-query are cast to TEXT.
        """
        inv     = await self.get_investigation(investigation_id)
        runs    = await self.get_agent_runs(investigation_id)
        events  = await self.get_events(investigation_id)
        iocs    = await self.get_iocs(investigation_id)
        verdict = await self.get_debate_verdict(investigation_id)

        return {
            "investigation": inv,
            "agent_runs":    runs,
            "events":        events,
            "iocs":          iocs,
            "verdict":       verdict,
        }

def _infer_ioc_type(value: str) -> str:
    """
    Infer IOC type from value format.
    Order matters — most specific checks first.
    """
    v = value.strip()
    if not v:
        return "unknown"

    if v.startswith("/") or (len(v) > 2 and v[1] == ":" and v[2] == "\\"):
        return "file_path"

    _exe_extensions = (
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        ".js", ".jar", ".sh", ".bin", ".msi", ".scr",
        ".xlsm", ".docm", ".xlsb",
    )
    lower = v.lower()
    if any(lower.endswith(ext) for ext in _exe_extensions):
        return "file_path"

    if "@" in v and "." in v.split("@")[-1]:
        return "email"

    if v.startswith("http://") or v.startswith("https://"):
        return "url"

    ip_part = v.split(":")[0] if ":" in v else v
    parts = ip_part.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ip"

    if len(v) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in v):
        return "hash"
    if len(v) >= 8 and all(c in "0123456789abcdefABCDEF" for c in v):
        return "hash"

    registry_prefixes = ("HKEY_", "HKLM\\", "HKCU\\", "HKU\\", "HKCR\\")
    if any(v.upper().startswith(p) for p in registry_prefixes):
        return "registry_key"

    mutex_prefixes = ("Global\\", "Local\\", "mutex_", "Mutex_")
    if any(v.startswith(p) for p in mutex_prefixes) or "\\" in v:
        return "mutex"

    if (
        "." in v
        and " " not in v
        and not v[0].isdigit()
        and not any(lower.endswith(ext) for ext in _exe_extensions)
    ):
        return "domain"

    return "unknown"