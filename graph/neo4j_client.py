import os
import logging
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class Neo4jClient:
    """
    Thin wrapper around the Neo4j driver.
    Handles connection, constraint creation, and all write/query operations.
    One instance shared across all agents.
    """

    def __init__(self):
        self._driver = GraphDatabase.driver(
            os.getenv("NEO4J_URI"),
            auth=(
                os.getenv("NEO4J_USER"),
                os.getenv("NEO4J_PASSWORD"),
            )
        )
        self._database = os.getenv("NEO4J_DATABASE", "neo4j")
        logger.info("[Neo4j] Driver initialised")

    def close(self):
        self._driver.close()

    def verify_connection(self) -> bool:
        try:
            self._driver.verify_connectivity()
            logger.info("[Neo4j] Connection verified")
            return True
        except Exception as e:
            logger.error(f"[Neo4j] Connection failed: {e}")
            return False

    def _run(self, query: str, params: dict = None):
        """Execute a single Cypher query."""
        with self._driver.session(database=self._database) as session:
            return session.run(query, params or {}).data()

    # ── Schema / Constraints ──────────────────────────────────────────── #

    def create_constraints(self):
        """
        Idempotent — safe to call on every startup.
        Creates uniqueness constraints so MERGE works correctly.
        """
        constraints = [
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.ip IS UNIQUE",
            "CREATE CONSTRAINT domain_unique IF NOT EXISTS FOR (n:Domain) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT hash_unique IF NOT EXISTS FOR (n:FileHash) REQUIRE n.hash IS UNIQUE",
            "CREATE CONSTRAINT actor_unique IF NOT EXISTS FOR (n:ThreatActor) REQUIRE n.name IS UNIQUE",
            "CREATE CONSTRAINT technique_unique IF NOT EXISTS FOR (n:Technique) REQUIRE n.technique_id IS UNIQUE",
            "CREATE CONSTRAINT malware_unique IF NOT EXISTS FOR (n:Malware) REQUIRE n.family IS UNIQUE",
            "CREATE CONSTRAINT cve_unique IF NOT EXISTS FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE",
            "CREATE CONSTRAINT event_unique IF NOT EXISTS FOR (n:KillChainEvent) REQUIRE n.event_id IS UNIQUE",
        ]
        for c in constraints:
            try:
                self._run(c)
            except Exception as e:
                logger.warning(f"[Neo4j] Constraint skipped: {e}")
        logger.info("[Neo4j] Constraints ready")

    # ── Node writers ──────────────────────────────────────────────────── #

    def merge_ip(self, ip: str, first_seen: str = "", last_seen: str = ""):
        self._run(
            """
            MERGE (n:IPAddress {ip: $ip})
            SET n.first_seen = CASE WHEN n.first_seen = '' OR n.first_seen IS NULL
                               THEN $first_seen ELSE n.first_seen END,
                n.last_seen  = $last_seen
            """,
            {"ip": ip, "first_seen": first_seen, "last_seen": last_seen}
        )

    def merge_domain(self, name: str, first_seen: str = ""):
        self._run(
            "MERGE (n:Domain {name: $name}) SET n.first_seen = $first_seen",
            {"name": name, "first_seen": first_seen}
        )

    def merge_hash(self, hash_val: str, algorithm: str = "sha256", file_name: str = ""):
        self._run(
            """
            MERGE (n:FileHash {hash: $hash})
            SET n.algorithm = $algorithm, n.file_name = $file_name
            """,
            {"hash": hash_val, "algorithm": algorithm, "file_name": file_name}
        )

    def merge_threat_actor(self, name: str, confidence: str = "low", aliases: list = None):
        self._run(
            """
            MERGE (n:ThreatActor {name: $name})
            SET n.confidence = $confidence, n.aliases = $aliases
            """,
            {"name": name, "confidence": confidence, "aliases": aliases or []}
        )

    def merge_technique(self, technique_id: str, name: str = "", tactic: str = ""):
        if not technique_id:
            return
        self._run(
            """
            MERGE (n:Technique {technique_id: $technique_id})
            SET n.name = $name, n.tactic = $tactic
            """,
            {"technique_id": technique_id, "name": name, "tactic": tactic}
        )

    def merge_malware(self, family: str, malware_type: str = "unknown", threat_level: str = "unknown"):
        self._run(
            """
            MERGE (n:Malware {family: $family})
            SET n.type = $type, n.threat_level = $threat_level
            """,
            {"family": family, "type": malware_type, "threat_level": threat_level}
        )

    def merge_cve(self, cve_id: str, severity: str = "unknown", description: str = ""):
        if not cve_id:
            return
        self._run(
            """
            MERGE (n:CVE {cve_id: $cve_id})
            SET n.severity = $severity, n.description = $description
            """,
            {"cve_id": cve_id, "severity": severity, "description": description}
        )

    def merge_event(
        self,
        event_id:       str,
        timestamp:      str,
        stage:          str,
        description:    str,
        source:         str = "",
        technique_id:   str = "",
        technique_name: str = "",
        confidence:     str = "low",
    ):
        self._run(
            """
            MERGE (n:KillChainEvent {event_id: $event_id})
            SET n.timestamp      = $timestamp,
                n.stage          = $stage,
                n.description    = $description,
                n.source         = $source,
                n.technique_id   = $technique_id,
                n.technique_name = $technique_name,
                n.confidence     = $confidence
            """,
            {
                "event_id": event_id, "timestamp": timestamp,
                "stage": stage, "description": description,
                "source": source, "technique_id": technique_id,
                "technique_name": technique_name, "confidence": confidence,
            }
        )

    # ── Relationship writers ──────────────────────────────────────────── #

    def link_actor_uses_technique(self, actor_name: str, technique_id: str):
        self._run(
            """
            MATCH (a:ThreatActor {name: $actor}), (t:Technique {technique_id: $tid})
            MERGE (a)-[:USES]->(t)
            """,
            {"actor": actor_name, "tid": technique_id}
        )

    def link_actor_deploys_malware(self, actor_name: str, malware_family: str):
        self._run(
            """
            MATCH (a:ThreatActor {name: $actor}), (m:Malware {family: $family})
            MERGE (a)-[:DEPLOYS]->(m)
            """,
            {"actor": actor_name, "family": malware_family}
        )

    def link_event_involves_ip(self, event_id: str, ip: str):
        self._run(
            """
            MATCH (e:KillChainEvent {event_id: $eid}), (i:IPAddress {ip: $ip})
            MERGE (e)-[:INVOLVES]->(i)
            """,
            {"eid": event_id, "ip": ip}
        )

    def link_event_involves_domain(self, event_id: str, domain: str):
        self._run(
            """
            MATCH (e:KillChainEvent {event_id: $eid}), (d:Domain {name: $domain})
            MERGE (e)-[:INVOLVES]->(d)
            """,
            {"eid": event_id, "domain": domain}
        )

    def link_event_involves_hash(self, event_id: str, hash_val: str):
        self._run(
            """
            MATCH (e:KillChainEvent {event_id: $eid}), (h:FileHash {hash: $hash})
            MERGE (e)-[:INVOLVES]->(h)
            """,
            {"eid": event_id, "hash": hash_val}
        )

    def link_event_uses_technique(self, event_id: str, technique_id: str):
        if not technique_id:
            return
        self._run(
            """
            MATCH (e:KillChainEvent {event_id: $eid}), (t:Technique {technique_id: $tid})
            MERGE (e)-[:USES]->(t)
            """,
            {"eid": event_id, "tid": technique_id}
        )

    def link_event_attributed_to_actor(self, event_id: str, actor_name: str):
        self._run(
            """
            MATCH (e:KillChainEvent {event_id: $eid}), (a:ThreatActor {name: $actor})
            MERGE (e)-[:ATTRIBUTED_TO]->(a)
            """,
            {"eid": event_id, "actor": actor_name}
        )

    def link_malware_connects_to_ip(self, malware_family: str, ip: str):
        self._run(
            """
            MATCH (m:Malware {family: $family}), (i:IPAddress {ip: $ip})
            MERGE (m)-[:CONNECTS_TO]->(i)
            """,
            {"family": malware_family, "ip": ip}
        )

    def link_malware_uses_technique(self, malware_family: str, technique_id: str):
        if not technique_id:
            return
        self._run(
            """
            MATCH (m:Malware {family: $family}), (t:Technique {technique_id: $tid})
            MERGE (m)-[:USES]->(t)
            """,
            {"family": malware_family, "tid": technique_id}
        )

    def link_malware_exploits_cve(self, malware_family: str, cve_id: str):
        if not cve_id:
            return
        self._run(
            """
            MATCH (m:Malware {family: $family}), (c:CVE {cve_id: $cve_id})
            MERGE (m)-[:EXPLOITS]->(c)
            """,
            {"family": malware_family, "cve_id": cve_id}
        )

    def link_ip_resolves_to_domain(self, ip: str, domain: str):
        self._run(
            """
            MATCH (i:IPAddress {ip: $ip}), (d:Domain {name: $domain})
            MERGE (i)-[:RESOLVES_TO]->(d)
            """,
            {"ip": ip, "domain": domain}
        )

    def link_event_precedes_event(self, event_id_before: str, event_id_after: str):
        self._run(
            """
            MATCH (a:KillChainEvent {event_id: $before}),
                  (b:KillChainEvent {event_id: $after})
            MERGE (a)-[:PRECEDES]->(b)
            """,
            {"before": event_id_before, "after": event_id_after}
        )

    # ── Query helpers ─────────────────────────────────────────────────── #

    def get_all_iocs(self) -> dict:
        """Return all IOC nodes grouped by type."""
        return {
            "ips":     self._run("MATCH (n:IPAddress) RETURN n.ip AS ip"),
            "domains": self._run("MATCH (n:Domain) RETURN n.name AS name"),
            "hashes":  self._run("MATCH (n:FileHash) RETURN n.hash AS hash"),
        }

    def get_attack_path(self) -> list:
        """Return full attack path ordered by timestamp."""
        return self._run(
            """
            MATCH (e:KillChainEvent)
            RETURN e.timestamp AS timestamp, e.stage AS stage,
                   e.description AS description, e.technique_id AS technique_id
            ORDER BY e.timestamp ASC
            """
        )

    def clear_all(self):
        """Wipe everything — useful between test investigations."""
        self._run("MATCH (n) DETACH DELETE n")
        logger.warning("[Neo4j] All nodes and relationships deleted")