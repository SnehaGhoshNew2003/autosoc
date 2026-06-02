import logging
from graph.neo4j_client import Neo4jClient

logger = logging.getLogger(__name__)


class AttackGraphBuilder:
    """
    Takes outputs from all agents and writes them into Neo4j.
    This is pure plumbing — no LLM involved.

    Usage:
        builder = AttackGraphBuilder(neo4j_client)
        builder.build_from_agents(
            threat_intel_result,
            malware_result,
            timeline_result,
        )
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    def build_from_agents(
        self,
        threat_intel:    dict,
        malware:         dict,
        timeline:        dict,
    ):
        """
        Main entry point. Writes all agent outputs to Neo4j in order:
        1. Nodes first (so relationships can reference them)
        2. Relationships second
        """
        logger.info("[AttackGraph] Starting graph build...")

        self._write_threat_intel(threat_intel)
        self._write_malware(malware)
        self._write_timeline(timeline)
        self._write_timeline_relationships(timeline, threat_intel)

        logger.info("[AttackGraph] Graph build complete")

    def _write_threat_intel(self, data: dict):
        if data.get("_status") == "error":
            logger.warning("[AttackGraph] Skipping ThreatIntel — agent errored")
            return

        for actor in data.get("threat_actors", []):
            name = actor.get("name", "")
            if not name or name.lower() == "unknown":
                continue
            self.client.merge_threat_actor(
                name=name,
                confidence=actor.get("confidence", "low"),
                aliases=actor.get("aliases", []),
            )
        for ttp in data.get("ttps", []):
            tid = ttp.get("technique_id", "")
            if not tid:
                continue
            self.client.merge_technique(
                technique_id=tid,
                name=ttp.get("technique_name", ""),
                tactic=ttp.get("tactic", ""),
            )
            for actor in data.get("threat_actors", []):
                name = actor.get("name", "")
                if name and name.lower() != "unknown":
                    self.client.link_actor_uses_technique(name, tid)

        for cve in data.get("cves", []):
            cve_id = cve.get("cve_id", "")
            if cve_id:
                self.client.merge_cve(
                    cve_id=cve_id,
                    severity=cve.get("severity", "unknown"),
                    description=cve.get("description", ""),
                )

        iocs = data.get("iocs", {})
        for ip in iocs.get("ips", []):
            self.client.merge_ip(ip)
        for domain in iocs.get("domains", []):
            self.client.merge_domain(domain)
        for h in iocs.get("hashes", []):
            self.client.merge_hash(h)

        logger.info("[AttackGraph] ThreatIntel written")

    def _write_malware(self, data: dict):
        if data.get("_status") == "error":
            logger.warning("[AttackGraph] Skipping Malware — agent errored")
            return

        clf    = data.get("classification", {})
        family = clf.get("family", "unknown")

        self.client.merge_malware(
            family=family,
            malware_type=clf.get("type", "unknown"),
            threat_level=data.get("threat_level", "unknown"),
        )

        for mt in data.get("mitre_techniques", []):
            tid = mt.get("technique_id", "")
            if tid:
                self.client.merge_technique(
                    technique_id=tid,
                    name=mt.get("technique_name", ""),
                )
                self.client.link_malware_uses_technique(family, tid)

        iocs = data.get("iocs", {})
        for ip in iocs.get("ips", []):
            self.client.merge_ip(ip)
            self.client.link_malware_connects_to_ip(family, ip)
        for h in iocs.get("hashes", []):
            self.client.merge_hash(h)
        for path in iocs.get("file_paths", []):
            pass  
        ba = data.get("behavioral_analysis", {})
        for conn in ba.get("network_connections", []):
            ip = conn.get("ip", "")
            if ip:
                self.client.merge_ip(ip)
                self.client.link_malware_connects_to_ip(family, ip)

        logger.info("[AttackGraph] Malware written")

    def _write_timeline(self, data: dict):
        if data.get("_status") == "error":
            logger.warning("[AttackGraph] Skipping Timeline — agent errored")
            return

        events = data.get("timeline", [])
        for i, ev in enumerate(events):
            event_id = f"evt_{i:04d}_{ev.get('timestamp', '').replace(' ', '_').replace(':', '')}"
            self.client.merge_event(
                event_id=event_id,
                timestamp=ev.get("timestamp", ""),
                stage=ev.get("stage", "unknown"),
                description=ev.get("description", ""),
                source=ev.get("source", ""),
                technique_id=ev.get("technique_id", ""),
                technique_name=ev.get("technique_name", ""),
                confidence=ev.get("confidence", "low"),
            )

            tid = ev.get("technique_id", "")
            if tid:
                self.client.merge_technique(
                    technique_id=tid,
                    name=ev.get("technique_name", ""),
                )
                self.client.link_event_uses_technique(event_id, tid)

            for ioc in ev.get("iocs_involved", []):
                ioc = ioc.strip()
                if not ioc:
                    continue

                if "." in ioc and len(ioc.split(".")) == 4:
                    self.client.merge_ip(ioc)
                    self.client.link_event_involves_ip(event_id, ioc)
                elif len(ioc) in (32, 40, 64):   
                    self.client.merge_hash(ioc)
                    self.client.link_event_involves_hash(event_id, ioc)
                elif "." in ioc and not ioc[0].isdigit():
                    self.client.merge_domain(ioc)
                    self.client.link_event_involves_domain(event_id, ioc)

        event_ids = [
            f"evt_{i:04d}_{ev.get('timestamp', '').replace(' ', '_').replace(':', '')}"
            for i, ev in enumerate(events)
        ]
        for i in range(len(event_ids) - 1):
            self.client.link_event_precedes_event(event_ids[i], event_ids[i + 1])

        logger.info(f"[AttackGraph] Timeline written — {len(events)} events")

    def _write_timeline_relationships(self, timeline: dict, threat_intel: dict):
        """Link timeline events to threat actors from intel."""
        if (timeline.get("_status") == "error" or
                threat_intel.get("_status") == "error"):
            return

        actors = [
            a.get("name", "")
            for a in threat_intel.get("threat_actors", [])
            if a.get("name", "").lower() not in ("", "unknown")
        ]

        if not actors:
            return

        events = timeline.get("timeline", [])
        for i, ev in enumerate(events):
            event_id = f"evt_{i:04d}_{ev.get('timestamp', '').replace(' ', '_').replace(':', '')}"
            for actor in actors:
                self.client.link_event_attributed_to_actor(event_id, actor)

        logger.info(f"[AttackGraph] Event→Actor links written for {len(actors)} actors")