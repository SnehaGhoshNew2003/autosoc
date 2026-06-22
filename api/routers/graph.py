import logging
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from api.dependencies.database import get_db
from api.models.schemas import GraphStatsResponse, StatusResponse
from database.timescale_client import TimescaleClient
from graph.neo4j_client import Neo4jClient

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_neo4j() -> Neo4jClient:
    """Create a fresh Neo4j client for each request."""
    return Neo4jClient()


async def _get_events_from_db(db: TimescaleClient, investigation_id: str) -> list:
    """Fetch kill-chain events from TimescaleDB as a fallback."""
    events = await db.get_events(investigation_id)
    return [
        {
            "timestamp": str(ev.get("event_time", "")),
            "stage": ev.get("stage", "unknown"),
            "description": ev.get("description", ""),
            "technique_id": ev.get("technique_id", ""),
        }
        for ev in events
    ]


@router.get(
    "/{investigation_id}/stats",
    response_model=GraphStatsResponse,
    summary="Get graph node and relationship counts",
)
async def get_graph_stats(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()

        all_events = neo4j._run("MATCH (n:KillChainEvent) RETURN count(n) AS count")
        neo4j_has_data = all_events and all_events[0].get("count", 0) > 0

        if not neo4j_has_data:

            logger.info(f"[Graph] Neo4j empty for {investigation_id[:8]}..., falling back to TimescaleDB")
            events = await _get_events_from_db(db, investigation_id)

            neo4j.close()

            return GraphStatsResponse(
                investigation_id=investigation_id,
                node_counts={"KillChainEvent": len(events)},
                relationship_counts={},
                attack_path=events,
            )

        node_counts = {}
        for label in [
            "IPAddress", "Domain", "FileHash", "ThreatActor",
            "Technique", "Malware", "CVE", "KillChainEvent",
        ]:
            if label == "KillChainEvent":
                result = neo4j._run(
                    "MATCH (n:KillChainEvent) WHERE n.investigation_id = $inv_id OR n.investigationId = $inv_id RETURN count(n) AS count",
                    {"inv_id": investigation_id}
                )
                filtered_count = result[0]["count"] if result else 0
                node_counts[label] = filtered_count if filtered_count > 0 else all_events[0]["count"]
            else:
                result = neo4j._run(f"MATCH (n:{label}) RETURN count(n) AS count")
                node_counts[label] = result[0]["count"] if result else 0

        rel_counts = {}
        for rel in ["USES", "INVOLVES", "PRECEDES", "CONNECTS_TO",
                    "ATTRIBUTED_TO", "DEPLOYS", "EXPLOITS"]:
            result = neo4j._run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS count")
            rel_counts[rel] = result[0]["count"] if result else 0

        attack_path = neo4j.get_attack_path(investigation_id=investigation_id)
        neo4j.close()

        return GraphStatsResponse(
            investigation_id=investigation_id,
            node_counts=node_counts,
            relationship_counts=rel_counts,
            attack_path=attack_path,
        )
    except Exception as e:
        logger.error(f"[Graph] stats failed: {e}")

        try:
            events = await _get_events_from_db(db, investigation_id)
            return GraphStatsResponse(
                investigation_id=investigation_id,
                node_counts={"KillChainEvent": len(events)},
                relationship_counts={},
                attack_path=events,
            )
        except:
            raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")


@router.get(
    "/{investigation_id}/attack-path",
    summary="Get ordered attack path from Neo4j",
    response_model=list,
)
async def get_attack_path(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()
        path = neo4j.get_attack_path(investigation_id=investigation_id)
        neo4j.close()

        if not path:
            logger.info(f"[Graph] Neo4j empty for attack-path {investigation_id[:8]}..., falling back to TimescaleDB")
            path = await _get_events_from_db(db, investigation_id)

        return path
    except Exception as e:
        logger.error(f"[Graph] attack-path failed: {e}")
        try:
            return await _get_events_from_db(db, investigation_id)
        except:
            raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")


@router.get(
    "/{investigation_id}/iocs",
    summary="Get all IOC nodes from Neo4j",
)
async def get_graph_iocs(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()
        iocs = neo4j.get_all_iocs()
        neo4j.close()
        return iocs
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {e}")


@router.get(
    "/{investigation_id}/full",
    summary="Get full Neo4j subgraph — all nodes AND relationships",
    description=(
        "Returns every node and relationship in the Neo4j graph for this "
        "investigation. Falls back to TimescaleDB events if Neo4j is empty."
    ),
)
async def get_full_graph(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()
        all_events = neo4j._run("MATCH (n:KillChainEvent) RETURN count(n) AS count")
        neo4j_empty = not all_events or all_events[0].get("count", 0) == 0

        if neo4j_empty:
            neo4j.close()
            events = await db.get_events(investigation_id)
            nodes = []
            for ev in events:
                eid = ev.get("id", "")
                ts = str(ev.get("event_time", ""))
                stage = ev.get("stage", "unknown")
                desc = ev.get("description", "")
                tech = ev.get("technique_id", "")
                nodes.append({
                    "id": eid,
                    "label": f"[{stage}] {desc[:40] if desc else '—'}",
                    "type": "KillChainEvent",
                    "labels": ["KillChainEvent"],
                    "properties": {
                        "event_id": eid,
                        "timestamp": ts,
                        "stage": stage,
                        "description": desc,
                        "technique_id": tech,
                    }
                })
            relationships = []
            for i in range(len(nodes) - 1):
                relationships.append({
                    "source": nodes[i]["id"],
                    "target": nodes[i + 1]["id"],
                    "type": "PRECEDES",
                    "properties": {},
                })

            return {
                "nodes": nodes,
                "relationships": relationships,
                "node_count": len(nodes),
                "relationship_count": len(relationships),
            }

        filtered_ids = neo4j._run(
            "MATCH (e:KillChainEvent) WHERE e.investigation_id = $inv_id OR e.investigationId = $inv_id RETURN e.event_id AS eid",
            {"inv_id": investigation_id}
        )
        inv_event_ids = {r["eid"] for r in filtered_ids if r.get("eid")}
        use_all_events = len(inv_event_ids) == 0

        if use_all_events:
            all_ids_result = neo4j._run("MATCH (e:KillChainEvent) RETURN e.event_id AS eid")
            inv_event_ids = {r["eid"] for r in all_ids_result if r.get("eid")}

        event_clause = "WHERE true" if use_all_events else "WHERE e.investigation_id = $inv_id OR e.investigationId = $inv_id"

        nodes_result = neo4j._run(f"""
            MATCH (e:KillChainEvent)
            {event_clause}
            OPTIONAL MATCH (e)-[r]-(connected)
            RETURN
                labels(e)                                        AS src_labels,
                e.event_id                                       AS src_id,
                e.timestamp                                      AS src_ts,
                e.stage                                          AS src_stage,
                e.description                                    AS src_desc,
                e.technique_id                                   AS src_tech,
                labels(connected)                                AS dst_labels,
                CASE
                    WHEN connected.ip       IS NOT NULL THEN connected.ip
                    WHEN connected.name     IS NOT NULL THEN connected.name
                    WHEN connected.hash     IS NOT NULL THEN connected.hash
                    WHEN connected.technique_id IS NOT NULL THEN connected.technique_id
                    WHEN connected.family   IS NOT NULL THEN connected.family
                    WHEN connected.cve_id   IS NOT NULL THEN connected.cve_id
                    WHEN connected.event_id IS NOT NULL THEN connected.event_id
                    ELSE toString(id(connected))
                END                                              AS dst_id,
                type(r)                                          AS rel_type
        """, {"inv_id": investigation_id} if not use_all_events else {})

        node_map: dict[str, dict] = {}
        relationships: list[dict] = []
        rel_set: set[tuple[str, str, str]] = set()

        for row in nodes_result:
            src_id = row["src_id"] or ""
            if src_id and src_id not in node_map:
                node_map[src_id] = {
                    "id": src_id,
                    "label": f"[{row.get('src_stage', '')}] {row.get('src_desc', '')[:40]}",
                    "type": "KillChainEvent",
                    "labels": ["KillChainEvent"],
                    "properties": {
                        "event_id": src_id,
                        "timestamp": row.get("src_ts", ""),
                        "stage": row.get("src_stage", ""),
                        "description": row.get("src_desc", ""),
                        "technique_id": row.get("src_tech", ""),
                    }
                }

            dst_id = row["dst_id"] or ""
            dst_labels = row["dst_labels"] or []
            rel_type = row["rel_type"] or ""

            if dst_id and dst_id not in node_map:
                primary = "Unknown"
                for lbl in dst_labels:
                    if lbl in ("IPAddress", "Domain", "FileHash", "ThreatActor",
                               "Technique", "Malware", "CVE"):
                        primary = lbl
                        break
                if primary == "Unknown" and dst_labels:
                    primary = dst_labels[0]
                display_label = dst_id[:27] + "..." if len(dst_id) > 30 else dst_id
                node_map[dst_id] = {
                    "id": dst_id,
                    "label": display_label,
                    "type": primary,
                    "labels": dst_labels,
                    "properties": {},
                }

            if src_id and dst_id and rel_type:
                rel_key = (src_id, dst_id, rel_type)
                if rel_key not in rel_set:
                    rel_set.add(rel_key)
                    relationships.append({"source": src_id, "target": dst_id, "type": rel_type, "properties": {}})

        if use_all_events:
            preceding = neo4j._run("MATCH (a:KillChainEvent)-[r:PRECEDES]->(b:KillChainEvent) RETURN a.event_id AS src, b.event_id AS dst")
        else:
            preceding = neo4j._run("""
                MATCH (a:KillChainEvent)-[r:PRECEDES]->(b:KillChainEvent)
                WHERE (a.investigation_id = $inv_id OR a.investigationId = $inv_id)
                  AND (b.investigation_id = $inv_id OR b.investigationId = $inv_id)
                RETURN a.event_id AS src, b.event_id AS dst
            """, {"inv_id": investigation_id})

        for row in preceding:
            src = row["src"] or ""
            dst = row["dst"] or ""
            if src in inv_event_ids and dst in inv_event_ids:
                rel_key = (src, dst, "PRECEDES")
                if rel_key not in rel_set:
                    rel_set.add(rel_key)
                    relationships.append({"source": src, "target": dst, "type": "PRECEDES", "properties": {}})

        neo4j.close()

        return {
            "nodes": list(node_map.values()),
            "relationships": relationships,
            "node_count": len(node_map),
            "relationship_count": len(relationships),
        }

    except Exception as e:
        logger.error(f"[Graph] full graph failed: {e}")
        raise HTTPException(status_code=503, detail=f"Graph unavailable: {e}")


@router.delete(
    "/clear",
    response_model=StatusResponse,
    summary="Clear all Neo4j graph data",
    description="Wipes all nodes and relationships from Neo4j. Irreversible.",
)
async def clear_graph():
    try:
        neo4j = _get_neo4j()
        neo4j.clear_all()
        neo4j.close()
        return StatusResponse(status="cleared", message="All Neo4j data deleted.")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {e}")