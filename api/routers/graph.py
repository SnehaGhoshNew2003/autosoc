# api/routers/graph.py
#
# GET /api/v1/graph/{investigation_id}/stats      — node/relationship counts
# GET /api/v1/graph/{investigation_id}/attack-path — ordered kill-chain path
# GET /api/v1/graph/{investigation_id}/iocs        — all IOC nodes from Neo4j
# GET /api/v1/graph/{investigation_id}/full        — full subgraph (nodes + rels)
# DELETE /api/v1/graph/clear                       — wipe all graph data

import logging
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


@router.get(
    "/{investigation_id}/stats",
    response_model=GraphStatsResponse,
    summary="Get graph node and relationship counts",
)
async def get_graph_stats(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns counts of each node type and relationship type in Neo4j,
    plus the ordered attack path for this investigation.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()

        node_counts = {}
        for label in [
            "IPAddress", "Domain", "FileHash", "ThreatActor",
            "Technique", "Malware", "CVE", "KillChainEvent",
        ]:
            result = neo4j._run(
                f"MATCH (n:{label}) RETURN count(n) AS count"
            )
            node_counts[label] = result[0]["count"] if result else 0

        rel_counts = {}
        for rel in ["USES", "INVOLVES", "PRECEDES", "CONNECTS_TO",
                    "ATTRIBUTED_TO", "DEPLOYS", "EXPLOITS"]:
            result = neo4j._run(
                f"MATCH ()-[r:{rel}]->() RETURN count(r) AS count"
            )
            rel_counts[rel] = result[0]["count"] if result else 0

        attack_path = neo4j.get_attack_path()
        neo4j.close()

        return GraphStatsResponse(
            investigation_id=investigation_id,
            node_counts=node_counts,
            relationship_counts=rel_counts,
            attack_path=attack_path,
        )
    except Exception as e:
        logger.error(f"[Graph] stats failed: {e}")
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {e}")


@router.get(
    "/{investigation_id}/attack-path",
    summary="Get ordered attack path from Neo4j",
    response_model=list,
)
async def get_attack_path(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns the kill-chain event sequence ordered by timestamp.
    Each entry contains: timestamp, stage, description, technique_id.
    """
    inv = await db.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        neo4j = _get_neo4j()
        path = neo4j.get_attack_path()
        neo4j.close()
        return path
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {e}")


@router.get(
    "/{investigation_id}/iocs",
    summary="Get all IOC nodes from Neo4j",
)
async def get_graph_iocs(
    investigation_id: str,
    db:               TimescaleClient = Depends(get_db),
):
    """
    Returns all IP, domain, and hash nodes currently in the Neo4j graph.
    Note: Neo4j stores IOCs globally (not per-investigation).
    """
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
        "investigation. Used by the graph visualization to render the full "
        "attack path with all entity types and relationship types."
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

        # Fetch all nodes with their labels and properties
        nodes_result = neo4j._run("""
            MATCH (n)
            OPTIONAL MATCH (n)-[r]-()
            RETURN n, collect(DISTINCT type(r)) AS rel_types
        """)

        nodes: list[dict] = []
        node_ids: set[str] = set()

        for row in nodes_result:
            n = row["n"]
            nid = str(n.get("id", n.get("name", "")))
            if not nid or nid in node_ids:
                continue
            node_ids.add(nid)

            labels = list(n.labels) if hasattr(n, "labels") else []
            props = dict(n)
            props.pop("id", None)
            props.pop("name", None)

            # Determine primary label
            primary = "Unknown"
            for lbl in labels:
                if lbl in ("IPAddress", "Domain", "FileHash", "ThreatActor",
                           "Technique", "Malware", "KillChainEvent", "CVE"):
                    primary = lbl
                    break
            if primary == "Unknown" and labels:
                primary = labels[0]

            display_label = n.get("name") or n.get("value") or n.get("stage") or primary
            if isinstance(display_label, str) and len(display_label) > 30:
                display_label = display_label[:27] + "..."

            nodes.append({
                "id": nid,
                "label": display_label,
                "type": primary,
                "labels": labels,
                "properties": props,
            })

        # Fetch all relationships
        rels_result = neo4j._run("""
            MATCH (a)-[r]->(b)
            RETURN
                id(a) AS src_id,
                id(b) AS dst_id,
                type(r) AS type,
                properties(r) AS props
        """)

        relationships: list[dict] = []
        for row in rels_result:
            src = str(row["src_id"])
            dst = str(row["dst_id"])
            rel_type = row["type"] or "RELATED"
            props = row["props"] or {}

            if src in node_ids and dst in node_ids:
                relationships.append({
                    "source": src,
                    "target": dst,
                    "type": rel_type,
                    "properties": props,
                })

        neo4j.close()

        return {
            "nodes": nodes,
            "relationships": relationships,
            "node_count": len(nodes),
            "relationship_count": len(relationships),
        }

    except Exception as e:
        logger.error(f"[Graph] full graph failed: {e}")
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {e}")


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