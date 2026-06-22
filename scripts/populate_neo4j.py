
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("populate_neo4j")
from graph.neo4j_client import Neo4jClient


def _infer_ioc_type(value: str) -> str:
    """Basic IOC type inference."""
    v = value.strip()
    if not v:
        return "unknown"
   
    if v.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in v.split(".")):
        return "ip"

    if ":" in v and not v[0].isdigit():
        return "domain"
    if "." in v and v.count(".") >= 1 and not v[0].isdigit():
        return "domain"
   
    if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v.lower()):
        return "hash"
    if v.startswith("HKC") or v.startswith("HK"):
        return "registry_key"
    if v.startswith("\\") or v.startswith("Global"):
        return "mutex"
    if v.startswith("http://") or v.startswith("https://"):
        return "url"

    if v.startswith("/") or (len(v) > 2 and v[1] == ":" and v[2] == "\\"):
        return "file_path"
    if "@" in v:
        return "email"
    if v.startswith("CVE-") or v.startswith("cve-"):
        return "cve"
    return "unknown"


async def populate_from_events(db, neo4j):
    """Read events from TimescaleDB and create Neo4j nodes for all completed investigations."""
    from database.timescale_client import TimescaleClient
    invs = await db.list_investigations(limit=1000)
    total_events = 0
    total_iocs = 0
    
    for inv in invs:
        inv_id = inv["id"]
        if inv.get("status") not in ("complete", "error"):
            logger.info(f"Skipping {inv_id[:8]}... — status={inv.get('status')}")
            continue
        
        logger.info(f"Processing investigation {inv_id[:8]}... — {inv.get('input_summary', '—')}")
        
        events = await db.get_events(inv_id)
        if not events:
            logger.info(f"  No events found for {inv_id[:8]}...")
            continue
        
        logger.info(f"  Found {len(events)} events")
        
        for ev in events:
            event_id = ev.get("id", "")
            if not event_id:
                event_id = f"evt_{events.index(ev):04d}_{str(ev.get('event_time', '')).replace(' ', '_').replace(':', '')}"
            
            ts = ev.get("event_time", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts = str(ts)
            
            neo4j.merge_event(
                event_id=event_id,
                timestamp=ts,
                stage=ev.get("stage", "unknown"),
                description=ev.get("description", ""),
                source=ev.get("source", ""),
                investigation_id=inv_id,
                technique_id=ev.get("technique_id", ""),
                technique_name=ev.get("technique_name", ""),
                confidence=ev.get("confidence", "low"),
            )
            total_events += 1
            iocs_involved = ev.get("iocs_involved", [])
            if isinstance(iocs_involved, str):
                try:
                    iocs_involved = json.loads(iocs_involved)
                except:
                    iocs_involved = [iocs_involved]
            
            for ioc_val in iocs_involved:
                ioc_val = str(ioc_val).strip()
                if not ioc_val:
                    continue
                
                ioc_type = _infer_ioc_type(ioc_val)
                if ioc_type == "ip":
                    neo4j.merge_ip(ioc_val)
                    neo4j.link_event_involves_ip(event_id, ioc_val)
                elif ioc_type == "domain":
                    neo4j.merge_domain(ioc_val)
                    neo4j.link_event_involves_domain(event_id, ioc_val)
                elif ioc_type == "hash":
                    neo4j.merge_hash(ioc_val)
                    neo4j.link_event_involves_hash(event_id, ioc_val)
                total_iocs += 1
    
        event_ids = []
        for ev in events:
            eid = ev.get("id", "")
            if not eid:
                idx = events.index(ev)
                eid = f"evt_{idx:04d}_{str(ev.get('event_time', '')).replace(' ', '_').replace(':', '')}"
            event_ids.append(eid)
        
        for i in range(len(event_ids) - 1):
            neo4j.link_event_precedes_event(event_ids[i], event_ids[i + 1])
    
    logger.info(f"Done! Created {total_events} event nodes and {total_iocs} IOC links")


async def main():
    from database.timescale_client import TimescaleClient
    
    db = TimescaleClient()
    neo4j = Neo4jClient()
    
    try:
        await db.connect()
        neo4j.create_constraints()
        await populate_from_events(db, neo4j)
    finally:
        await db.close()
        neo4j.close()


if __name__ == "__main__":
    asyncio.run(main())