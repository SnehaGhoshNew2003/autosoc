from __future__ import annotations

import json
import logging
import re
import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from api.dependencies.database import get_db
from api.models.schemas import StatusResponse
from database.timescale_client import TimescaleClient

router = APIRouter()
logger = logging.getLogger(__name__)


def _get_groq():
    try:
        from groq import AsyncGroq
    except ImportError:
        raise HTTPException(status_code=503, detail="groq package not installed on server")
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="GROQ_API_KEY not configured")
    return AsyncGroq(api_key=api_key)

def _truncate(text: str, max_words: int = 5) -> str:
    words = text.strip().split()
    return " ".join(words[:max_words]) if words else "New Chat"


async def _generate_title(client, first_message: str) -> str:
    try:
        resp = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a title generator. Given a user's first message, "
                        "reply with ONLY a 4-5 word title that summarizes the topic. "
                        "No quotes, no punctuation, no explanation."
                    ),
                },
                {"role": "user", "content": first_message},
            ],
            max_tokens=20,
            temperature=0.3,
        )
        title = (resp.choices[0].message.content or "").strip()
        return _truncate(title)
    except Exception as e:
        logger.warning(f"[Chat] Title generation failed: {e}")
        return _truncate(first_message)


async def _stream_chat_response(
    client,
    messages: list[dict],
    on_chunk=None,
) -> str:
    full_text = ""
    stream = await client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        stream=True,
        temperature=0.4,
        max_tokens=2048,
    )
    async for chunk in stream:
        delta = chunk.choices[0].delta.content or ""
        if delta:
            full_text += delta
            if on_chunk is not None:
                await on_chunk(delta)
    return full_text


@router.post("/conversations", response_model=dict)
async def create_conversation(
    db: TimescaleClient = Depends(get_db),
):
    conv_id = await db.create_conversation()
    conv = await db.get_conversation(conv_id)
    return conv


@router.get("/conversations")
async def list_conversations(
    db: TimescaleClient = Depends(get_db),
):
    convs = await db.list_conversations()
    return {"conversations": convs}


@router.delete("/conversations/{conversation_id}", response_model=StatusResponse)
async def delete_conversation(
    conversation_id: str,
    db: TimescaleClient = Depends(get_db),
):
    ok = await db.soft_delete_conversation(conversation_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return StatusResponse(status="deleted", message="Conversation hidden from history.")


@router.get("/conversations/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    db: TimescaleClient = Depends(get_db),
):
    conv = await db.get_conversation(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    messages = await db.get_chat_messages(conversation_id)
    return {"messages": messages}


@router.post("/conversations/{conversation_id}/title")
async def generate_title(
    conversation_id: str,
    body: dict,
    db: TimescaleClient = Depends(get_db),
):
    conv = await db.get_conversation(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    first_msg = body.get("first_message", "")
    if not first_msg:
        return {"title": conv["title"]}

    client = _get_groq()
    title = await _generate_title(client, first_msg)
    await db.update_conversation_title(conversation_id, title)
    return {"title": title}


@router.post("/conversations/{conversation_id}/messages")
async def send_message(
    conversation_id: str,
    body: dict,
    db: TimescaleClient = Depends(get_db),
):
    conv = await db.get_conversation(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    user_content = body.get("content", "").strip()
    if not user_content:
        raise HTTPException(status_code=400, detail="Empty message")
    await db.add_chat_message(conversation_id, "user", user_content)
    history = await db.get_chat_messages(conversation_id)

    try:
        investigations = await db.list_investigations(limit=20)
    except Exception:
        investigations = []

    inv_context = ""
    if investigations:
        inv_context = "\n\nAVAILABLE INVESTIGATIONS IN DATABASE:\n"
        for inv in investigations:
            inv_context += (
                f"- ID: {inv['id'][:8]}... | Created: {inv.get('created_at', 'N/A')} | "
                f"Status: {inv.get('status', 'N/A')} | Severity: {inv.get('severity', 'N/A')} | "
                f"Verdict: {inv.get('verdict', 'N/A')} | Summary: {inv.get('input_summary', 'N/A')}\n"
            )
        inv_context += (
            "\nWhen the user asks about investigations, use the data above. "
            "You can reference investigation IDs (first 8 chars), dates, severities, verdicts, and summaries. "
            "If they ask for details about a specific investigation, provide all available information from the context above."
        )
    try:
        all_iocs = await db.get_iocs("00000000-0000-0000-0000-000000000000")
        if not all_iocs:
            ioc_rows = []
            for inv in investigations[:5]:
                try:
                    inv_iocs = await db.get_iocs(inv["id"])
                    ioc_rows.extend(inv_iocs)
                except Exception:
                    pass
            all_iocs = ioc_rows
    except Exception:
        all_iocs = []

    ioc_context = ""
    if all_iocs:
        ioc_context = "\n\nAVAILABLE IOCs (Indicators of Compromise) IN DATABASE:\n"
        for ioc in all_iocs[:50]:
            ioc_context += (
                f"- [{ioc.get('ioc_type', 'unknown')}] {ioc.get('value', 'N/A')} | "
                f"Source: {ioc.get('source_agent', 'N/A')} | "
                f"First seen: {ioc.get('first_seen', 'N/A')} | "
                f"Context: {ioc.get('context', 'N/A')}\n"
            )
        ioc_context += (
            "\nWhen the user asks about IOCs, threats, IPs, domains, hashes, or indicators of compromise, "
            "use the data above. You can reference specific values, types, sources, and timestamps. "
            "If they ask for all IOCs or IOCs of a specific type, list them from the context above."
        )

    groq_messages = [
        {
            "role": "system",
            "content": (
                "You are AutoSOC AI Analyst — a cybersecurity expert. "
                "Answer in clear, plain English. Be concise but thorough. "
                "Cover threats, attack techniques, IOCs, incident response, and MITRE ATT&CK mappings."
                f"{inv_context}{ioc_context}"
            ),
        },
    ]
    for m in history:
        groq_messages.append({"role": m["role"], "content": m["content"]})

    client = _get_groq()

    async def event_stream():
        assistant_text = ""
        try:
            async def on_chunk(chunk: str):
                nonlocal assistant_text
                assistant_text += chunk
                yield f"data: {json.dumps({'content': chunk})}\n\n"

            full = await _stream_chat_response(client, groq_messages)
            yield f"data: {json.dumps({'content': full})}\n\n"
            await db.add_chat_message(conversation_id, "assistant", full)
            user_msgs = [m for m in history if m["role"] == "user"]
            if len(user_msgs) <= 1 and conv["title"] == "New Chat":
                title = await _generate_title(client, user_content)
                await db.update_conversation_title(conversation_id, title)

            yield "data: [DONE]\n\n"
        except Exception as e:
            logger.error(f"[Chat] stream error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")