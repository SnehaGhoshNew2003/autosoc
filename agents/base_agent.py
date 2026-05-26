import asyncio
import json
import logging
import re
import os
from dotenv import load_dotenv
from crewai import LLM                         
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()
logger = logging.getLogger(__name__)


class BaseAgent:
    def __init__(
        self,
        name: str,
        system_prompt: str,
        model: str = "gemini-3.5-pro",
    ):
        self.name = name
        self.system_prompt = system_prompt
        self.llm = LLM(
            model=model,
            api_key=os.getenv("GEMINI_API_KEY"),
            temperature=0.2,       
        )

        self._history: list[dict] = []

    def _strip_json_fences(self, text: str) -> str:
        """Strip markdown code fences Gemini sometimes wraps around JSON."""
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        return match.group(1).strip() if match else text.strip()

    def _build_messages(self, user_content: str) -> list[dict]:
        """
        Assemble the full message list for this call:
        system prompt  +  running history  +  new user turn.
        CrewAI LLM.call() accepts OpenAI-style message dicts.
        """
        messages = [{"role": "system", "content": self.system_prompt}]
        messages.extend(self._history)
        messages.append({"role": "user", "content": user_content})
        return messages

    def _parse_response(self, raw: str) -> tuple[any, bool]:
        """
        Try to parse raw text as JSON.
        Returns (parsed_value, is_json).
        """
        clean = self._strip_json_fences(raw)
        try:
            return json.loads(clean), True
        except json.JSONDecodeError:
            return raw, False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def analyze(self, evidence: str) -> dict:
        """
        Send evidence through chat history → get structured JSON response.
        Maintains conversation context across multiple calls.
        """
        if not evidence or not evidence.strip():
            return {
                "agent": self.name,
                "data": None,
                "status": "error",
                "error": "Empty input",
            }

        try:
            messages = self._build_messages(evidence)
            loop = asyncio.get_event_loop()
            raw: str = await loop.run_in_executor(
                None,
                lambda: self.llm.call(messages) 
            )
            self._history.append({"role": "user",      "content": evidence})
            self._history.append({"role": "assistant",  "content": raw})

            parsed, is_json = self._parse_response(raw)
            return {
                "agent":  self.name,
                "data":   parsed,
                "status": "complete",
                "json":   is_json, 
            }

        except Exception as e:
            logger.error(f"[{self.name}] analyze() failed: {e}")
            raise 

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def query(self, prompt: str) -> str:
        """
        One-shot query — NO chat history, NO side effects.
        Good for quick lookups from other agents.
        """
        if not prompt or not prompt.strip():
            return "ERROR: Empty prompt"

        try:
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user",   "content": prompt},
            ]
            loop = asyncio.get_event_loop()
            raw: str = await loop.run_in_executor(
                None,
                lambda: self.llm.call(messages)
            )
            return raw

        except Exception as e:
            logger.error(f"[{self.name}] query() failed: {e}")
            raise

    def reset_chat(self):
        """Clear conversation history between investigations."""
        self._history = []