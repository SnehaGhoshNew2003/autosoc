import asyncio
import json
import logging
import re
import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM
from tenacity import retry, stop_after_attempt
from tenacity.wait import wait_base

load_dotenv()
logger = logging.getLogger(__name__)

_CHAR_LIMIT = 8000  

def _trim(text: str, limit: int = _CHAR_LIMIT) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * 0.6)
    tail = limit - head
    dropped = len(text) - limit
    logger.warning(f"[Trim] Dropping {dropped} chars from middle of input")
    return text[:head] + f"\n...[{dropped} chars omitted]...\n" + text[-tail:]

def get_llm(temperature: float = 0.2) -> LLM:
    return LLM(
        model=os.getenv("GROQ_MODEL", "groq/llama-3.3-70b-versatile"),
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=temperature,
    )

class _GroqRateLimitWait(wait_base):
    def __call__(self, retry_state) -> float:
        exc = retry_state.outcome.exception()
        if exc:
            s = str(exc)
            m = re.search(r'try again in (\d+)m(\d+(?:\.\d+)?)s', s)
            if m:
                wait = int(m.group(1)) * 60 + float(m.group(2)) + 5
                logger.warning(f"[RateLimit] Daily limit — sleeping {wait:.0f}s")
                return wait
            m = re.search(r'try again in (\d+(?:\.\d+)?)s', s)
            if m:
                wait = float(m.group(1)) + 3
                logger.warning(f"[RateLimit] TPM — sleeping {wait:.1f}s")
                return wait
        return 40.0

class BaseAgent:
    role:      str = "Generic Analyst"
    goal:      str = "Analyze input and return structured results"
    backstory: str = "You are a generic analysis agent."

    def __init__(self, name, system_prompt, model=None, temperature=0.2, verbose=False):
        self.name = name
        self.system_prompt = system_prompt
        self.verbose = verbose
        self._history: list[dict] = []
        self.llm = get_llm(temperature=temperature) if model is None else LLM(
            model=model, api_key=os.getenv("GROQ_API_KEY"), temperature=temperature,
        )
        self.agent = Agent(
            role=self.role, goal=self.goal, backstory=self.backstory,
            llm=self.llm, verbose=verbose, memory=False, allow_delegation=False,
        )

    def _strip_json_fences(self, text):
        m = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        return m.group(1).strip() if m else text.strip()

    def _parse_response(self, raw):
        clean = self._strip_json_fences(raw)
        try:
            return json.loads(clean), True
        except json.JSONDecodeError:
            return raw, False

    def _build_task_description(self, evidence):
        if not self._history:
            return f"{self.system_prompt}\n\nINPUT:\n{_trim(evidence)}"
        history_block = "\n".join(
            f"[{m['role'].upper()}]: {m['content']}" for m in self._history[-4:]
        )
        return (
            f"{self.system_prompt}\n\n"
            f"PREVIOUS CONTEXT:\n{history_block}\n\n"
            f"NEW INPUT:\n{_trim(evidence)}"
        )

    def _make_crew(self, task):
        return Crew(agents=[self.agent], tasks=[task],
                    process=Process.sequential, verbose=self.verbose)

    @retry(stop=stop_after_attempt(5), wait=_GroqRateLimitWait())
    async def analyze(self, evidence: str) -> dict:
        if not evidence or not evidence.strip():
            return {"agent": self.name, "data": None,
                    "status": "error", "error": "Empty input"}
        task = Task(
            description=self._build_task_description(evidence),
            expected_output="A valid JSON object. No markdown fences, no explanation — JSON only.",
            agent=self.agent,
        )
        crew = self._make_crew(task)
        crew_output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)
        raw = str(crew_output)
        self._history.append({"role": "user", "content": evidence})
        self._history.append({"role": "assistant", "content": raw})
        parsed, is_json = self._parse_response(raw)
        return {"agent": self.name, "data": parsed, "status": "complete", "is_json": is_json}

    @retry(stop=stop_after_attempt(5), wait=_GroqRateLimitWait())
    async def query(self, prompt: str) -> str:
        if not prompt or not prompt.strip():
            return "ERROR: Empty prompt"
        task = Task(
            description=f"{self.system_prompt}\n\nQUESTION:\n{_trim(prompt)}",
            expected_output="A clear, direct answer.",
            agent=self.agent,
        )
        crew = self._make_crew(task)
        crew_output = await asyncio.get_running_loop().run_in_executor(None, crew.kickoff)
        return str(crew_output)

    def reset_chat(self):
        self._history = []