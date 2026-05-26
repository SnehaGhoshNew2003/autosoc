import asyncio
import json
import logging
import re
import os
from dotenv import load_dotenv
from crewai import Agent, Task, Crew, Process, LLM
from tenacity import retry, stop_after_attempt, wait_exponential

load_dotenv()
logger = logging.getLogger(__name__)

class BaseAgent:
    """
    Wraps a crewai.Agent + Crew properly.
    Subclasses define: role, goal, backstory, system_prompt.
    """

    role:      str = "Generic Analyst"
    goal:      str = "Analyze input and return structured results"
    backstory: str = "You are a generic analysis agent."

    def __init__(
        self,
        name:        str,
        system_prompt: str,
        model:       str   = None,
        temperature: float = 0.2,
        verbose:     bool  = False,
    ):
        self.name          = name
        self.system_prompt = system_prompt
        self.verbose       = verbose
        self._history:  list[dict] = []
        self.llm = LLM(
            model   = model or os.getenv("GEMINI_MODEL", "gemini-2.5-pro"),
            api_key = os.getenv("GEMINI_API_KEY"),
            temperature = temperature,
        )
        self.agent = Agent(
            role      = self.role,
            goal      = self.goal,
            backstory = self.backstory,
            llm       = self.llm,
            verbose   = verbose,
            memory    = False,   
            allow_delegation = False,
        )

    def _strip_json_fences(self, text: str) -> str:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        return match.group(1).strip() if match else text.strip()

    def _parse_response(self, raw: str) -> tuple:
        clean = self._strip_json_fences(raw)
        try:
            return json.loads(clean), True
        except json.JSONDecodeError:
            return raw, False

    def _build_task_description(self, evidence: str) -> str:
        """
        Inject chat history + new evidence into the task description.
        This is how we give CrewAI agents conversation context.
        """
        if not self._history:
            return f"{self.system_prompt}\n\nINPUT:\n{evidence}"

        history_block = "\n".join(
            f"[{msg['role'].upper()}]: {msg['content']}"
            for msg in self._history
        )
        return (
            f"{self.system_prompt}\n\n"
            f"PREVIOUS CONTEXT:\n{history_block}\n\n"
            f"NEW INPUT:\n{evidence}"
        )

    def _make_crew(self, task: Task) -> Crew:
        """Assemble a single-agent crew for one task."""
        return Crew(
            agents  = [self.agent],
            tasks   = [task],
            process = Process.sequential,   
            verbose = self.verbose,
        )

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def analyze(self, evidence: str) -> dict:
        """
        Run a CrewAI Task against this agent and return structured output.
        Maintains conversation history across calls.
        """
        if not evidence or not evidence.strip():
            return {"agent": self.name, "data": None,
                    "status": "error", "error": "Empty input"}

        try:
            task = Task(
                description    = self._build_task_description(evidence),
                expected_output = (
                    "A valid JSON object matching the schema defined in the instructions. "
                    "No markdown fences, no explanation text — JSON only."
                ),
                agent = self.agent,
            )

            crew = self._make_crew(task)
            loop = asyncio.get_event_loop()
            crew_output = await loop.run_in_executor(None, crew.kickoff)
            raw = str(crew_output)
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
        One-shot query with NO history and NO side effects.
        Good for follow-up questions from the orchestrator.
        """
        if not prompt or not prompt.strip():
            return "ERROR: Empty prompt"

        try:
            task = Task(
                description     = f"{self.system_prompt}\n\nQUESTION:\n{prompt}",
                expected_output = "A clear, direct answer to the question.",
                agent           = self.agent,
            )
            crew = self._make_crew(task)

            loop = asyncio.get_event_loop()
            crew_output = await loop.run_in_executor(None, crew.kickoff)
            return str(crew_output)

        except Exception as e:
            logger.error(f"[{self.name}] query() failed: {e}")
            raise

    def reset_chat(self):
        """Clear conversation history between investigations."""
        self._history = []