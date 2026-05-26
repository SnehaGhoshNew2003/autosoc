import asyncio
import json
import logging
import google.generativeai as genai
from dotenv import load_dotenv
from tenacity import retry, stop_after_attempt, wait_exponential
import os

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

logger = logging.getLogger(__name__)

class BaseAgent:
    def __init__(self, name: str, system_prompt: str, model: str = "gemini-3.5-pro"):
        self.name = name
        self.system_prompt = system_prompt
        self.model = genai.GenerativeModel(
            model_name=model,
            system_instruction=system_prompt
        )
        self.chat = self.model.start_chat(history=[])

    async def analyze(self, evidence: str) -> dict:
        """Send evidence to Gemini and get structured response."""
        try:                                        
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.chat.send_message(evidence)
            )

            try:                                   
                parsed = json.loads(response.text)
                return {
                    "agent": self.name,
                    "data": parsed,                
                    "status": "complete"
                }
            except json.JSONDecodeError:
                return {
                    "agent": self.name,
                    "data": response.text,
                    "status": "complete"
                }

        except Exception as e:                   
            logger.error(f"[{self.name}] Failed: {e}")
            return {
                "agent": self.name,
                "data": None,
                "status": "error",
                "error": str(e)
            }

    async def query(self, prompt: str) -> str:
        """One-shot query without chat history."""
        try:                                         
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: self.model.generate_content(prompt)
            )
            return response.text
        except Exception as e:
            logger.error(f"[{self.name}] Query failed: {e}")
            return f"ERROR: {e}"

    def reset_chat(self):                           
        """Clear conversation history — useful between investigations."""
        self.chat = self.model.start_chat(history=[])