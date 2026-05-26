import os
import logging
from dotenv import load_dotenv
from crewai import LLM

load_dotenv()
logger = logging.getLogger(__name__)


def get_llm(temperature: float = 0.2) -> LLM:
    """
    Shared LLM factory used by all agents.
    Pull model + key from .env so you change it in one place.
    """
    return LLM(
        model=os.getenv("GEMINI_MODEL", "gemini/gemini-2.5-pro"),
        api_key=os.getenv("GEMINI_API_KEY"),
        temperature=temperature,
    )