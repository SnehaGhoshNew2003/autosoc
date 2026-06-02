import logging
import asyncio
from typing import List
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew
from agents.base_agent import get_llm

logger = logging.getLogger(__name__)

class ThreatVerdict(BaseModel):
    final_verdict: str = Field(description="e.g., 'Confirmed True Positive', 'Likely False Positive', 'Benign Admin Activity'")
    confidence_score: int = Field(description="Confidence percentage from 0 to 100")
    key_red_team_evidence: List[str] = Field(description="Strongest points arguing it is an attack")
    key_blue_team_evidence: List[str] = Field(description="Strongest points arguing it is benign")
    executive_summary: str = Field(description="A 2-sentence summary of the final conclusion")


def build_red_team_agent() -> Agent:
    return Agent(
        role="Red Team Hypothesis Defender",
        goal="Review the pipeline data and argue why this is a severe, malicious attack.",
        backstory=(
            "You are an aggressive threat analyst. You look at timelines, logs, and intel "
            "and connect the dots to prove a network compromise. You highlight the absolute "
            "worst-case scenario and defend your threat hypothesis using the provided data."
        ),
        llm=get_llm(temperature=0.4),
        verbose=False,
        allow_delegation=False,
    )

def build_blue_team_agent() -> Agent:
    return Agent(
        role="Blue Team Skeptic",
        goal="Review the pipeline data and the Red Team's claims, and argue why this is benign.",
        backstory=(
            "You are a strict, skeptical IT auditor. You believe most alerts are false positives, "
            "admin errors, or misconfigurations. You aggressively dismantle the Red Team's arguments "
            "by pointing out missing evidence or providing alternative, harmless explanations."
        ),
        llm=get_llm(temperature=0.3),
        verbose=False,
        allow_delegation=False,
    )

def build_judge_agent() -> Agent:
    return Agent(
        role="CISO Adjudicator",
        goal="Evaluate the debate and issue a final confidence-scored verdict.",
        backstory=(
            "You are the Chief Information Security Officer. You do not investigate raw data; "
            "you listen to your Red Team and Blue Team debate. You penalize logical leaps and "
            "reward hard evidence. You make the final, objective decision on the threat severity."
        ),
        llm=get_llm(temperature=0.0),  
        verbose=False,
        allow_delegation=False,
    )

class MultiAgentDebate:
    """
    Step 8 Module: Takes the outputs from the rest of the pipeline and 
    forces an adversarial debate to generate a final confidence score.
    """
    def __init__(self):
        self.red_team = build_red_team_agent()
        self.blue_team = build_blue_team_agent()
        self.judge = build_judge_agent()

    async def run(
        self, 
        log_data: dict, 
        intel_data: dict, 
        malware_data: dict, 
        timeline_data: dict
    ) -> dict:
        """
        Runs the debate system sequentially using CrewAI context injection.
        """
        logger.info("[MultiAgentDebate] Initiating Final Threat Verdict Debate...")

        evidence_bundle = (
            f"=== LOG EVIDENCE ===\n{log_data.get('summary', 'None')}\n\n"
            f"=== INTEL EVIDENCE ===\n{intel_data.get('summary', 'None')}\n\n"
            f"=== MALWARE EVIDENCE ===\n{malware_data.get('summary', 'None')}\n\n"
            f"=== RECONSTRUCTED TIMELINE ===\n{timeline_data.get('narrative', 'None')}\n"
        )
        red_task = Task(
            description=(
                f"EVIDENCE BUNDLE:\n{evidence_bundle}\n\n"
                "TASK: Argue aggressively that this evidence represents a true, severe cyber attack. "
                "Cite specific pieces of the evidence bundle to back up your claim."
            ),
            expected_output="A robust paragraph arguing this is a malicious attack with specific data references.",
            agent=self.red_team
        )

        blue_task = Task(
            description=(
                f"EVIDENCE BUNDLE:\n{evidence_bundle}\n\n"
                "TASK: Counter the Red Team's argument. Look at the data provided and find alternate "
                "benign explanations (e.g., scheduled admin tasks, misconfigurations, false positives). "
                "Dismantle their assumptions."
            ),
            expected_output="A robust paragraph dismantling the Red Team's argument using counter-evidence.",
            agent=self.blue_team,
            context=[red_task]  
        )

        judge_task = Task(
            description=(
                f"EVIDENCE BUNDLE:\n{evidence_bundle}\n\n"
                "TASK: Act as the CISO. Weigh both arguments against the evidence bundle. "
                "Determine the objective truth. Provide a final verdict, confidence score, "
                "and populate the required Pydantic JSON fields completely."
            ),
            expected_output="A ThreatVerdict structured JSON object containing all required fields.",
            agent=self.judge,
            context=[red_task, blue_task],  
            output_pydantic=ThreatVerdict
        )

        crew = Crew(
            agents=[self.red_team, self.blue_team, self.judge],
            tasks=[red_task, blue_task, judge_task],
            process="sequential",
            verbose=False
        )

        try:
            loop = asyncio.get_event_loop()
            crew_output = await loop.run_in_executor(None, crew.kickoff)
            
            result: ThreatVerdict = crew_output.pydantic
            return {
                **result.model_dump(),
                "_agent": "MultiAgentDebate",
                "_status": "complete"
            }

        except Exception as e:
            logger.error(f"[MultiAgentDebate] run() failed: {e}")
            return {
                **ThreatVerdict(
                    final_verdict="Error during debate execution",
                    confidence_score=0,
                    key_red_team_evidence=[],
                    key_blue_team_evidence=[],
                    executive_summary=str(e)
                ).model_dump(),
                "_agent": "MultiAgentDebate",
                "_status": "error",
                "_error": str(e),
            }