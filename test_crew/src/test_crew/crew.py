from __future__ import annotations

from typing import List

from crewai import Agent, Crew, Process, Task
from crewai.agents.agent_builder.base_agent import BaseAgent
from crewai.project import CrewBase, agent, crew, task

from .tools.threat_tools import ThreatAnalysisTool, ThreatDetectionTool, ThreatReporterTool
from .workflow import run_threat_workflow


@CrewBase
class ThreatIntelligenceCrew:
    """CrewAI workflow for threat detection, analysis, and alert reporting."""

    agents: List[BaseAgent]
    tasks: List[Task]

    @agent
    def detector_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['detector_agent'],  # type: ignore[index]
            verbose=True,
            tools=[ThreatDetectionTool()],
        )

    @agent
    def analyzer_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['analyzer_agent'],  # type: ignore[index]
            verbose=True,
            tools=[ThreatAnalysisTool()],
        )

    @agent
    def reporter_agent(self) -> Agent:
        return Agent(
            config=self.agents_config['reporter_agent'],  # type: ignore[index]
            verbose=True,
            tools=[ThreatReporterTool()],
        )

    @task
    def detection_task(self) -> Task:
        return Task(
            config=self.tasks_config['detection_task'],  # type: ignore[index]
        )

    @task
    def analysis_task(self) -> Task:
        return Task(
            config=self.tasks_config['analysis_task'],  # type: ignore[index]
        )

    @task
    def reporting_task(self) -> Task:
        return Task(
            config=self.tasks_config['reporting_task'],  # type: ignore[index]
            output_file='alerts/report.md',
        )

    @crew
    def crew(self) -> Crew:
        """Create the sequential threat-intelligence crew."""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
        )


def run_threat_workflow_for_logs(logs: list[str] | None = None) -> dict:
    """Run the practical threat workflow on raw log lines.

    The CrewAI agents are configured for the project structure, while the
    deterministic pipeline keeps the project runnable without external LLM
    credentials.
    """
    return run_threat_workflow(logs)


TestCrew = ThreatIntelligenceCrew
