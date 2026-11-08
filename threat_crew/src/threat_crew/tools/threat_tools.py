from __future__ import annotations

import json
from typing import Type

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

from threat_intel.alerts import create_alert_record
from threat_intel.pipeline import run_threat_pipeline


class LogsInput(BaseModel):
    logs: list[str] = Field(..., description='Network log lines to analyze.')


class AnalysisInput(BaseModel):
    analysis_json: str = Field(..., description='Structured analysis JSON produced by the analyzer stage.')


class ThreatDetectionTool(BaseTool):
    name: str = 'threat_detection_tool'
    description: str = 'Detects anomalies from raw network logs using the Isolation Forest model.'
    args_schema: Type[BaseModel] = LogsInput

    def _run(self, logs: list[str]) -> str:
        result = run_threat_pipeline(logs)
        return json.dumps({
            'count': result['count'],
            'suspicious_count': result['suspicious_count'],
            'detections': result['detections'],
        })


class ThreatAnalysisTool(BaseTool):
    name: str = 'threat_analysis_tool'
    description: str = 'Explains why a session looks suspicious and recommends a defensive action.'
    args_schema: Type[BaseModel] = AnalysisInput

    def _run(self, analysis_json: str) -> str:
        return analysis_json


class ThreatReporterTool(BaseTool):
    name: str = 'threat_reporter_tool'
    description: str = 'Formats a structured alert for analysts and responders.'
    args_schema: Type[BaseModel] = AnalysisInput

    def _run(self, analysis_json: str) -> str:
        analysis = json.loads(analysis_json)
        alert = create_alert_record(analysis)
        return json.dumps(alert)
