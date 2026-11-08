from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from threat_intel.pipeline import run_threat_pipeline

CURRENT_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = CURRENT_DIR.parent
WORKSPACE_ROOT = PACKAGE_ROOT.parent.parent
SAMPLE_LOG_PATH = WORKSPACE_ROOT / 'sample_logs.txt'


def load_sample_logs(limit: int | None = None) -> List[str]:
    if not SAMPLE_LOG_PATH.exists():
        raise FileNotFoundError(f'Sample log file not found: {SAMPLE_LOG_PATH}')
    logs = [line.strip() for line in SAMPLE_LOG_PATH.read_text(encoding='utf-8').splitlines() if line.strip()]
    return logs[:limit] if limit else logs


def run_threat_workflow(logs: Iterable[str] | None = None) -> dict:
    log_entries = list(logs) if logs is not None else load_sample_logs()
    return run_threat_pipeline(log_entries)
