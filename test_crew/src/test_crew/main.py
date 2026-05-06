#!/usr/bin/env python
from __future__ import annotations

import json
import sys
from pathlib import Path

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ROOT = Path(__file__).resolve().parent.parent
for path in (WORKSPACE_ROOT, PACKAGE_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from test_crew.workflow import load_sample_logs, run_threat_workflow


def _print_result(result: dict) -> None:
    print(json.dumps(result, indent=2))


def run() -> dict:
    """Run the threat-intelligence workflow on the bundled sample logs."""
    result = run_threat_workflow(load_sample_logs())
    _print_result(result)
    return result


def train() -> dict:
    """Compatibility wrapper for the old CrewAI template command."""
    return run()


def replay() -> dict:
    """Compatibility wrapper for the old CrewAI template command."""
    return run()


def test() -> dict:
    """Compatibility wrapper for the old CrewAI template command."""
    return run()


def run_with_trigger() -> dict:
    """Run the workflow using a trigger payload passed on the command line."""
    if len(sys.argv) < 2:
        raise Exception('No trigger payload provided. Please provide JSON payload as argument.')

    try:
        trigger_payload = json.loads(sys.argv[1])
    except json.JSONDecodeError as exc:
        raise Exception('Invalid JSON payload provided as argument') from exc

    logs = trigger_payload.get('logs') or trigger_payload.get('log')
    if not logs:
        raise Exception('Trigger payload must include a "logs" list or "log" string.')
    if not isinstance(logs, list):
        logs = [logs]

    result = run_threat_workflow(logs)
    _print_result(result)
    return result


if __name__ == '__main__':
    run()
