# CrewAI Threat Workflow

See the root-level [README.md](../README.md) for the complete project documentation.

This package contains the CrewAI multi-agent orchestration for threat detection, analysis, and alert reporting. Run via:

```bash
venv/bin/python src/test_crew/main.py
```

Or from the project root:

```bash
venv/bin/python test_crew/src/test_crew/main.py
```

The three agents (Detector, Analyzer, Reporter) use the shared threat pipeline in `threat_intel/` for reproducible results.
