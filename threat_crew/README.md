# threat_crew

CrewAI definitions for the three roles in the threat pipeline: Detector, Analyzer and Reporter (`config/agents.yaml`, `config/tasks.yaml`, tools in `tools/threat_tools.py`).

By default `main.py` runs the same three stages as deterministic Python through `threat_intel.pipeline`, so the project works without LLM credentials. See the root [README](../README.md).

```bash
pip install -r requirements-agents.txt   # from the repository root
python threat_crew/src/threat_crew/main.py
```
