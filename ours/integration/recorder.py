"""
Collects the events of one run and writes the trace JSON (spec section 7).
Nothing is truncated: message contents and tool args are stored in full.
"""
import json
from pathlib import Path


class Recorder:
    def __init__(self):
        self.events = []

    def add(self, event_type: str, **fields) -> dict:
        event = {"seq": len(self.events), "type": event_type, **fields}
        self.events.append(event)
        return event

    def usage(self) -> dict:
        calls = [e for e in self.events if e["type"] == "llm_call"]
        return {
            "llm_calls": len(calls),
            "input_tokens": sum(e.get("input_tokens", 0) for e in calls),
            "output_tokens": sum(e.get("output_tokens", 0) for e in calls),
            "llm_latency_s": round(sum(e.get("latency_s", 0) for e in calls), 3),
        }

    def write(self, path, run: dict, task: str, outcome: dict, extra: dict = None) -> dict:
        trace = {
            "schema_version": 1,
            "run": run,
            "task": task,
            "events": self.events,
            "outcome": outcome,
            "usage": self.usage(),
            **(extra or {}),
        }
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(trace, indent=1, ensure_ascii=False), encoding="utf-8")
        return trace
