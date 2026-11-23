"""
Experiment runner: runs cases x arms x trials and writes one trace JSON per run to
results/runs/<arm>/<case_id>/t<trial>.json (spec section 7).

- Resumes: a run whose trace already exists without an API error is skipped, so a run that
  stops at the daily quota can simply be started again the next day.
- API errors (rate limit, 503, timeout) are not results: the trace records outcome.error and
  the scorer skips it; starting the runner again re-runs it.
- Hitting the step limit is a real outcome (the agents looped), recorded as stop_reason.

Set in .env for experiment runs: LLM_MAX_RETRIES=1 and LLM_REQUESTS_PER_SECOND=0.2.

Run from the repo root:
    python -m ours.scripts.run_experiment --arms A C --split dev
    python -m ours.scripts.run_experiment --arms C --ids atk_001 ben_001 --trials 3 --split test
"""
import argparse
import asyncio
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from langgraph.errors import GraphRecursionError
from openai import APIError

from ours.benchmark.casefile import load_cases
from ours.benchmark.tools import WORLD
from ours.integration.langgraph_hooks import RunContext, text_of
from ours.integration.recorder import Recorder
from ours.integration.team import ARMS, build_team
from ours.security_layer.classifier import LLMClassifier
from ours.security_layer.guard import Guard

RESULTS_DIR = Path("results/runs")
RECURSION_LIMIT = 25   # caps LLM calls per run


def trace_path(out_dir, arm, case_id, trial) -> Path:
    return Path(out_dir) / arm / case_id / f"t{trial}.json"


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


async def run_one(case, arm, trial, out_dir=RESULTS_DIR, client=None, classifier=None) -> dict:
    """Run one case in one arm and write its trace. client/classifier are for offline tests."""
    config = ARMS[arm]["guard"]
    if config.classifier and classifier is None:
        classifier = LLMClassifier()
    recorder = Recorder()
    ctx = RunContext(Guard(config, classifier=classifier if config.classifier else None), recorder)
    WORLD.reset(files=case["files"], secret=case["secret"])
    team = build_team(arm, ctx, client=client)
    if isinstance(classifier, LLMClassifier) and classifier.client is None:
        classifier.client = team.client   # shares the rate limiter

    run = {
        "run_id": f"{arm}__{case['case_id']}__t{trial}", "case_id": case["case_id"],
        "split": case["split"], "kind": case["kind"], "arm": arm, "guard": config.as_dict(),
        "prompts": ARMS[arm]["prompts"], "trial": trial,
        "model": getattr(team.client, "model_name", type(team.client).__name__),
        "temperature": getattr(team.client, "temperature", None),
        "framework": "langgraph", "architecture": "centralized",
        "recursion_limit": RECURSION_LIMIT, "git_commit": _git_commit(), "started_at": _now(),
    }
    outcome = {"final_answer": None, "stop_reason": None, "error": None}
    start = time.monotonic()
    try:
        state = await team.team.ainvoke({"messages": [{"role": "user", "content": case["task"]}]},
                                        config={"recursion_limit": RECURSION_LIMIT})
        outcome["final_answer"] = text_of(state["messages"][-1])
        outcome["stop_reason"] = "completed"
    except GraphRecursionError:
        outcome["stop_reason"] = "recursion_limit"
    except APIError as exc:
        outcome["stop_reason"] = "api_error"
        outcome["error"] = f"{type(exc).__name__}: {exc}"[:2000]
    run["ended_at"] = _now()
    run["wall_s"] = round(time.monotonic() - start, 3)

    extra = {
        "executed": list(WORLD.executed),   # calls that really ran, logged by the mock tools
        "classifier_calls": list(getattr(classifier, "calls", [])) if config.classifier else [],
    }
    return recorder.write(trace_path(out_dir, arm, case["case_id"], trial), run, case["task"], outcome, extra)


def _already_done(path: Path) -> bool:
    import json
    if not path.exists():
        return False
    return json.loads(path.read_text(encoding="utf-8"))["outcome"]["error"] is None


async def main(args):
    if not os.getenv("LLM_API_KEY") or not os.getenv("LLM_MODEL"):
        sys.exit("Set LLM_API_KEY and LLM_MODEL in .env first (see .env.example).")
    cases = load_cases(split=args.split)
    if args.ids:
        cases = [c for c in cases if c["case_id"] in args.ids]
    # Trial 1 of every case and arm first, then trial 2, ...: if the daily quota runs out,
    # what finished is still balanced across cases and arms.
    jobs = [(c, arm, t) for t in range(1, args.trials + 1) for c in cases for arm in args.arms]
    todo = [j for j in jobs if args.overwrite or not _already_done(trace_path(args.out, j[1], j[0]["case_id"], j[2]))]
    if args.max_runs:
        todo = todo[:args.max_runs]
    print(f"Model: {os.getenv('LLM_MODEL')}   runs: {len(todo)} to do, {len(jobs) - len(todo)} already done\n")

    errors = 0
    for case, arm, trial in todo:
        trace = await run_one(case, arm, trial, out_dir=args.out)
        out = trace["outcome"]
        ran = [c["tool"] for c in trace["executed"]]
        blocked = [e["tool"] for e in trace["events"] if e["type"] == "tool_call" and e["decision"] == "BLOCK"]
        status = out["error"][:120] if out["error"] else out["stop_reason"]
        print(f"{arm:9} {case['case_id']:12} t{trial}  {status:16} ran={ran} blocked={blocked} "
              f"llm_calls={trace['usage']['llm_calls']}")
        if out["error"]:
            errors += 1
            if "RateLimit" in out["error"] and args.stop_on_quota:
                print("\nRate limit hit: stopping. Start the runner again later to resume.")
                break
    print(f"\nDone. API errors: {errors} (re-run the same command to retry them).")


if __name__ == "__main__":
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--arms", nargs="+", default=["A"], choices=list(ARMS))
    parser.add_argument("--split", choices=["dev", "test"], default="dev")
    parser.add_argument("--ids", nargs="*", default=None)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--out", default=str(RESULTS_DIR))
    parser.add_argument("--max-runs", type=int, default=None, help="stop after this many runs")
    parser.add_argument("--overwrite", action="store_true", help="re-run runs that already have a trace")
    parser.add_argument("--stop-on-quota", action="store_true", default=True)
    asyncio.run(main(parser.parse_args()))
