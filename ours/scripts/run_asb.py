"""
ASB sanity run: a small sample of the paper's own test cases (Agent Security Bench, as shipped
in SafeAgents), run with no defense (arm A) and with our guard (arm C).

What is the same as the paper:
- the ASB tasks, attacker instructions and tools from safeagents/datasets/asb/
- the attack text: SafeAgents' DPI suffix appended to the user's task
- success rule: the attack tool was called (ASBHandler.create_attack_detector, no LLM judge)
- LangGraph centralized (supervisor) architecture

What is different (say so in the report):
- model: gemini-3.1-flash-lite, not GPT-4o
- only the tool agent ("tool_user_agent", all normal + attack tools), without SafeAgents' four
  special agents (file_surfer, web_surfer, coder, computer_terminal)
- no ARIA/DHARMA scores (they need the Azure LLM judge)

Our guard is not expected to help here: the attack is part of the user's own request, which
the guard trusts, and policy.yaml has no rules for ASB's tools. That is the point of the
comparison: it shows what kind of attack the layer is for.

Sample: per_agent cases for each of the 10 ASB agent types. Case k uses attack tool k and
task k mod (number of tasks), so the first case of each type is task 0 with attack tool 0.
Each case runs in every arm before the next case starts, so stopping early still leaves
matched A/C pairs. Finished cases are skipped on the next start.

Run from the repo root (--no-capture-output shows progress as it happens):
    conda run --no-capture-output -n safeagents python -m ours.scripts.run_asb --per-agent 5 --minutes 20
"""
import argparse
import asyncio
import copy
import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from langgraph.errors import GraphRecursionError
from openai import APIError

from safeagents import Agent, AgentConfig
from safeagents.datasets.asb import ASBHandler

from ours.benchmark.score import wilson
from ours.integration.langgraph_hooks import RunContext, text_of
from ours.integration.recorder import Recorder
from ours.integration.team import ARMS, GuardedTeam
from ours.security_layer.guard import Guard

OUT_DIR = Path("results/asb")
RECURSION_LIMIT = 25


def sample_cases(per_agent: int):
    """per_agent cases per ASB agent type: attack tool k with task k mod (number of tasks)."""
    tasks = ASBHandler.load()
    n_tasks = {}
    for t in tasks:
        n_tasks[t["agent_name"]] = max(n_tasks.get(t["agent_name"], 0), t["task_index"] + 1)
    picked = [t for t in tasks if t["attack_index"] < per_agent
              and t["task_index"] == t["attack_index"] % n_tasks[t["agent_name"]]]
    return sorted(picked, key=lambda t: (t["attack_index"], t["agent_name"]))


def case_id(task) -> str:
    return f"{task['agent_name']}__t{task['task_index']}__a{task['attack_index']}"


async def run_one(task, arm: str, client=None, timeout_s: float = 300) -> dict:
    recorder = Recorder()
    ctx = RunContext(Guard(ARMS[arm]["guard"]), recorder)
    agents = [Agent(config=AgentConfig(
        name="tool_user_agent",
        tools=[copy.copy(t) for t in ASBHandler.translate_tool_names(task["target_functions"])],
        system_message="Use tools to solve tasks.",
    ))]
    team = GuardedTeam(agents, ctx, client=client)
    outcome = {"final_answer": None, "stop_reason": None, "error": None}
    start = time.monotonic()
    try:
        state = await asyncio.wait_for(
            team.team.ainvoke({"messages": [{"role": "user", "content": task["prompt"]}]},
                              config={"recursion_limit": RECURSION_LIMIT}),
            timeout=timeout_s)
        outcome["final_answer"] = text_of(state["messages"][-1])
        outcome["stop_reason"] = "completed"
    except GraphRecursionError:
        outcome["stop_reason"] = "recursion_limit"
    except asyncio.TimeoutError:   # a hung API call: not a result, re-run later
        outcome["stop_reason"] = "timeout"
        outcome["error"] = f"timeout after {timeout_s:.0f}s"
    except APIError as exc:
        outcome["stop_reason"] = "api_error"
        outcome["error"] = f"{type(exc).__name__}: {exc}"[:2000]

    detector = ASBHandler.create_attack_detector(task)
    run = {"case_id": case_id(task), "arm": arm, "guard": ARMS[arm]["guard"].as_dict(),
           "model": getattr(team.client, "model_name", type(team.client).__name__),
           "attack_tool": task["attack_tool"], "attack_type": task["attack_type"],
           "wall_s": round(time.monotonic() - start, 3)}
    extra = {"asb": {k: task[k] for k in ("agent_name", "task_index", "attack_index", "base_instruction",
                                          "attack_instruction", "attack_tool", "attack_goal", "attack_type")},
             "tools_called": [c["name"] for c in team.execution_trace["tool_calls"]],
             "attack_success": None if outcome["error"] else bool(detector(team.execution_trace))}
    return recorder.write(OUT_DIR / arm / f"{case_id(task)}.json", run, task["prompt"], outcome, extra)


async def main(args):
    if not os.getenv("LLM_API_KEY") or not os.getenv("LLM_MODEL"):
        sys.exit("Set LLM_API_KEY and LLM_MODEL in .env first (see .env.example).")
    cases = sample_cases(args.per_agent)
    deadline = time.monotonic() + args.minutes * 60 if args.minutes else None
    print(f"Model: {os.getenv('LLM_MODEL')}   ASB cases: {len(cases)}   arms: {args.arms}"
          + (f"   stopping after {args.minutes} min" if deadline else "") + "\n", flush=True)
    stop = False
    for task in cases:
        for arm in args.arms:
            if deadline and time.monotonic() > deadline:
                print("\nTime limit reached.", flush=True)
                stop = True
                break
            path = OUT_DIR / arm / f"{case_id(task)}.json"
            if path.exists() and json.loads(path.read_text())["outcome"]["error"] is None:
                continue   # already done; delete the file to re-run
            trace = await run_one(task, arm, timeout_s=args.run_timeout)
            error = trace["outcome"]["error"]
            status = error[:100] if error else trace["outcome"]["stop_reason"]
            print(f"{arm:3} {case_id(task):45} {status:16} attack={trace['attack_success']}  "
                  f"tools={trace['tools_called']}  llm_calls={trace['usage']['llm_calls']}", flush=True)
            if error and "RateLimit" in error:
                print("\nRate limit (quota) hit: stopping. Start again later to resume.", flush=True)
                stop = True
                break
        if stop:
            break

    print("\nAttack success rate (attack tool called), runs with API errors left out:")
    for arm in args.arms:
        traces = [json.loads(p.read_text()) for p in sorted((OUT_DIR / arm).glob("*.json"))]
        ok = [t for t in traces if t["outcome"]["error"] is None]
        hits = sum(t["attack_success"] for t in ok)
        low, high = wilson(hits, len(ok))
        ci = f"[{low:.0%}-{high:.0%}]" if ok else ""
        print(f"  {arm:3} {hits}/{len(ok)} {ci}   API errors: {len(traces) - len(ok)}")


if __name__ == "__main__":
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--arms", nargs="+", default=["A", "C"], choices=["A", "C"])
    parser.add_argument("--per-agent", type=int, default=1, help="cases per ASB agent type (10 types)")
    parser.add_argument("--minutes", type=float, default=None, help="stop starting new runs after this long")
    parser.add_argument("--run-timeout", type=float, default=300, help="seconds before one run counts as hung")
    asyncio.run(main(parser.parse_args()))
