"""
Run case files with NO guard (Config A style) and score each run from the calls that ran.

Use it to check that new cases behave as intended before trusting them:
  - benign cases should show benign=True, attack=False
  - attack cases should show attack=True on the unprotected team (otherwise they are
    too weak to be useful)

One run is roughly 5-8 requests. Check your daily quota first.

Run from the repo root:
    python -m ours.scripts.run_cases
    python -m ours.scripts.run_cases --split dev --ids atk_001 ben_001
"""
import argparse
import asyncio
import os
import sys
import time

from dotenv import load_dotenv

from ours.benchmark.casefile import check_case, load_cases
from ours.benchmark.tools import WORLD
from ours.scripts.attack_variants_probe import build_team

load_dotenv()


async def run_case(case, tools_mode):
    WORLD.reset(files=case["files"], secret=case["secret"])
    team = build_team(tools_mode)
    await team.run(task=case["task"])
    return check_case(case, WORLD.executed)


async def main(cases, pause, tools_mode):
    if not os.getenv("LLM_API_KEY") or not os.getenv("LLM_MODEL"):
        sys.exit("Set LLM_API_KEY and LLM_MODEL in .env first (see .env.example).")
    print(f"Model: {os.getenv('LLM_MODEL')}   cases: {len(cases)}   tools: {tools_mode}\n")

    ok = []
    for case in cases:
        try:
            result = await run_case(case, tools_mode)
            ran = [c["tool"] for c in WORLD.executed]
            ok.append((case, result))
            print(f"{case['case_id']:8} {case['kind']:7} attack={result['attack']}  "
                  f"benign={result['benign']}  ran={ran}")
        except Exception as exc:  # API errors are not results
            print(f"{case['case_id']:8} ERROR (not counted): {str(exc)[:300]}")
        time.sleep(pause)

    attacks = [r for c, r in ok if c["kind"] == "attack"]
    benigns = [r for c, r in ok if c["kind"] == "benign"]
    print(f"\nAttack cases: attack succeeded in {sum(r['attack'] for r in attacks)} of {len(attacks)}")
    print(f"Benign cases: task done in {sum(r['benign'] for r in benigns)} of {len(benigns)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "test"], default=None)
    parser.add_argument("--ids", nargs="*", default=None)
    parser.add_argument("--tools", choices=["partitioned", "all"], default="all")
    parser.add_argument("--pause", type=float, default=45.0)
    args = parser.parse_args()
    cases = load_cases(split=args.split)
    if args.ids:
        cases = [c for c in cases if c["case_id"] in args.ids]
    asyncio.run(main(cases, args.pause, args.tools))
