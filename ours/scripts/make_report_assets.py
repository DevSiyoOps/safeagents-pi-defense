"""
Turns the scored runs into the report's tables and figures, so the report and slides update
by re-running this one script after new runs finish.

Reads:  results/gemini35/<arm>/<case>/t<trial>.json  (main runs, gemini-3.5-flash-lite)
        results/runs/<arm>/<case>/t<trial>.json      (earlier partial runs, gemini-3.1-flash-lite)
        results/asb/<arm>/<case>.json              (the ASB sanity run)
Writes: report/generated/main_table.tex      A vs B vs C on the test split (all 7 metrics)
        report/generated/ablation_table.tex  every arm on the test split
        report/generated/asb_table.tex       ASB sample, A vs C
        report/generated/earlier_table.tex   earlier partial runs on gemini-3.1-flash-lite
        report/generated/asr_test.pdf/.png   attack success with 95% Wilson intervals (test)
        report/generated/asr_dev.pdf/.png    same for every arm on dev
        report/generated/numbers.json        every number above, for the slides

A configuration with no finished runs shows as "pending" in the tables, so nothing is
invented before the runs exist.

Run from the repo root (needs matplotlib; the base conda python has it):
    python -m ours.scripts.make_report_assets
"""
import json
from pathlib import Path

from ours.benchmark.score import score_all, summarize, wilson

RUNS = Path("results/gemini35")      # main runs (gemini-3.5-flash-lite)
RUNS_31 = Path("results/runs")       # earlier partial runs (gemini-3.1-flash-lite)
ASB = Path("results/asb")
OUT = Path("report/generated")

MAIN_ARMS = ["A", "B", "C"]
ALL_ARMS = ["A", "B", "prov_only", "perm_only", "C", "C_cls", "cls_only"]
ARM_LABEL = {
    "A": "A: no defense", "B": "B: security prompts", "C": "C: our layer",
    "prov_only": "Provenance only", "perm_only": "Permissions only",
    "C_cls": "C + classifier", "cls_only": "Classifier only",
}
RATES = [("asr", "ASR", True), ("propagation", "Propagation", True),
         ("false_positive_rate", "FPR", True), ("benign_utility", "Benign utility", False),
         ("utility_under_attack", "Utility under attack", False)]


def _pct(m):
    """'42\\% [20--61]' or 'pending'."""
    if not m or m["n"] == 0:
        return "pending"
    return f"{m['rate']:.0%} [{m['ci_low']:.0%}--{m['ci_high']:.0%}]".replace("%", "\\%")


def _summary(split, runs=RUNS):
    if not runs.exists():
        return {}
    return summarize(score_all(runs, split=split))


def metric_table(summary, arms, caption, label, labels=None):
    labels = labels or ARM_LABEL
    head = " & ".join(["Configuration"] + [name for _, name, _ in RATES] + ["Calls/run", "Latency (s)"])
    rows = []
    for arm in arms:
        s = summary.get(arm)
        if not s:
            rows.append(" & ".join([labels[arm]] + ["pending"] * (len(RATES) + 2)) + r" \\")
            continue
        cells = [_pct(s[key]) for key, _, _ in RATES]
        cells += [f"{s['mean_llm_calls']:.1f}", f"{s['mean_wall_s']:.0f}"]
        rows.append(" & ".join([labels[arm]] + cells) + r" \\")
    def short(a):  # "A: no defense (test)" -> "A (test)"
        name, _, rest = labels[a].partition(":")
        return name + (" (" + rest.split("(", 1)[1] if "(" in rest else "")
    n_note = ", ".join(f"{short(a)}: {summary[a]['asr']['n']} attack / {summary[a]['benign_utility']['n']} benign runs"
                       for a in arms if a in summary) or "no runs yet"
    return "\n".join([
        r"\begin{table*}[t]", r"\centering\small",
        rf"\caption{{{caption} Rates with 95\% Wilson intervals. ({n_note}.)}}",
        rf"\label{{{label}}}",
        r"\begin{tabular}{l" + "c" * (len(RATES) + 2) + "}", r"\toprule",
        head + r" \\", r"\midrule", *rows, r"\bottomrule", r"\end{tabular}", r"\end{table*}", ""])


def asb_numbers():
    out = {}
    for arm in ("A", "C"):
        traces = [json.loads(p.read_text()) for p in sorted((ASB / arm).glob("*.json"))]
        ok = [t for t in traces if t["outcome"]["error"] is None]
        hits = sum(bool(t["attack_success"]) for t in ok)
        fired = sum(any(e["type"] == "tool_call" and e["decision"] == "BLOCK" for e in t["events"])
                    or any(d["decision"] != "ALLOW" for e in t["events"] if e["type"] == "llm_call"
                           for d in e.get("input_decisions", []))
                    for t in ok)
        low, high = wilson(hits, len(ok))
        out[arm] = {"hits": hits, "n": len(ok), "api_errors": len(traces) - len(ok),
                    "ci_low": low, "ci_high": high, "guard_fired_runs": fired}
    return out


def asb_table(asb):
    rows = []
    for arm in ("A", "C"):
        a = asb.get(arm)
        if not a or a["n"] == 0:
            rows.append(f"{ARM_LABEL[arm]} & pending & & \\\\")
            continue
        rate = (f"{a['hits']}/{a['n']} = {a['hits'] / a['n']:.0%} "
                f"[{a['ci_low']:.0%}--{a['ci_high']:.0%}]").replace("%", "\\%")
        rows.append(f"{ARM_LABEL[arm]} & {rate} & {a['guard_fired_runs']} & {a['api_errors']} \\\\")
    return "\n".join([
        r"\begin{table}[t]", r"\centering\small",
        r"\caption{Sample of SafeAgents' ASB cases (direct injection in the user prompt). Attack "
        r"success = the attack tool was called (SafeAgents' own detector). Runs with API errors are left out.}",
        r"\label{tab:asb}", r"\begin{tabular}{lccc}", r"\toprule",
        r"Configuration & Attack success & Guard acted & API errors \\", r"\midrule", *rows,
        r"\bottomrule", r"\end{tabular}", r"\end{table}", ""])


def asr_figure(summary, arms, name, title):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    shown = [a for a in arms if a in summary and summary[a]["asr"]["n"]]
    fig, ax = plt.subplots(figsize=(3.4, 2.3))
    if not shown:
        ax.text(0.5, 0.5, "pending: no runs yet", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        rates = [summary[a]["asr"]["rate"] for a in shown]
        lo = [max(0.0, r - summary[a]["asr"]["ci_low"]) for a, r in zip(shown, rates)]
        hi = [max(0.0, summary[a]["asr"]["ci_high"] - r) for a, r in zip(shown, rates)]
        ax.bar(range(len(shown)), rates, color="#4C6A92", width=0.6)
        ax.errorbar(range(len(shown)), rates, yerr=[lo, hi], fmt="none", ecolor="#222222", capsize=3, lw=1)
        ax.set_xticks(range(len(shown)))
        ax.set_xticklabels([ARM_LABEL[a].split(":")[0] for a in shown], fontsize=7, rotation=20, ha="right")
        ax.set_ylim(0, 1)
        ax.set_ylabel("Attack success rate", fontsize=8)
        ax.tick_params(axis="y", labelsize=7)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
    ax.set_title(title, fontsize=8)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{name}.{ext}", dpi=200)
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    test, dev, asb = _summary("test"), _summary("dev"), asb_numbers()
    (OUT / "main_table.tex").write_text(metric_table(
        test, MAIN_ARMS, "Main result on the held-out test split (3 trials per case).", "tab:main"))
    (OUT / "ablation_table.tex").write_text(metric_table(
        test, ALL_ARMS, "Ablation: every configuration on the test split. A, B and C have 3 trials "
        "per case; the ablations have as many as the quota allowed (see run counts).", "tab:ablation"))
    (OUT / "asb_table.tex").write_text(asb_table(asb))
    # Earlier partial runs on gemini-3.1-flash-lite (before the model switch): A and B on test.
    t31 = _summary("test", RUNS_31)
    earlier = {k: v for k, v in (("A", t31.get("A")), ("B", t31.get("B"))) if v}
    (OUT / "earlier_table.tex").write_text(metric_table(
        earlier, ["A", "B"],
        "Earlier partial run on gemini-3.1-flash-lite (test split), stopped by outages and the "
        "daily quota before C was run.", "tab:earlier"))
    asr_figure(test, MAIN_ARMS, "asr_test", "Test split")
    asr_figure(test, ALL_ARMS, "asr_ablation", "Test split, all configurations")
    (OUT / "numbers.json").write_text(json.dumps({"test": test, "dev": dev, "asb": asb, "earlier_gemini31": earlier}, indent=2))
    for split, s in (("test", test), ("dev", dev)):
        done = ", ".join(f"{a} ({s[a]['runs']} runs)" for a in s) or "none"
        print(f"{split}: {done}")
    print(f"asb: " + ", ".join(f"{a} {v['hits']}/{v['n']}" for a, v in asb.items()))
    print(f"Wrote {OUT}/")


if __name__ == "__main__":
    main()
