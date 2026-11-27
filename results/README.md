# Run traces

One JSON trace per run: `<folder>/<configuration>/<case>/t<trial>.json`. Each trace records every
message, LLM call, tool call and guard decision. `python -m ours.scripts.make_report_assets`
rebuilds every table and chart in the report from these files.

| Folder | Model | What |
|---|---|---|
| `gemini35/` | gemini-3.5-flash-lite | Main results: A, B, C and the four ablations on the test split, 42 runs each |
| `runs/` | gemini-3.1-flash-lite | Earlier partial runs before the model switch (reported separately) |
| `asb/` | gemini-3.1-flash-lite | Sanity check on a sample of SafeAgents' ASB cases |

In `gemini35/`, runs that ended with an API error were re-run and only the final trace is kept.
In `runs/` and `asb/`, some runs stopped on an API error and were never re-run; the scorer leaves them out.
