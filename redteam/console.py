"""CLI for the red-team console.

Usage (from the worktree root, with the venv):
  .venv/bin/python -m redteam.console run [--provider groq|env]
  .venv/bin/python -m redteam.console run --family policy_bypass

Prints one line per family (blocked/passed + judge verdict) and then the
full trace for every family. Run JSON is saved under redteam_runs/ (not
committed) so any result can be re-checked later.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from redteam import engine  # noqa: E402
from redteam.providers import get_chat_fn  # noqa: E402


def _save(run: dict) -> str:
    directory = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "redteam_runs")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"run-{run['run_id']}.json")
    with open(path, "w") as handle:
        json.dump(run, handle, indent=2)
    return path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verity red-team console")
    parser.add_argument("command", choices=["run"])
    parser.add_argument("--provider", default=None,
                        help="groq (local stored connection) or env")
    parser.add_argument("--family", default=None,
                        choices=list(engine.GENERATOR_USER))
    args = parser.parse_args(argv)
    chat_fn = get_chat_fn(args.provider)
    families = (args.family,) if args.family else tuple(engine.GENERATOR_USER)
    run = engine.run_all(chat_fn, families)
    path = _save(run)
    summary = run["summary"]
    print(f"Run {run['run_id']} ({run['provider_base_url']}): "
          f"{summary['completed']}/{summary['total']} completed, "
          f"{summary['blocked']} blocked, {summary['passed']} passed, "
          f"judge agreement {summary['judge_agreement']}, "
          f"avg {summary['avg_latency_ms']} ms")
    for trace in run["traces"]:
        print("=" * 70)
        if trace.get("status") != "ok":
            print(f"{trace['family']}: ERROR - {trace.get('error')}")
            continue
        print(f"{trace['family']}: {trace['outcome'].upper()} "
              f"(deciding layer: {trace['deciding_layer']}, "
              f"judge: {trace['judge']['verdict']})")
        print(f"  attack: {trace['attack_text']}")
        print(f"  guard signals: {trace['guard']['signals']} "
              f"(classifier {trace['guard']['classifier_score']})")
        print(f"  policy: blocked={trace['policy']['blocked']} "
              f"action={trace['policy']['action']}")
        if trace["target_response"] is not None:
            print(f"  target reply: {trace['target_response'][:400]}")
        print(f"  judge: {trace['judge']['rationale']}")
    print(f"Full run JSON saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
