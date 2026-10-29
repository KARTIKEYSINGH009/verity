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
    parser.add_argument("--preset", default=None,
                        choices=list(engine.POLICY_PRESETS),
                        help="policy preset: retail, saas, or strict")
    parser.add_argument("--policy", default=None,
                        help="custom plain-language business policy text")
    parser.add_argument("--demo", action="store_true",
                        help="run offline simulation with realistic synthetic probes (no API key needed)")
    args = parser.parse_args(argv)
    policy = args.policy or (engine.POLICY_PRESETS[args.preset] if args.preset else engine.DEFAULT_POLICY)
    families = (args.family,) if args.family else engine.DEFAULT_FAMILIES
    has_key = bool(os.environ.get("REDTEAM_API_KEY") or os.environ.get("GROQ_API_KEY"))
    if args.demo or (args.provider is None and not has_key):
        run = engine.run_demo(families=families, policy=policy)
    else:
        chat_fn = get_chat_fn(args.provider)
        run = engine.run_all(chat_fn, families, policy=policy)
    path = _save(run)
    summary = run["summary"]
    print(f"Run {run['run_id']} ({run['provider_base_url']}): "
          f"{summary['completed']}/{summary['total']} completed, "
          f"{summary['blocked']} blocked, {summary['passed']} passed\n"
          f"  correct blocks: {summary.get('correct_blocks', 0)}, "
          f"false alarms: {summary.get('false_alarms', 0)}, "
          f"correct passes: {summary.get('correct_passes', 0)}, "
          f"missed: {summary.get('missed_attacks', 0)}\n"
          f"  judge agreement: {summary['judge_agreement']}, "
          f"avg {summary['avg_latency_ms']} ms\n"
          f"Policy: {policy}")
    for trace in run["traces"]:
        print("=" * 70)
        if trace.get("status") != "ok":
            print(f"{trace['family']}: ERROR - {trace.get('error')}")
            continue
        print(f"{trace['family']}: {trace['outcome'].upper()} "
              f"(deciding layer: {trace['deciding_layer']}, "
              f"judge: {trace['judge']['verdict']})")
        print(f"  prompt: {trace['attack_text']}")
        print(f"  guard signals: {trace['guard']['signals']} "
              f"(classifier {trace['guard']['classifier_score']})")
        print(f"  request policy: blocked={trace['policy_request']['blocked']} "
              f"action={trace['policy_request']['action']}")
        if trace.get("policy_response"):
            print(f"  response policy: violates={trace['policy_response']['violates']} "
                  f"action={trace['policy_response']['action']}")
        if trace["target_response"] is not None:
            print(f"  target reply: {trace['target_response'][:400]}")
        print(f"  judge: {trace['judge']['rationale']}")
    print(f"Full run JSON saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
