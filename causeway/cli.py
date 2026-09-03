"""The command line. Everything the console shows is reachable from here without a browser.

    causeway run       correlate a corpus and print the cases, root causes and responses
    causeway metrics   measure every configuration and write results/<corpus>.json
    causeway export    write a corpus as JSONL, the shape `causeway run <file>` accepts
    causeway serve     start the analyst console

Nothing here decides anything; it is a projection of `Pipeline`, the same one the server
and the tests use.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import dedup, metrics
from .corpus import Scenario, load
from .pipeline import Case, Pipeline
from .schema import dump_alerts


def _add_corpus_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("corpus", nargs="?", default="lab",
                        help="'lab' (default), 'ait', or a path to a .jsonl file")
    parser.add_argument("--scenario", default=None, help="AIT scenario name")
    parser.add_argument("--seed", type=int, default=7, help="lab corpus seed")


def _load(args: argparse.Namespace) -> Scenario:
    return load(args.corpus, scenario=args.scenario, seed=args.seed)


# -- run ---------------------------------------------------------------------------------

def _case_text(case: Case, *, verbose: bool) -> str:
    inc, rec = case.incident, case.recommendation
    lines = [
        f"{inc.id}  {inc.alert_count} alerts / {len(inc.observations)} observations  "
        f"{', '.join(inc.sensors)}  {inc.to_dict()['first_seen']} -> {inc.to_dict()['last_seen']}",
        f"  confidence {inc.confidence:.2f}   evidence: {inc.to_dict()['evidence_label']}",
    ]
    for i, root in enumerate(case.roots, 1):
        lines.append(f"  root #{i}  {root.entity.label:40} score {root.score:.3f}")
    lines.append(f"  recommend  {rec.recommended_label}  [{rec.recommended}]")
    if rec.blocked_reason:
        lines.append(f"  withheld   {rec.blocked_reason}")
    if verbose:
        for obs in inc.observations:
            rep = obs.representative
            dup = f" (x{obs.count})" if obs.count > 1 else ""
            lines.append(f"    {rep.when}  {rep.sensor:9} {rep.text}{dup}")
        for edge in inc.edges:
            lines.append(f"    {edge.src} -> {edge.dst}  {edge.confidence:.2f}  {edge.reason}")
    return "\n".join(lines)


def cmd_run(args: argparse.Namespace) -> int:
    scn = _load(args)
    pipe = Pipeline.from_scenario(scn).run()
    if args.json:
        args.json.write_text(json.dumps(pipe.state(), indent=2) + "\n")
        print(f"wrote {args.json}")
        return 0
    s = pipe.summary()
    print(f"corpus {s['corpus']}: {s['alerts']} alerts -> {s['observations']} observations "
          f"-> {s['incidents']} incidents   ({s['suppressed']} duplicates held in the ledger)")
    print(f"audit chain: {s['audit_events']} events, "
          f"{'intact' if s['audit_intact'] else 'BROKEN at ' + str(s['audit_first_bad'])}")
    print()
    for case in pipe.cases[:args.top]:
        print(_case_text(case, verbose=args.verbose))
        print()
    if len(pipe.cases) > args.top:
        print(f"... {len(pipe.cases) - args.top} more; raise --top or use --json")
    return 0


# -- metrics -----------------------------------------------------------------------------

def cmd_metrics(args: argparse.Namespace) -> int:
    scn = _load(args)
    payload = metrics.run_all(scn, window=args.window)
    out = args.out or metrics.RESULTS_DIR / f"{scn.name}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print()
    print(metrics.render(payload))
    print(f"\nwrote {out}")
    return 0


# -- export ------------------------------------------------------------------------------

def cmd_export(args: argparse.Namespace) -> int:
    scn = _load(args)
    dump_alerts(scn.alerts, str(args.out))
    print(f"wrote {len(scn.alerts)} alerts to {args.out}")
    return 0


# -- serve -------------------------------------------------------------------------------

def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("the console needs the server extra: pip install -e '.[server]'", file=sys.stderr)
        return 2
    import os
    os.environ["CAUSEWAY_CORPUS"] = args.corpus
    if args.scenario:
        os.environ["CAUSEWAY_SCENARIO"] = args.scenario
    uvicorn.run("server.app:app", host=args.host, port=args.port)
    return 0


# -- entry -------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="causeway", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="correlate a corpus and print the cases")
    _add_corpus_args(run)
    run.add_argument("--top", type=int, default=5, help="cases to print (default 5)")
    run.add_argument("-v", "--verbose", action="store_true",
                     help="also print every observation and edge")
    run.add_argument("--json", type=Path, default=None, help="write the full state here")
    run.set_defaults(func=cmd_run)

    met = sub.add_parser("metrics", help="measure every configuration over a corpus")
    _add_corpus_args(met)
    met.add_argument("--window", type=int, default=dedup.REPEAT_WINDOW,
                     help=f"duplicate repeat window in seconds (default {dedup.REPEAT_WINDOW})")
    met.add_argument("--out", type=Path, default=None,
                     help="results file (default results/<corpus>.json)")
    met.set_defaults(func=cmd_metrics)

    exp = sub.add_parser("export", help="write a corpus as JSONL")
    _add_corpus_args(exp)
    exp.add_argument("--out", type=Path, required=True)
    exp.set_defaults(func=cmd_export)

    srv = sub.add_parser("serve", help="start the analyst console")
    _add_corpus_args(srv)
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=8788)
    srv.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
