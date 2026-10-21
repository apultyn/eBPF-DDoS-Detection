"""Compare evaluated runs side by side.

    python -m analysis.compare eval/us-pcap eval/us-live eval/kernel-live \\
        [--names "user space -pcap,user space live,kernel live"] [--out eval/compare]

Each argument is an output directory of a single-run evaluation
(python -m analysis.evaluate --run ...). Prints, and with --out writes:

    compare.csv          per run: variant, source, window length, offset,
                         TP/FP/TN/FN, accuracy, precision, recall, F1, FPR,
                         attacks detected, losses
    compare_latency.csv  detection latency per attack (rows) and run (columns)

Runs with different window lengths or excerpts are compared, but with a
warning, since their numbers are then not like for like.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import pandas as pd

METRICS = ["TP", "FP", "TN", "FN", "accuracy", "precision", "recall", "f1", "fpr"]


def load(dir_: Path) -> dict:
    path = dir_ / "metrics.json"
    if not path.exists():
        raise SystemExit(f"{dir_}: no metrics.json; run analysis.evaluate first")

    m = json.loads(path.read_text())
    if "counts" not in m:
        raise SystemExit(f"{dir_}: a multi-day evaluation; compare single-run evaluations (--run)")

    return m


def row(name: str, m: dict, prediction: str) -> dict:
    run = m.get("run") or {}
    s = m["scores"][prediction]
    c = m["counts"]
    off = (run.get("offset") or {})
    losses = run.get("losses") or {}

    return {
        "run": name,
        "variant": run.get("variant"),
        "source": run.get("source"),
        "window_ms": (run.get("window_length_ns") or c.get("window_length_ns", 0)) / 1e6,
        "offset_s": off.get("offset_ns", 0) / 1e9 if run.get("live") else None,
        "offset_correlation": off.get("correlation"),
        "scored": c["windows_scored"],
        "attack_share": c.get("attack_window_share"),
        **{k: s.get(k) for k in METRICS},
        "attacks_detected": s.get("attacks_detected"),
        "attacks_total": s.get("attacks_total"),
        "window_loss": losses.get("window_loss"),
        "warnings": len(m.get("warnings", [])),
    }


def compare(dirs: list[Path], names: list[str], prediction: str) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    loaded = [load(d) for d in dirs]
    table = pd.DataFrame([row(n, m, prediction) for n, m in zip(names, loaded)])

    warnings = []
    lengths = set(table["window_ms"])
    if len(lengths) > 1:
        warnings.append(f"the runs have different window lengths ({sorted(lengths)} ms); "
                        "their metrics are not directly comparable")

    spans = {(((m.get("run") or {}).get("excerpt") or {}).get("trace_start"),
               ((m.get("run") or {}).get("excerpt") or {}).get("trace_end")) for m in loaded}
    if len(spans) > 1:
        warnings.append("the runs were scored over different excerpts (or some without --excerpt)")

    for n, m in zip(names, loaded):
        for w in m.get("warnings", []):
            warnings.append(f"{n}: {w}")

    lat = []
    for n, d in zip(names, dirs):
        f = d / "latency.csv"
        if f.exists():
            l = pd.read_csv(f)
            l = l[l["prediction"] == prediction]
            l["value"] = [f"{x:.3f}" if st == "detected" else st for x, st in zip(l["latency_s"], l["status"])]
            lat.append(l.set_index("label")["value"].rename(n))
    latency = pd.concat(lat, axis=1) if lat else pd.DataFrame()

    return table, latency, warnings


def _fmt(v) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("dirs", nargs="+", type=Path, help="evaluation output directories")
    p.add_argument("--names", help="comma-separated names for the runs; default the directory names")
    p.add_argument("--prediction", default="window", choices=["window", "window_or_ip"])
    p.add_argument("--out", type=Path, help="directory for compare.csv and compare_latency.csv")
    args = p.parse_args(argv)

    names = args.names.split(",") if args.names else [d.name for d in args.dirs]
    if len(names) != len(args.dirs):
        p.error("--names needs one name per directory")

    table, latency, warnings = compare(args.dirs, names, args.prediction)

    with pd.option_context("display.width", 200, "display.max_columns", None):
        print(table.set_index("run").T.map(_fmt).to_string())
        if not latency.empty:
            print(f"\ndetection latency per attack, s ({args.prediction} prediction, trace time)")
            print(latency.fillna("-").to_string())

    for w in warnings:
        print(f"\nWARNING: {w}")

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        table.to_csv(args.out / "compare.csv", index=False)
        latency.to_csv(args.out / "compare_latency.csv")

    return 0


if __name__ == "__main__":
    sys.exit(main())
