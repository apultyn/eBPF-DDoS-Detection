"""Evaluate detector windows against interval labels.

One day:

    python -m analysis.evaluate --labels labels/03-11.parquet \\
        --run results/03-11/ --out eval/03-11/

Several days, with a total over all of them:

    python -m analysis.evaluate \\
        --day 03-11 labels/03-11.parquet results/03-11/ \\
        --day 01-12 labels/01-12.parquet results/01-12/ \\
        --out eval/

Ground truth follows Koshovyi & Wu (2026), section 4.1.3; see
analysis.groundtruth. Each window is judged over the span the detector
actually evaluated: in combined mode the previous and the current window,
read from run.json. Only windows with evaluated = true are used, and the
first --warmup of those per day (default 75, as in the 2026 thesis) are
excluded as warm-up.

Two predictions are scored. "window" is the window-level verdict (the
malicious column). "window_or_ip" also counts a window as flagged when any
source in it was flagged per IP.

Detection latency is measured in trace time, per attack label: end_ns of the
first flagged window that overlaps the label's intervals and ends at or
after the attack's first start, minus that start.

Outputs, per day in <out>/<day>/ and for all days in <out>/:

    windows.csv   every window with its span, truth, predictions, outcome,
                  exclusion reason and the attack labels it overlaps
    latency.csv   per attack label and prediction: detected, missed, or not
                  covered by any scored window
    metrics.csv   confusion counts and accuracy, precision, recall, F1
    metrics.json  the same plus exclusion counts and warnings
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from . import groundtruth, schema
from .timefmt import format_ns, parse_duration

DEFAULT_WARMUP = 75

PREDICTIONS = ("window", "window_or_ip")


class RunError(ValueError):
    """The detector run cannot be evaluated."""


@dataclass
class Run:
    windows: pd.DataFrame
    length_ns: int
    mode: str
    source: str


def load_run(run_dir: Path) -> Run:
    """Read windows.csv and the window length and mode from run.json."""
    info = json.loads((run_dir / "run.json").read_text())

    source = info.get("source", "")
    if source != "pcap":
        raise RunError(
            f"{run_dir}: source is {source!r}; ground truth is in trace time, so only "
            "trace replays (-pcap) can be matched against labels"
        )

    cfg = info["config"]
    length = parse_duration(cfg["window_length"])
    mode = cfg["mode"]

    if mode not in ("combined", "current"):
        raise RunError(f"{run_dir}: unknown mode {mode!r}")

    w = pd.read_csv(
        run_dir / "windows.csv",
        usecols=["epoch", "start_ns", "end_ns", "evaluated", "malicious", "flagged_ips"],
        dtype={"epoch": "int64", "start_ns": "int64", "end_ns": "int64",
               "evaluated": str, "malicious": str, "flagged_ips": str},
        keep_default_na=False,
    )

    if not (w["end_ns"] - w["start_ns"] == length).all():
        raise RunError(f"{run_dir}: windows.csv does not match window_length {cfg['window_length']} in run.json")

    w["evaluated"] = w["evaluated"].map({"true": True, "false": False})
    if w["evaluated"].isna().any():
        raise RunError(f"{run_dir}: unexpected values in the evaluated column")

    w["malicious"] = w["malicious"].eq("true")
    w["flagged_ips"] = pd.to_numeric(w["flagged_ips"].replace("", "0")).astype("int64")

    return Run(windows=w.sort_values("epoch").reset_index(drop=True), length_ns=length,
               mode=mode, source=source)


def score(truth: np.ndarray, predicted: np.ndarray) -> dict:
    """Confusion counts and metrics. A metric whose denominator is zero is
    reported as None rather than as a number."""
    tp = int(np.sum(truth & predicted))
    fp = int(np.sum(~truth & predicted))
    tn = int(np.sum(~truth & ~predicted))
    fn = int(np.sum(truth & ~predicted))

    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, **metrics(tp, fp, tn, fn)}


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    def div(a, b):
        return a / b if b else None

    precision = div(tp, tp + fp)
    recall = div(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)

    return {
        "accuracy": div(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def evaluate_day(name: str, labels: pd.DataFrame, run: Run, warmup: int) -> dict:
    """Label and score one day's windows."""
    w = run.windows.copy()
    warnings: list[str] = []

    # The span the detector judged: in combined mode the previous window as
    # well. Unevaluated windows are exactly those without an adjacent
    # previous window, so every evaluated span is contiguous.
    w["span_start_ns"] = w["start_ns"] - (run.length_ns if run.mode == "combined" else 0)
    w["span_end_ns"] = w["end_ns"]

    starts, ends = groundtruth.attack_intervals(labels)
    by_label = groundtruth.intervals_by_label(labels)

    w["truth"] = groundtruth.overlaps(w["span_start_ns"], w["span_end_ns"], starts, ends)
    w["attack_labels"] = groundtruth.overlapping_labels(w["span_start_ns"], w["span_end_ns"], by_label)

    w["pred_window"] = w["malicious"]
    w["pred_window_or_ip"] = w["malicious"] | (w["flagged_ips"] > 0)

    # Exclusions: windows the detector did not evaluate, then the first
    # `warmup` evaluated windows.
    w["excluded"] = ""
    w.loc[~w["evaluated"], "excluded"] = "not_evaluated"

    evaluated_idx = np.flatnonzero(w["evaluated"].to_numpy())
    w.loc[evaluated_idx[:warmup], "excluded"] = "warmup"

    used = w["excluded"].eq("")

    for p in PREDICTIONS:
        col = w["pred_" + p]
        outcome = np.where(w["truth"], np.where(col, "TP", "FN"), np.where(col, "FP", "TN"))
        w["outcome_" + p] = np.where(used, outcome, "")

    # Sanity checks that catch a wrong --time-offset or the wrong labels.
    if len(starts) and used.any():
        first_used = int(w.loc[used, "span_start_ns"].min())
        last_used = int(w.loc[used, "span_end_ns"].max())
        label_first = int(labels["start_ns"].min())
        label_last = int(labels["end_ns"].max())

        if label_last < first_used or label_first > last_used:
            warnings.append(
                f"labels ({format_ns(label_first)} to {format_ns(label_last)}) do not overlap the "
                f"scored windows ({format_ns(first_used)} to {format_ns(last_used)}); "
                "check --time-offset and that labels and run are from the same day"
            )
        elif not w.loc[used, "truth"].any():
            warnings.append("no scored window overlaps an attack interval")

    if not used.any():
        warnings.append("no windows left to score after exclusions")

    scores = {p: score(w.loc[used, "truth"].to_numpy(), w.loc[used, "pred_" + p].to_numpy())
              for p in PREDICTIONS}

    latency = attack_latency(w, used, by_label)

    for p in PREDICTIONS:
        lp = latency[latency["prediction"] == p]
        scores[p]["attacks_total"] = int(len(lp))
        scores[p]["attacks_detected"] = int((lp["status"] == "detected").sum())
        scores[p]["attacks_not_covered"] = int((lp["status"] == "not_covered").sum())

    counts = {
        "windows_total": int(len(w)),
        "excluded_not_evaluated": int((w["excluded"] == "not_evaluated").sum()),
        "excluded_warmup": int((w["excluded"] == "warmup").sum()),
        "windows_scored": int(used.sum()),
        "attack_intervals": int(len(starts)),
        "mode": run.mode,
        "window_length_ns": run.length_ns,
        "span_ns": run.length_ns * (2 if run.mode == "combined" else 1),
        "warmup": warmup,
    }

    return {"name": name, "windows": w, "latency": latency, "scores": scores,
            "counts": counts, "warnings": warnings}


def attack_latency(w: pd.DataFrame, used: pd.Series, by_label: dict) -> pd.DataFrame:
    """Detection latency per attack label, in trace time."""
    rows = []
    scored = w[used]

    for name, (s, e) in by_label.items():
        attack_start = int(s[0])
        covers = groundtruth.overlaps(scored["span_start_ns"], scored["span_end_ns"], s, e)

        for p in PREDICTIONS:
            hit = scored[covers & scored["pred_" + p].to_numpy() & (scored["end_ns"] >= attack_start).to_numpy()]

            row = {
                "label": name,
                "prediction": p,
                "attack_start_ns": attack_start,
                "attack_start_utc": format_ns(attack_start),
                "attack_end_ns": int(e[-1]),
                "scored_windows_overlapping": int(covers.sum()),
                "first_flagged_end_ns": None,
                "latency_s": None,
            }

            if not covers.any():
                row["status"] = "not_covered"
            elif hit.empty:
                row["status"] = "missed"
            else:
                first_end = int(hit["end_ns"].min())
                row["status"] = "detected"
                row["first_flagged_end_ns"] = first_end
                row["latency_s"] = (first_end - attack_start) / 1e9

            rows.append(row)

    columns = ["label", "prediction", "status", "attack_start_ns", "attack_start_utc", "attack_end_ns",
               "scored_windows_overlapping", "first_flagged_end_ns", "latency_s"]

    return pd.DataFrame(rows, columns=columns)


def total(days: list[dict]) -> dict:
    """Sum confusion counts over days and recompute the metrics."""
    out = {}

    for p in PREDICTIONS:
        c = {k: sum(d["scores"][p][k] for d in days)
             for k in ("TP", "FP", "TN", "FN", "attacks_total", "attacks_detected", "attacks_not_covered")}
        out[p] = {**c, **metrics(c["TP"], c["FP"], c["TN"], c["FN"])}

    counts = {k: sum(d["counts"][k] for d in days)
              for k in ("windows_total", "excluded_not_evaluated", "excluded_warmup", "windows_scored")}

    return {"scores": out, "counts": counts}


def metric_rows(name: str, result: dict) -> list[dict]:
    rows = []
    for p in PREDICTIONS:
        rows.append({"day": name, "prediction": p, **result["counts"], **result["scores"][p]})
    return rows


WINDOW_COLUMNS = ["epoch", "start_ns", "end_ns", "span_start_ns", "span_end_ns", "evaluated",
                  "excluded", "truth", "malicious", "flagged_ips",
                  "outcome_window", "outcome_window_or_ip", "attack_labels"]


def write_outputs(out: Path, days: list[dict]) -> dict:
    out.mkdir(parents=True, exist_ok=True)

    summary = {"days": {}, "total": None}
    all_rows = []

    for d in days:
        dir_ = out / d["name"] if len(days) > 1 else out
        dir_.mkdir(parents=True, exist_ok=True)

        d["windows"][WINDOW_COLUMNS].to_csv(dir_ / "windows.csv", index=False)
        d["latency"].to_csv(dir_ / "latency.csv", index=False)

        rows = metric_rows(d["name"], d)
        pd.DataFrame(rows).to_csv(dir_ / "metrics.csv", index=False)

        day_summary = {"counts": d["counts"], "scores": d["scores"], "warnings": d["warnings"]}
        (dir_ / "metrics.json").write_text(json.dumps(day_summary, indent=2) + "\n")

        summary["days"][d["name"]] = day_summary
        all_rows.extend(rows)

    if len(days) > 1:
        t = total(days)
        summary["total"] = t
        all_rows.extend(metric_rows("all", t))

        pd.DataFrame(all_rows).to_csv(out / "metrics.csv", index=False)
        (out / "metrics.json").write_text(json.dumps(summary, indent=2) + "\n")

    return summary


def _fmt(v) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "n/a"
    return f"{v:.4f}"


def print_summary(days: list[dict], summary: dict) -> None:
    print()
    print(f"{'day':<8} {'prediction':<13} {'scored':>7} {'warmup':>7} {'not eval':>8} "
          f"{'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6}  {'accuracy':>8} {'precision':>9} {'recall':>8} {'F1':>8}  attacks")

    def line(name, p, counts, s):
        print(f"{name:<8} {p:<13} {counts['windows_scored']:>7} {counts['excluded_warmup']:>7} "
              f"{counts['excluded_not_evaluated']:>8} {s['TP']:>6} {s['FP']:>6} {s['TN']:>6} {s['FN']:>6}  "
              f"{_fmt(s['accuracy']):>8} {_fmt(s['precision']):>9} {_fmt(s['recall']):>8} {_fmt(s['f1']):>8}  "
              f"{s['attacks_detected']}/{s['attacks_total']} detected")

    for d in days:
        for p in PREDICTIONS:
            line(d["name"], p, d["counts"], d["scores"][p])

    if summary["total"]:
        for p in PREDICTIONS:
            line("all", p, summary["total"]["counts"], summary["total"]["scores"][p])

    for d in days:
        lat = d["latency"][d["latency"]["prediction"] == "window"]
        if lat.empty:
            continue

        print(f"\n{d['name']}: detection latency per attack (window prediction, trace time)")
        for r in lat.itertuples():
            detail = f"{r.latency_s:.3f} s" if r.status == "detected" else r.status
            print(f"  {r.label:<16} starts {r.attack_start_utc}  {detail}")

    for d in days:
        for warn in d["warnings"]:
            print(f"\nWARNING ({d['name']}): {warn}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--day", nargs=3, action="append", metavar=("NAME", "LABELS", "RUN"),
                   help="a day to evaluate: name, label parquet, detector result directory; repeatable")
    p.add_argument("--labels", type=Path, help="label parquet, for a single day")
    p.add_argument("--run", type=Path, help="detector result directory, for a single day")
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--warmup", type=int, default=DEFAULT_WARMUP,
                   help=f"evaluated windows excluded at the start of each day (default {DEFAULT_WARMUP})")
    p.add_argument("--force", action="store_true", help="write into a non-empty output directory")
    args = p.parse_args(argv)

    specs = []
    if args.day:
        specs = [(n, Path(l), Path(r)) for n, l, r in args.day]
    if args.labels or args.run:
        if not (args.labels and args.run):
            p.error("--labels and --run go together")
        specs.append((args.labels.stem, args.labels, args.run))
    if not specs:
        p.error("give --labels and --run, or one or more --day")

    if len({n for n, _, _ in specs}) != len(specs):
        p.error("day names must be unique")

    if args.out.exists() and any(args.out.iterdir()) and not args.force:
        p.error(f"{args.out} is not empty; use --force to write into it")

    days = []
    for name, labels_path, run_dir in specs:
        try:
            run = load_run(run_dir)
        except RunError as e:
            p.error(str(e))

        labels = schema.read(labels_path)
        days.append(evaluate_day(name, labels, run, args.warmup))

    summary = write_outputs(args.out, days)
    print_summary(days, summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
