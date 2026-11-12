"""Evaluate detector windows against interval labels.

One day:

    python -m analysis.evaluate --labels labels/03-11.parquet \\
        --run results/03-11/ --out eval/03-11/

A live run (user space with -iface, or the kernel variant), replayed from
an excerpt made by scripts/excerpt.py. Its windows are on the wall clock and
are moved to trace time by an offset, found by matching packets per window
against a reference run of the same excerpt in -pcap mode:

    python -m analysis.evaluate --labels labels/03-11.parquet \\
        --run results/kernel-1/ --reference results/ref-pcap/ \\
        --excerpt excerpts/03-11.excerpt.json --out eval/kernel-1/

Several days of -pcap runs, with a total over all of them:

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

With --excerpt, only windows whose evaluated span lies entirely inside the
excerpt's first-to-last packet are scored; the rest are reported as
before_excerpt or after_excerpt, since they would otherwise count as
correctly judged normal windows. The warm-up then counts from the excerpt's
start. Runs that had blocking on are refused.

Detection latency is measured in trace time, per attack label: end_ns of the
first flagged window that overlaps the label's intervals and ends at or
after the attack's first start, minus that start.

Outputs, per day in <out>/<day>/ and for all days in <out>/:

    windows.csv   every window with its span, truth, predictions, outcome,
                  exclusion reason and the attack labels it overlaps
    latency.csv   per attack label and prediction: detected, missed, or not
                  covered by any scored window
    metrics.csv   confusion counts and accuracy, precision, recall, F1, FPR
    metrics.json  the same plus exclusion counts, warnings and, for a single
                  run, the run's variant, offset and packet losses
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

from . import alignment, groundtruth, tcpreplay
from .timefmt import format_ns, parse_duration

DEFAULT_WARMUP = 75

PREDICTIONS = ("window", "window_or_ip")


class RunError(ValueError):
    """The detector run cannot be evaluated."""


LIVE_SOURCES = ("live", "xdp")

# Losses above this fraction are warned about: they change what the
# detector sees, and with it the detection results.
LOSS_WARNING = 0.01
MAX_METADATA_BYTES = 8 * 1024 * 1024


def read_metadata(path: Path, description: str) -> dict:
    """Read small JSON metadata without ever loading a PCAP into memory."""
    try:
        with path.open("rb") as source:
            if path.stat().st_size > MAX_METADATA_BYTES:
                raise RunError(f"{description}: {path} is too large for JSON metadata; give the JSON file, not a PCAP")
            raw = source.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise RunError(f"{description}: {path} exceeds the metadata size limit")
        result = json.loads(raw)
    except (OSError, ValueError, UnicodeError) as e:
        raise RunError(f"{description}: cannot read JSON metadata from {path}: {e}") from e
    if not isinstance(result, dict):
        raise RunError(f"{description}: {path} must contain a JSON object")
    return result


def read_excerpt(path: Path) -> dict:
    excerpt = read_metadata(path, "--excerpt (expected .excerpt.json)")
    for name in ("trace_start_ns", "trace_end_ns"):
        if type(excerpt.get(name)) is not int:
            raise RunError(f"--excerpt: {path} needs an integer {name}")
    if excerpt["trace_end_ns"] < excerpt["trace_start_ns"]:
        raise RunError(f"--excerpt: {path} ends before it starts")
    return excerpt


def progress(message: str) -> None:
    print(f"evaluate: {message}", file=sys.stderr, flush=True)


@dataclass
class Run:
    windows: pd.DataFrame
    length_ns: int
    mode: str
    source: str
    info: dict
    dir: Path

    @property
    def live(self) -> bool:
        return self.source in LIVE_SOURCES

    @property
    def variant(self) -> str:
        return "kernel" if self.source == "xdp" else "userspace"


def load_run(run_dir: Path, allow_live: bool = False) -> Run:
    """Read windows.csv and the window length and mode from run.json.

    Live runs ("live" from user space with -iface, "xdp" from the kernel
    variant) are only accepted with allow_live, since they need an offset
    to trace time. Runs with blocking on are always refused: blocked
    packets never reach the detector, so it stops seeing an attack it has
    acted on, and the window metrics would no longer measure detection.
    """
    if not run_dir.is_dir():
        raise RunError(f"{run_dir}: expected a detector results directory containing run.json and windows.csv, not a PCAP")
    for name in ("run.json", "windows.csv"):
        if not (run_dir / name).is_file():
            raise RunError(f"{run_dir}: missing {name}; give a completed detector results directory")
    info = read_metadata(run_dir / "run.json", "detector run")

    source = info.get("source", "")
    if source != "pcap" and source not in LIVE_SOURCES:
        raise RunError(f"{run_dir}: unknown source {source!r}")

    if source in LIVE_SOURCES and not allow_live:
        raise RunError(
            f"{run_dir}: source is {source!r}, a live run; its windows are on the wall clock. "
            "Evaluate it on its own with --run, --excerpt and --reference (or --offset-ns)"
        )

    blocked = info.get("stats", {}).get("blocked_packets") or 0
    if info.get("config", {}).get("block") or blocked:
        raise RunError(
            f"{run_dir}: blocking was on (config.block = {info.get('config', {}).get('block')}, "
            f"{blocked} packets blocked); evaluation runs must not block"
        )

    cfg = info["config"]
    length = parse_duration(cfg["window_length"])
    mode = cfg["mode"]

    if mode not in ("combined", "current"):
        raise RunError(f"{run_dir}: unknown mode {mode!r}")

    w = pd.read_csv(
        run_dir / "windows.csv",
        usecols=["epoch", "start_ns", "end_ns", "packets", "evaluated", "malicious", "flagged_ips"],
        dtype={"epoch": "int64", "start_ns": "int64", "end_ns": "int64", "packets": "int64",
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
               mode=mode, source=source, info=info, dir=run_dir)


def series(run: Run) -> alignment.Series:
    """The run's packets per window, on the run's own clock."""
    w = run.windows
    return alignment.Series.of(w["start_ns"], w["end_ns"], w["packets"])


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
        "fpr": div(fp, fp + tn),
    }


def evaluate_day(name: str, labels: pd.DataFrame, run: Run, warmup: int,
                 offset_ns: int = 0, excerpt: dict | None = None) -> dict:
    """Label and score one day's windows.

    offset_ns (wall - trace) moves a live run's windows to trace time.
    With excerpt, only windows whose evaluated span lies inside
    [trace_start_ns, trace_end_ns] are scored, and the warm-up counts from
    the excerpt's start.
    """
    w = run.windows.copy()
    warnings: list[str] = []

    w["wall_start_ns"] = w["start_ns"]
    w["start_ns"] = w["start_ns"] - offset_ns
    w["end_ns"] = w["end_ns"] - offset_ns

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

    # Exclusions: windows outside the excerpt, windows the detector did not
    # evaluate, then the first `warmup` evaluated windows that remain.
    w["excluded"] = ""
    if excerpt is not None:
        w.loc[w["span_start_ns"] < excerpt["trace_start_ns"], "excluded"] = "before_excerpt"
        w.loc[(w["excluded"] == "") & (w["span_end_ns"] > excerpt["trace_end_ns"]), "excluded"] = "after_excerpt"

    w.loc[(w["excluded"] == "") & ~w["evaluated"], "excluded"] = "not_evaluated"

    candidates = np.flatnonzero(((w["excluded"] == "") & w["evaluated"]).to_numpy())
    w.loc[candidates[:warmup], "excluded"] = "warmup"

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
        "excluded_before_excerpt": int((w["excluded"] == "before_excerpt").sum()),
        "excluded_after_excerpt": int((w["excluded"] == "after_excerpt").sum()),
        "excluded_not_evaluated": int((w["excluded"] == "not_evaluated").sum()),
        "excluded_warmup": int((w["excluded"] == "warmup").sum()),
        "windows_scored": int(used.sum()),
        "attack_window_share": float(w.loc[used, "truth"].mean()) if used.any() else None,
        "attack_intervals": int(len(starts)),
        "offset_ns": offset_ns,
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

    counts = {k: sum(d["counts"].get(k, 0) for d in days)
              for k in ("windows_total", "excluded_before_excerpt", "excluded_after_excerpt",
                        "excluded_not_evaluated", "excluded_warmup", "windows_scored")}

    return {"scores": out, "counts": counts}


def metric_rows(name: str, result: dict) -> list[dict]:
    run = result.get("run") or {}
    extra = {k: run.get(k) for k in ("variant", "source")} if run else {}
    rows = []
    for p in PREDICTIONS:
        rows.append({"day": name, "prediction": p, **extra, **result["counts"], **result["scores"][p]})
    return rows


def describe_run(run: Run, offset_ns: int, align: alignment.Alignment | None,
                 excerpt: dict | None, reference: Run | None) -> dict:
    """What a single run was, how it was moved to trace time, and how many
    packets were lost on the way to the detector."""
    live = run.info.get("live") or {}
    nic = live.get("nic_delta") or {}
    socket = live.get("socket") or {}
    stats = run.info.get("stats", {})
    replay = tcpreplay.read(run.dir)

    losses = {
        "sent_tcpreplay": replay.get("successful") if replay else None,
        "tcpreplay_failed": replay.get("failed") if replay else None,
        "nic_rx_packets": nic.get("dev.rx_packets"),
        "nic_rx_dropped": nic.get("dev.rx_drop"),
        "socket_offered": socket.get("kernel_total"),
        "socket_dropped": socket.get("kernel_dropped"),
        "detector_packets": stats.get("packets"),
        "excerpt_packets_ip": excerpt.get("packets_ip") if excerpt else None,
    }

    warnings: list[str] = []

    # The detector starts after the replay, so the whole run cannot be
    # compared with the whole excerpt. Within windows fully inside the
    # excerpt, though, the live count should match what the reference saw.
    if reference is not None and excerpt is not None and run.live:
        w = run.windows
        inside = ((w["start_ns"] - offset_ns >= excerpt["trace_start_ns"]) &
                  (w["end_ns"] - offset_ns <= excerpt["trace_end_ns"]))
        if inside.any():
            sub = alignment.Series.of(w.loc[inside, "start_ns"], w.loc[inside, "end_ns"], w.loc[inside, "packets"])
            expected = float(alignment.predicted(series(reference), sub, offset_ns).sum())
            observed = float(sub.packets.sum())
            losses["window_packets_observed"] = int(observed)
            losses["window_packets_expected"] = round(expected)
            losses["window_loss"] = 1 - observed / expected if expected else None

            if losses["window_loss"] is not None and losses["window_loss"] > LOSS_WARNING:
                warnings.append(
                    f"{losses['window_loss']:.1%} of the excerpt's packets did not reach the detector "
                    "in the windows inside the excerpt; losses change what it detects"
                )

    if replay and replay.get("failed"):
        warnings.append(f"tcpreplay failed to send {replay['failed']} packets")
    if socket.get("kernel_dropped"):
        warnings.append(f"the capture socket dropped {socket['kernel_dropped']} packets")
    if nic.get("dev.rx_drop"):
        warnings.append(f"the interface dropped {nic['dev.rx_drop']} packets")

    timing = None
    if replay and excerpt and replay.get("actual_seconds"):
        span_s = (excerpt["trace_end_ns"] - excerpt["trace_start_ns"]) / 1e9
        timing = {"excerpt_seconds": span_s, "replay_seconds": replay["actual_seconds"],
                  "ratio": replay["actual_seconds"] / span_s if span_s else None}
        if timing["ratio"] and timing["ratio"] > 1 + LOSS_WARNING:
            warnings.append(
                f"the replay took {timing['ratio']:.3f} times the excerpt's duration; tcpreplay "
                "did not keep up with the original rate"
            )

    return {
        "variant": run.variant,
        "source": run.source,
        "live": run.live,
        "run_dir": str(run.dir),
        "window_length_ns": run.length_ns,
        "mode": run.mode,
        "offset": (align.as_dict() if align else
                   {"offset_ns": offset_ns, "method": "manual" if run.live else "none (trace replay)"}),
        "reference": str(reference.dir) if reference else None,
        "excerpt": None if excerpt is None else {
            k: excerpt.get(k) for k in ("file", "trace_start", "trace_end", "packets_ip", "max_gap_s")},
        "tcpreplay": replay,
        "replay_timing": timing,
        "losses": losses,
        "warnings": warnings + (align.warnings if align else []),
    }


WINDOW_COLUMNS = ["epoch", "start_ns", "end_ns", "wall_start_ns", "span_start_ns", "span_end_ns",
                  "packets", "evaluated",
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
        if d.get("run"):
            day_summary["run"] = d["run"]
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
    for d in days:
        r = d.get("run")
        if not r:
            continue
        o = r["offset"]
        print(f"{d['name']}: {r['variant']} ({r['source']}), window {r['window_length_ns'] / 1e6:g} ms, {r['mode']}")
        if r["live"]:
            corr = o.get("correlation")
            ratio = o.get("peak_ratio")
            print(f"  offset {o['offset_ns'] / 1e9:.3f} s by {o['method']}"
                  + (f", correlation {corr:.4f}" if corr is not None else "")
                  + (f", peak ratio {ratio:.2f}" if ratio is not None else ""))
        c = d["counts"]
        print(f"  windows: {c['windows_total']} total, {c['excluded_before_excerpt']} before and "
              f"{c['excluded_after_excerpt']} after the excerpt, {c['excluded_not_evaluated']} not evaluated, "
              f"{c['excluded_warmup']} warm-up, {c['windows_scored']} scored"
              + (f" ({c['attack_window_share']:.1%} attack)" if c["attack_window_share"] is not None else ""))
        l = r["losses"]
        print("  packets: " + ", ".join(f"{k.replace('_', ' ')} {v if not isinstance(v, float) else f'{v:.2%}'}"
                                         for k, v in l.items() if v is not None))
        print()

    print(f"{'day':<8} {'prediction':<13} {'scored':>7} {'warmup':>7} {'not eval':>8} "
          f"{'TP':>6} {'FP':>6} {'TN':>6} {'FN':>6}  {'accuracy':>8} {'precision':>9} {'recall':>8} {'F1':>8} {'FPR':>8}  attacks")

    def line(name, p, counts, s):
        print(f"{name:<8} {p:<13} {counts['windows_scored']:>7} {counts['excluded_warmup']:>7} "
              f"{counts['excluded_not_evaluated']:>8} {s['TP']:>6} {s['FP']:>6} {s['TN']:>6} {s['FN']:>6}  "
              f"{_fmt(s['accuracy']):>8} {_fmt(s['precision']):>9} {_fmt(s['recall']):>8} {_fmt(s['f1']):>8} "
              f"{_fmt(s['fpr']):>8}  {s['attacks_detected']}/{s['attacks_total']} detected")

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
    p.add_argument("--excerpt", type=Path, help="excerpt.json from scripts/excerpt.py; required for live runs")
    p.add_argument("--reference", type=Path,
                   help="results directory (run.json and windows.csv) from a -pcap run of the same excerpt")
    p.add_argument("--offset-ns", type=int, help="the offset (wall - trace) in ns, instead of --reference")
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

    single = len(specs) == 1 and not args.day
    if not single and (args.excerpt or args.reference or args.offset_ns is not None):
        p.error("--excerpt, --reference and --offset-ns apply to a single run (--labels and --run)")

    try:
        excerpt = read_excerpt(args.excerpt) if args.excerpt else None
    except RunError as e:
        p.error(str(e))

    days = []
    for name, labels_path, run_dir in specs:
        progress(f"reading detector windows from {run_dir}")
        try:
            run = load_run(run_dir, allow_live=single)
        except RunError as e:
            p.error(str(e))

        offset, align, reference = 0, None, None

        if single and run.live:
            if excerpt is None:
                p.error("a live run needs --excerpt, so that windows before and after the replay are left out")
            if args.offset_ns is not None:
                offset = args.offset_ns
            elif args.reference:
                progress(f"reading reference windows from {args.reference}")
                try:
                    reference = load_run(args.reference)
                except RunError as e:
                    p.error(f"reference: {e}")
                progress("aligning live and reference windows (bounded coarse grid)")
                try:
                    align = alignment.estimate_offset(series(reference), series(run))
                except ValueError as e:
                    p.error(f"alignment: {e}")
                offset = align.offset_ns
            else:
                p.error("a live run needs --reference (a -pcap run of the same excerpt) or --offset-ns")

        progress(f"reading and merging labels in batches from {labels_path}")
        try:
            labels = groundtruth.read_labels(labels_path)
        except (OSError, ValueError) as e:
            p.error(f"labels: {labels_path}: expected preprocessed label Parquet in the common schema: {e}")
        progress(f"scoring {len(run.windows)} windows against {int(labels['is_attack'].sum())} merged attack intervals")
        day = evaluate_day(name, labels, run, args.warmup, offset_ns=offset, excerpt=excerpt)
        if single:
            day["run"] = describe_run(run, offset, align, excerpt, reference)
            day["warnings"] = day["run"]["warnings"] + day["warnings"]
        days.append(day)

    progress(f"writing evaluation to {args.out}")
    summary = write_outputs(args.out, days)
    print_summary(days, summary)

    return 0


if __name__ == "__main__":
    sys.exit(main())
