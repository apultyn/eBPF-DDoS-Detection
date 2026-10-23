"""Plot individual detector runs without aggregating repetitions.

    python -m analysis.plot results/ --out results/plots --format png pdf
    python -m analysis.plot results/results/usr-per-nat-1 --kind resources
    python -m analysis.plot results/results/eval-usr-acc-gen-1 --kind accuracy

See PLOTTING.md for counter semantics, evaluation discovery and limitations.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Patch
from matplotlib.ticker import EngFormatter


BLUE, ORANGE, PURPLE, GREY = "#0072B2", "#D55E00", "#AA4499", "#666666"
COUNTERS = ("packets", "bytes", "blocked_packets", "blocked_bytes", "kernel_drops")
FLAGS = ("malicious", "evaluated", "warm_up", "truth")
STYLE = {"font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
         "axes.grid": True, "grid.alpha": 0.18, "legend.fontsize": 8}


def metadata(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def numeric(frame: pd.DataFrame, name: str) -> pd.Series:
    """Blank and absent measurements stay unknown; malformed numbers fail."""
    if name not in frame:
        return pd.Series(np.nan, index=frame.index, dtype=float)
    return pd.to_numeric(frame[name].replace("", np.nan), errors="raise")


def read_windows(path: Path) -> pd.DataFrame:
    w = pd.read_csv(path, dtype=str, keep_default_na=False)
    if w.empty:
        raise ValueError(f"{path}: no windows")
    for name in ("start_ns", "end_ns"):
        if name not in w or w[name].eq("").any():
            raise ValueError(f"{path}: missing {name}")
        # Parse integers directly: converting nanoseconds through float loses precision.
        w[name] = w[name].map(int).astype("int64")
    w = w.sort_values("start_ns").reset_index(drop=True)
    if (w.end_ns <= w.start_ns).any():
        raise ValueError(f"{path}: windows must have positive durations")
    if (w.start_ns.iloc[1:].to_numpy() < w.end_ns.iloc[:-1].to_numpy()).any():
        raise ValueError(f"{path}: overlapping windows")
    for name in COUNTERS:
        w[name] = numeric(w, name)
        if (w[name].dropna() < 0).any():
            raise ValueError(f"{path}: negative {name}")
    for name in FLAGS:
        if name not in w:
            w[name] = pd.Series(pd.NA, index=w.index, dtype="boolean")
            continue
        values = w[name].str.strip().str.lower()
        if not values.isin(("", "true", "false")).all():
            raise ValueError(f"{path}: invalid {name} boolean")
        w[name] = values.map({"true": True, "false": False}).astype("boolean")
    return w


def traffic_series(w: pd.DataFrame, source: str = "live") -> dict[str, pd.Series]:
    duration = (w.end_ns - w.start_ns) / 1e9
    # packets/bytes are already AFTER XDP blocking. Do not subtract blocks again.
    accounted = w.packets + w.blocked_packets
    if source == "live":
        accounted = accounted + w.kernel_drops
    return {"processed_pps": w.packets / duration,
            "blocked_pps": w.blocked_packets / duration,
            "capture_loss_pps": w.kernel_drops / duration,
            "accounted_pps": accounted / duration,
            "processed_MBps": w.bytes / duration / 1e6,
            "blocked_MBps": w.blocked_bytes / duration / 1e6}


def step_coordinates(w: pd.DataFrame, values: pd.Series, origin: int) -> tuple[list, list]:
    """Keep true window extents and break lines at gaps and unknown samples."""
    x, y = [], []
    previous_end = None
    for start, end, value in zip(w.start_ns, w.end_ns, values):
        if previous_end is not None and start != previous_end:
            x.append(np.nan)
            y.append(np.nan)
        x.extend(((int(start) - origin) / 1e9, (int(end) - origin) / 1e9))
        y.extend((np.nan if pd.isna(value) else float(value),) * 2)
        previous_end = end
    return x, y


def window_line(ax, w, values, origin, label, color=BLUE, linestyle="-"):
    if not values.notna().any():
        return
    x, y = step_coordinates(w, values, origin)
    ax.plot(x, y, label=label, color=color, linestyle=linestyle, linewidth=0.9)


def shade_windows(ax, w, mask, origin, color=PURPLE, alpha=0.12):
    """Merge adjacent spans to keep vector exports small."""
    ranges = []
    for start, end in zip(w.loc[mask, "start_ns"], w.loc[mask, "end_ns"]):
        if ranges and ranges[-1][1] == start:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))
    for start, end in ranges:
        ax.axvspan((int(start) - origin) / 1e9, (int(end) - origin) / 1e9,
                   color=color, alpha=alpha, linewidth=0)


def save(fig, directory: Path, name: str, formats: list[str]) -> list[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    outputs = []
    for extension in formats:
        path = directory / f"{name}.{extension}"
        fig.savefig(path, dpi=160, facecolor="white")
        outputs.append(path)
    plt.close(fig)
    return outputs


def finish_axes(axes, w, origin, xlim=None, symlog=False, sample_extent=None):
    for ax in np.atleast_1d(axes):
        if symlog:
            ax.set_yscale("symlog", linthresh=1)
        ax.set_ylim(bottom=0)
        extent = (0, (int(w.end_ns.iloc[-1]) - origin) / 1e9)
        if sample_extent is not None:
            extent = (min(extent[0], sample_extent[0]), max(extent[1], sample_extent[1]))
        ax.set_xlim(*(xlim or extent))
        ax.set_xlabel("Elapsed time from first window (s)")
        handles, labels = ax.get_legend_handles_labels()
        if handles:
            ax.legend(loc="upper right")


def plot_traffic(run: Path, out: Path, formats: list[str], xlim=None, symlog=False) -> list[Path]:
    info = metadata(run / "run.json")
    w = read_windows(run / "windows.csv")
    source = info.get("source", "live")
    origin = int(w.start_ns.iloc[0])
    rates = traffic_series(w, source)
    with plt.rc_context(STYLE):
        fig, axes = plt.subplots(3, 1, figsize=(12, 9), sharex=True)
        fig.subplots_adjust(left=0.09, right=0.98, top=0.90, bottom=0.13, hspace=0.30)
        window_line(axes[0], w, rates["accounted_pps"], origin, "Accounted arrivals (partial reconstruction)")
        window_line(axes[0], w, rates["processed_pps"], origin, "Counted after blocking", GREY, ":")
        window_line(axes[0], w, rates["blocked_pps"], origin, "Intentional XDP blocks", ORANGE, "--")
        window_line(axes[0], w, rates["capture_loss_pps"], origin, "Capture socket losses", PURPLE, "-.")
        window_line(axes[1], w, rates["processed_MBps"], origin, "Processed bytes")
        window_line(axes[1], w, rates["blocked_MBps"], origin, "Blocked bytes", ORANGE, "--")
        window_line(axes[2], w, rates["processed_pps"], origin, "Processed = counted after blocking")
        for ax, label in zip(axes, ("Packet rate (packets/s)", "Byte rate (MB/s; decimal)", "Processed rate (packets/s)")):
            ax.set_ylabel(label)
            if ax is not axes[1]:
                ax.yaxis.set_major_formatter(EngFormatter())
            shade_windows(ax, w, w.malicious.fillna(False), origin)
        finish_axes(axes, w, origin, xlim, symlog)
        fig.suptitle(f"{run.name} | traffic | {source}", fontsize=14)
        notes = ["Shading: detector flagged this window. Counted packets already exclude XDP blocks.",
                 "Accounted arrivals = counted + blocked" + (" + socket losses." if source == "live" else ".") +
                 " Upstream losses are unmeasured; this is not sender or wire throughput."]
        if source == "live" and w.blocked_packets.notna().any() and info.get("config", {}).get("block"):
            notes.append("Userspace block counters are sampled at close; rates include the closing grace period.")
        if rates["accounted_pps"].isna().any():
            notes.append("Missing counters: arrivals are unknown in those windows (line gaps).")
        fig.text(0.09, 0.015, "\n".join(notes), fontsize=8, va="bottom")
        return save(fig, out, "traffic", formats)


def sampled_csv(path: Path) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if frame.empty or "ts_ns" not in frame or frame.ts_ns.eq("").any():
        raise ValueError(f"{path}: expected samples with ts_ns")
    frame["ts_ns"] = frame.ts_ns.map(int).astype("int64")
    frame = frame.sort_values("ts_ns").reset_index(drop=True)
    if frame.ts_ns.duplicated().any():
        raise ValueError(f"{path}: duplicate sample timestamps")
    for name in frame.columns.difference(["ts_ns"]):
        frame[name] = numeric(frame, name)
    return frame


def ratio(frame, numerator, denominator):
    denom = numeric(frame, denominator)
    return numeric(frame, numerator) / denom.where(denom > 0)


def plot_resources(run: Path, out: Path, formats: list[str], xlim=None, symlog=False) -> list[Path]:
    info = metadata(run / "run.json")
    w = read_windows(run / "windows.csv")
    origin = int(w.start_ns.iloc[0])
    outputs = []
    # The independent memwatch stream continues even if verdict windows go missing.
    cpu = sampled_csv(run / "cpu.csv") if (run / "cpu.csv").exists() else w
    cpu_clock = cpu["ts_ns"] if "ts_ns" in cpu else numeric(cpu, "eval_end_ns")
    specs = [
        ("host_cpu", "Host CPU busy (% of all cores)", cpu_clock,
         [(100 * ratio(cpu, "host_busy_ns", "host_total_ns"), "Whole machine", BLUE)],
         "Includes XDP, softirq and other processes; no idle/traffic baseline has been subtracted."),
        ("host_softirq", "Host softirq (% of all CPU time)", cpu_clock,
         [(100 * ratio(cpu, "host_softirq_ns", "host_total_ns"), "Whole machine softirq", BLUE)],
         "Part of host busy time; includes packet work outside the detector process."),
        ("busiest_core", "Busiest core busy (%)", cpu_clock,
         [(100 * numeric(cpu, "host_max_core_share"), "Busiest core", BLUE)],
         "A hot receive core can be hidden by low whole-machine utilization."),
        ("process_cpu", "Detector CPU (% of one core)", numeric(w, "eval_end_ns"),
         [(100 * (numeric(w, "user_cpu_ns") + numeric(w, "sys_cpu_ns")) /
           numeric(w, "cpu_interval_ns").where(numeric(w, "cpu_interval_ns") > 0), "Detector process", BLUE)],
         "Summed over threads; 100% means one busy core. XDP per-packet work is outside this process."),
        ("heap", "Go heap allocation (MiB)", numeric(w, "eval_end_ns"),
         [(numeric(w, "heap_alloc_bytes") / 2**20, "Detector heap", BLUE)],
         "Go heap only; not total process or machine memory."),
    ]
    if (run / "memory.csv").exists():
        mem = sampled_csv(run / "memory.csv")
        main = numeric(mem, "main")
        bpf = info.get("bpf_memory", {})
        total, initial = bpf.get("total_bytes"), bpf.get("start_total_bytes")
        memory_lines = [(main / 2**20, "Cgroup main (anon + kernel + sock)", BLUE),
                        (numeric(mem, "current") / 2**20, "Cgroup current (includes file cache)", GREY)]
        note = "Cgroup main excludes file cache; kernel subcomponents must not be added to kernel again."
        if total is not None and initial == total:
            memory_lines.append(((main + total) / 2**20, "Main + separately charged BPF maps", ORANGE))
            note += " Map footprint is fixed at start/end; BPF program/JIT memory is excluded."
        else:
            note += " Total including BPF maps unavailable: no verified constant map footprint."
        specs.append(("memory", "Memory (MiB)", mem.ts_ns, memory_lines, note))
    with plt.rc_context(STYLE):
        for name, ylabel, timestamps, lines, note in specs:
            if not any(values.notna().any() for values, _, _ in lines):
                continue
            fig, ax = plt.subplots(figsize=(12, 4.6))
            fig.subplots_adjust(left=0.08, right=0.98, top=0.85, bottom=0.23)
            elapsed = (timestamps - origin) / 1e9
            for values, label, color in lines:
                if values.notna().any():
                    # A long missing sample interval must not imply observed continuity.
                    intervals = timestamps.diff()
                    typical = intervals[intervals > 0].median()
                    gap = intervals > 3 * typical
                    xx, yy = [], []
                    for t, value, missing in zip(elapsed, values, gap):
                        if missing:
                            xx.append(np.nan)
                            yy.append(np.nan)
                        xx.append(t)
                        yy.append(value)
                    ax.plot(xx, yy, label=label, color=color, linewidth=0.9)
            shade_windows(ax, w, w.malicious.fillna(False), origin)
            valid_elapsed = elapsed.dropna()
            extent = (float(valid_elapsed.min()), float(valid_elapsed.max())) if not valid_elapsed.empty else None
            finish_axes(ax, w, origin, xlim, symlog, extent)
            ax.set_ylabel(ylabel)
            fig.suptitle(f"{run.name} | {name.replace('_', ' ')}", fontsize=14)
            fig.text(0.08, 0.035, textwrap.fill(note + " Shading: flagged windows.", 145), fontsize=8)
            outputs.extend(save(fig, out, name, formats))
    return outputs


def discover_runs(root: Path) -> list[Path]:
    if (root / "run.json").is_file() and (root / "windows.csv").is_file():
        return [root]
    return sorted({p.parent for p in root.rglob("run.json") if (p.parent / "windows.csv").is_file()})


def evaluation_for(run: Path, explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        if not (explicit / "windows.csv").is_file() or not (explicit / "metrics.json").is_file():
            raise ValueError(f"{explicit}: --evaluation needs windows.csv and metrics.json")
        validate_evaluation(run, explicit)
        return explicit
    # Evaluation files often retain absolute paths from the Linux testbed.
    candidates = []
    for path in run.parent.glob("*/metrics.json"):
        info = metadata(path).get("run", {})
        saved = str(info.get("run_dir", "")).replace("\\", "/").rstrip("/")
        if saved.rsplit("/", 1)[-1] == run.name and (path.parent / "windows.csv").is_file():
            candidates.append(path.parent)
    if len(candidates) > 1:
        raise ValueError(f"{run}: several matching evaluations; select --evaluation")
    if candidates:
        validate_evaluation(run, candidates[0])
    return candidates[0] if candidates else None


def validate_evaluation(run: Path, evaluation: Path) -> None:
    """Bind a derived evaluation to the raw windows, even after moving directories."""
    m = metadata(evaluation / "metrics.json")
    saved = str(m.get("run", {}).get("run_dir", "")).replace("\\", "/").rstrip("/")
    if saved and saved.rsplit("/", 1)[-1] != run.name:
        raise ValueError(f"{evaluation}: evaluation identifies a different run ({saved})")
    raw = pd.read_csv(run / "windows.csv", dtype=str, keep_default_na=False)
    derived = pd.read_csv(evaluation / "windows.csv", dtype=str, keep_default_na=False)
    # For live evaluations, wall_start_ns preserves the original clock exactly.
    start = "wall_start_ns" if "wall_start_ns" in derived else "start_ns"
    columns = [("epoch", "epoch"), ("start_ns", start), ("packets", "packets")]
    for left, right in columns:
        if left not in raw or right not in derived:
            raise ValueError(f"{evaluation}: cannot verify raw/evaluated {left} identity")
        # Evaluation writes every raw window, including excluded rows.
        raw_values = raw.loc[raw.start_ns.map(int).sort_values().index, left].map(int).tolist()
        evaluated_values = derived.loc[derived[start].map(int).sort_values().index, right].map(int).tolist()
        if raw_values != evaluated_values:
            raise ValueError(f"{evaluation}: {left} does not match raw run {run.name}; evaluation may be stale")
    raw = raw.loc[raw.start_ns.map(int).sort_values().index].reset_index(drop=True)
    derived = derived.loc[derived[start].map(int).sort_values().index].reset_index(drop=True)
    for name in ("evaluated", "malicious"):
        if name in raw and name in derived:
            a, b = raw[name].str.lower(), derived[name].str.lower()
            used = raw.evaluated.str.lower().eq("true") if name == "malicious" else pd.Series(True, index=raw.index)
            if not a.loc[used].eq(b.loc[used]).all():
                raise ValueError(f"{evaluation}: {name} verdicts do not match raw run {run.name}")
    if "flagged_ips" in raw and "flagged_ips" in derived:
        if not numeric(raw, "flagged_ips").fillna(0).eq(numeric(derived, "flagged_ips").fillna(0)).all():
            raise ValueError(f"{evaluation}: flagged IP counts do not match raw run {run.name}")


def accuracy_values(w: pd.DataFrame, prediction="window") -> tuple[pd.Series, pd.Series, pd.Series]:
    excluded = w["excluded"].ne("") if "excluded" in w else pd.Series(False, index=w.index)
    scored = ~excluded & w.evaluated.fillna(False) & w.truth.notna()
    pred = w.malicious.copy()
    if prediction == "window_or_ip":
        ips = numeric(w, "flagged_ips")
        pred = pred | (ips > 0).astype("boolean").where(ips.notna())
    scored &= pred.notna()
    return w.truth.where(scored), pred.where(scored), scored


def plot_accuracy(evaluation: Path, out: Path, formats: list[str], prediction="window", xlim=None) -> list[Path]:
    m = metadata(evaluation / "metrics.json")
    w = read_windows(evaluation / "windows.csv")
    header = pd.read_csv(evaluation / "windows.csv", nrows=0).columns
    for required in ("truth", "evaluated", "excluded", "malicious"):
        if required not in header:
            raise ValueError(f"{evaluation}: missing {required}; run analysis.evaluate first")
    truth, pred, scored = accuracy_values(w, prediction)
    origin = int(w.start_ns.iloc[0])
    # NaN is deliberately visible as no verdict/truth, rather than benign.
    outcome = pd.Series(np.nan, index=w.index)
    for value, mask in ((0, ~truth & ~pred), (1, truth & pred), (2, ~truth & pred), (3, truth & ~pred)):
        outcome.loc[mask.fillna(False)] = value
    warnings = m.get("warnings", [])
    with plt.rc_context(STYLE):
        fig, axes = plt.subplots(3, 1, figsize=(12, 7.7), sharex=True,
                                 gridspec_kw={"height_ratios": [1, 1, 0.8]})
        fig.subplots_adjust(left=0.08, right=0.98, top=0.85, bottom=0.27, hspace=0.38)
        for ax, values, title, color in zip(axes[:2], (truth, pred), ("Actual label", f"Prediction ({prediction})"), (BLUE, ORANGE)):
            window_line(ax, w, values, origin, title, color)
            ax.set_yticks((0, 1), ("Benign", "Attack"))
            ax.set_ylim(-0.15, 1.15)
            ax.set_ylabel(title)
        colors = ["#999999", "#009E73", "#E69F00", "#CC6677"]
        x = np.column_stack(((w.start_ns - origin) / 1e9, (w.end_ns - origin) / 1e9)).ravel()
        # Each interval is drawn independently, so gaps in the CSV stay gaps.
        axes[2].barh(np.zeros(len(w)), (w.end_ns - w.start_ns) / 1e9,
                     left=(w.start_ns - origin) / 1e9, height=0.8,
                     color=[colors[int(v)] if pd.notna(v) else "#E8E8E8" for v in outcome], linewidth=0)
        axes[2].set_yticks([])
        axes[2].set_ylabel("Outcome")
        for ax in axes:
            shade_windows(ax, w, ~scored, origin, GREY, 0.10)
            ax.set_xlim(*(xlim or (0, float(x[-1]))))
        axes[-1].set_xlabel("Elapsed aligned trace time from first recorded window (s)")
        fig.legend(handles=[Patch(color=c, label=n) for c, n in zip(colors, ("TN", "TP", "FP", "FN"))] +
                       [Patch(color="#E8E8E8", label="Excluded / unavailable")], ncol=5, loc="upper center",
                       bbox_to_anchor=(0.53, 0.18))
        status = "PROVISIONAL: evaluation warnings" if warnings else "Aligned evaluation"
        fig.suptitle(f"{evaluation.name} | actual vs predicted labels\n{status}", fontsize=13,
                     color="#9A3412" if warnings else "black")
        note = "Only scored windows have labels. Grey spans include warm-up, outside-excerpt and unevaluated windows."
        if warnings:
            note += "\n" + textwrap.fill("Warnings: " + "; ".join(dict.fromkeys(warnings)), 155)
        fig.text(0.08, 0.015, note, fontsize=8, va="bottom")
        return save(fig, out, f"accuracy_{prediction}", formats)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", type=Path, help="one run, evaluation directory, or results tree")
    parser.add_argument("--kind", choices=("all", "traffic", "resources", "accuracy"), default="all")
    parser.add_argument("--out", type=Path, help="output root (default: INPUT/plots)")
    parser.add_argument("--format", nargs="+", choices=("png", "pdf", "svg"), default=["png"])
    parser.add_argument("--evaluation", type=Path, help="explicit evaluation directory for one run")
    parser.add_argument("--prediction", choices=("window", "window_or_ip"), default="window")
    parser.add_argument("--xlim", type=float, nargs=2, metavar=("START_S", "END_S"))
    parser.add_argument("--symlog", action="store_true", help="symmetric-log traffic/resource axes; preserves zeros")
    args = parser.parse_args(argv)
    if not args.directory.is_dir():
        parser.error("directory must exist")
    if args.xlim and not (all(np.isfinite(args.xlim)) and 0 <= args.xlim[0] < args.xlim[1]):
        parser.error("--xlim requires finite seconds with 0 <= START < END")
    out = args.out or args.directory / "plots"
    errors, records = [], []
    try:
        if (args.directory / "metrics.json").is_file() and (args.directory / "windows.csv").is_file():
            if args.kind not in ("all", "accuracy"):
                parser.error("evaluation directory supports --kind accuracy or all")
            runs = []
            outputs = plot_accuracy(args.directory, out / args.directory.name, args.format, args.prediction, args.xlim)
            records.append({"input": str(args.directory.resolve()), "outputs": [str(p.resolve()) for p in outputs],
                            "warnings": metadata(args.directory / "metrics.json").get("warnings", [])})
        else:
            runs = discover_runs(args.directory)
            if not runs:
                raise ValueError("no detector runs found (need run.json and windows.csv)")
            if len({run.name for run in runs}) != len(runs):
                raise ValueError("duplicate run directory names in input tree; plot each cohort to a separate --out directory")
            if args.evaluation and len(runs) != 1:
                parser.error("--evaluation requires a single run input")
        for run in runs:
            try:
                info = metadata(run / "run.json")
                performance = info.get("config", {}).get("block") is True
                outputs, notices = [], []
                dest = out / run.name
                if args.kind in ("all", "traffic"):
                    outputs.extend(plot_traffic(run, dest, args.format, args.xlim, args.symlog))
                if args.kind == "resources" or (args.kind == "all" and performance):
                    outputs.extend(plot_resources(run, dest, args.format, args.xlim, args.symlog))
                if args.kind == "accuracy" or (args.kind == "all" and not performance and info.get("source") != "pcap"):
                    evaluation = evaluation_for(run, args.evaluation)
                    if performance:
                        notices.append("accuracy skipped: blocking enabled")
                        if args.kind == "accuracy":
                            errors.append(f"{run.name}: accuracy unavailable with blocking enabled")
                    elif evaluation:
                        outputs.extend(plot_accuracy(evaluation, dest, args.format, args.prediction, args.xlim))
                        notices.extend(metadata(evaluation / "metrics.json").get("warnings", []))
                    else:
                        notices.append("accuracy skipped: no matching evaluation; truth cannot be inferred from traffic")
                        if args.kind == "accuracy":
                            errors.append(f"{run.name}: no matching evaluation")
                record = {"input": str(run.resolve()), "blocking": info.get("config", {}).get("block"),
                          "outputs": [str(p.resolve()) for p in outputs], "warnings": notices}
                records.append(record)
                print(f"{run.name}: saved {len(outputs)} files" + (f"; {len(notices)} warning(s)" if notices else ""))
            except (OSError, ValueError, KeyError) as error:
                errors.append(f"{run.name}: {error}")
        out.mkdir(parents=True, exist_ok=True)
        (out / "plot_manifest.json").write_text(json.dumps({"plots": records, "errors": errors}, indent=2), encoding="utf8")
    except (OSError, ValueError, KeyError) as error:
        errors.append(str(error))
    for error in errors:
        print(f"plot: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
