"""Plot saved window truth and classification outcomes on trace time.

Preserves native grids, saved exclusions, and alignment warnings. No clock
offsets or ground-truth labels are fitted or recomputed here.
"""

from collections import Counter
import csv
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.ticker import MultipleLocator

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
DATA = REPO / "results" / "data-raspberry"
TESTBED = "Raspberry Pi 400"
RUNS = (("Userspace", "usr", "run.json"), ("Kernel", "ker", "run_kernelspace.json"))
COLORS = {
    "TP": "#31816D",
    "TN": "#2864A0",
    "FP": "#E0A34B",
    "FN": "#C76552",
    "Excluded": "#C2C7CF",
}
TRUTH_COLORS = {"Benign": "#D6E3EF", "Attack": "#C47740"}


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def parse_ns(text):
    whole, fraction = text.removesuffix("Z").split(".")
    delta = datetime.fromisoformat(whole).replace(tzinfo=timezone.utc) - datetime(
        1970, 1, 1, tzinfo=timezone.utc
    )
    return (delta.days * 86400 + delta.seconds) * 10**9 + int(fraction.ljust(9, "0"))


def extract(label, prefix, manifest_name):
    name = f"{prefix}-acc-gen-1"
    directory = DATA / f"eval-{name}-adjusted"
    metrics = json.loads((directory / "metrics.json").read_text(encoding="utf-8-sig"))
    rows = read_csv(directory / "windows.csv")
    raw_dir = DATA / name
    manifest = json.loads((raw_dir / manifest_name).read_text(encoding="utf-8-sig"))
    original = read_csv(raw_dir / "windows.csv")
    assert manifest["config"]["block"] is False
    assert metrics["run"]["variant"] == ("userspace" if prefix == "usr" else "kernel")
    assert Path(metrics["run"]["run_dir"]).name == name
    assert len(rows) == len(original) == metrics["counts"]["windows_total"]
    excerpt = metrics["run"]["excerpt"]
    start, end = parse_ns(excerpt["trace_start"]), parse_ns(excerpt["trace_end"])
    width, span = metrics["counts"]["window_length_ns"], metrics["counts"]["span_ns"]
    assert metrics["counts"]["mode"] == "combined" and span == 2 * width
    offset = metrics["counts"]["offset_ns"]
    assert offset == metrics["run"]["offset"]["offset_ns"]
    table = []
    scored_counts = Counter()
    previous_end = None
    for row, raw in zip(rows, original):
        a, b = int(row["start_ns"]), int(row["end_ns"])
        assert b - a == width
        assert previous_end is None or a == previous_end
        previous_end = b
        assert row["epoch"] == raw["epoch"]
        assert int(raw["start_ns"]) - offset == a
        assert int(raw["end_ns"]) - offset == b
        assert int(row["wall_start_ns"]) == int(raw["start_ns"])
        assert row["packets"] == raw["packets"]
        assert int(row["span_end_ns"]) == b
        assert b - int(row["span_start_ns"]) == span
        assert row["truth"] in ("True", "False")
        assert (row["truth"] == "True") == bool(row["attack_labels"])
        assert row["malicious"] in ("True", "False")
        assert row["evaluated"] in ("True", "False")
        excluded = row["excluded"]
        outcome = row["outcome_window"]
        if excluded:
            assert outcome == ""
            state = "Excluded"
        else:
            assert row["evaluated"] == "True"
            actual, predicted = row["truth"] == "True", row["malicious"] == "True"
            expected = (
                ("TP" if predicted else "FN")
                if actual
                else ("FP" if predicted else "TN")
            )
            assert outcome == expected
            assert start <= int(row["span_start_ns"]) < b <= end
            state = outcome
            scored_counts[state] += 1
        if b <= start or a >= end:
            continue
        clipped_start, clipped_end = max(a, start), min(b, end)
        table.append(
            {
                "implementation": label,
                "epoch": row["epoch"],
                "start_ns": a,
                "end_ns": b,
                "span_start_ns": int(row["span_start_ns"]),
                "span_end_ns": int(row["span_end_ns"]),
                "plot_start_ns": clipped_start,
                "plot_end_ns": clipped_end,
                "plot_start_elapsed_s": (clipped_start - start) / 1e9,
                "plot_end_elapsed_s": (clipped_end - start) / 1e9,
                "truth_attack": row["truth"],
                "attack_labels": row["attack_labels"],
                "window_prediction_attack": row["malicious"],
                "plot_state": state,
                "excluded_reason": excluded,
            }
        )
    assert sum(scored_counts.values()) == metrics["counts"]["windows_scored"]
    assert all(
        scored_counts[state] == metrics["scores"]["window"][state]
        for state in ("TP", "TN", "FP", "FN")
    )
    assert all(a["plot_end_ns"] == b["plot_start_ns"] for a, b in zip(table, table[1:]))
    paths = [
        directory / "metrics.json",
        directory / "windows.csv",
        raw_dir / manifest_name,
        raw_dir / "windows.csv",
    ]
    return {
        "implementation": label,
        "directory": directory.relative_to(REPO).as_posix(),
        "trace_start_ns": start,
        "trace_end_ns": end,
        "window_ns": width,
        "effective_span_ns": span,
        "rows": table,
        "scores": dict(scored_counts),
        "saved_counts": metrics["counts"],
        "alignment": metrics["run"]["offset"],
        "warnings": metrics["warnings"],
        "first_mapped_window_elapsed_s": (table[0]["plot_start_ns"] - start) / 1e9,
        "unobserved_prefix_s": (table[0]["plot_start_ns"] - start) / 1e9,
        "version": manifest["version"],
        "source_sha256": {
            path.relative_to(REPO)
            .as_posix(): hashlib.sha256(path.read_bytes())
            .hexdigest()
            for path in paths
        },
    }


def merge_groups(rows, state_key):
    groups = []
    for row in rows:
        state = row[state_key]
        if (
            groups
            and groups[-1]["state"] == state
            and groups[-1]["end_ns"] == row["plot_start_ns"]
        ):
            groups[-1]["end_ns"] = row["plot_end_ns"]
        else:
            groups.append(
                {
                    "start_ns": row["plot_start_ns"],
                    "end_ns": row["plot_end_ns"],
                    "state": state,
                }
            )
    return groups


def main():
    runs = [extract(*spec) for spec in RUNS]
    start, end = runs[0]["trace_start_ns"], runs[0]["trace_end_ns"]
    assert all(
        run["trace_start_ns"] == start and run["trace_end_ns"] == end for run in runs
    )
    assert all(run["window_ns"] == runs[0]["window_ns"] for run in runs)
    methods = sorted({run["alignment"].get("method", "unspecified") for run in runs})
    alignment_warnings = {
        run["implementation"]: run["alignment"].get("warnings", []) for run in runs
    }
    has_alignment_warnings = any(alignment_warnings.values())
    if has_alignment_warnings:
        status = "Provisional: saved alignment warnings are preserved."
    elif methods == ["manual"]:
        status = "Updated evaluations with saved manual trace offsets."
    else:
        status = "Saved trace mappings; no alignment warnings recorded."
    # The kernel label grid covers the complete excerpt. A userspace grid
    # may cover less of it; any missing prefix stays grey in the outcome row.
    truth_rows = []
    for row in runs[1]["rows"]:
        truth_rows.append(
            {
                **row,
                "truth_state": "Attack" if row["truth_attack"] == "True" else "Benign",
            }
        )
    assert truth_rows[0]["plot_start_ns"] == start
    assert truth_rows[-1]["plot_end_ns"] == end
    truth_groups = merge_groups(truth_rows, "truth_state")
    with (OUT / "figure-11-outcomes.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=list(runs[0]["rows"][0]))
        writer.writeheader()
        for run in runs:
            writer.writerows(run["rows"])
    with (OUT / "figure-11-ground-truth.csv").open(
        "w", newline="", encoding="utf-8"
    ) as stream:
        columns = [
            "start_ns",
            "end_ns",
            "span_start_ns",
            "span_end_ns",
            "plot_start_ns",
            "plot_end_ns",
            "plot_start_elapsed_s",
            "plot_end_elapsed_s",
            "truth_attack",
            "attack_labels",
            "truth_state",
        ]
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(truth_rows)
    evidence = {
        "figure": 11,
        "testbed": TESTBED,
        "status": status,
        "alignment_methods": methods,
        "alignment_warnings": alignment_warnings,
        "prediction": "window: malicious column, not window_or_ip",
        "axis": "Trace elapsed minutes from 2018-12-01T14:21:52.153161000Z; ends at 2018-12-01T15:01:51.999846000Z.",
        "window_ns": runs[0]["window_ns"],
        "effective_span_ns": runs[0]["effective_span_ns"],
        "ground_truth_source": runs[1]["directory"],
        "ground_truth_groups": truth_groups,
        "grey": "Saved excluded windows and intervals with no aligned native windows; these causes remain distinct in the data.",
        "limitations": [
            "Offsets and their recorded diagnostics are used verbatim from the evaluations. This plot does not independently validate replay timing or refit offsets.",
            "The top truth strip uses the kernel evaluation's native grid because it covers the complete excerpt. Each outcome is computed against its own saved native-grid truth.",
            "The two native grids are not resampled or paired, and have different scored-window counts; sub-window differences at truth transitions are expected.",
            "Combined-mode labels apply to the current and previous window. The strip colors each current-window bin, approximately 0.537 seconds, using a 1.074-second effective span.",
            "Grey intervals without native windows mean no windows mapped there under the saved offset, not a benign verdict or proven lack of physical capture.",
            "The original corrected flow labels and packet trace remain remote; their saved adjusted evaluation outputs are used here.",
            "Short states retain their actual durations. PNG rendering cannot reliably expose every isolated subpixel window; PDF/SVG and CSV preserve the intervals.",
        ],
        "needed_for_validated_time_comparison": [
            "Sender replay logs and independent packet/traffic landmarks validating trace-to-live timing throughout each run.",
            "A corrected evaluation after resolving replay timing, with original corrected flow labels and trace provenance; rerun synchronized replay if a constant offset cannot fit.",
        ],
        "runs": [
            {key: value for key, value in run.items() if key != "rows"} for run in runs
        ],
    }
    (OUT / "figure-11-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "axes.spines.bottom": False,
            "axes.axisbelow": True,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.facecolor": "white",
        }
    )
    fig, axes = plt.subplots(3, 1, figsize=(12, 4.7), sharex=True)
    fig.subplots_adjust(left=0.15, right=0.985, top=0.73, bottom=0.15, hspace=0.35)
    fig.text(
        0.15,
        0.965,
        f"Window classification over time: {TESTBED}",
        fontsize=15.5,
        weight="bold",
        va="top",
    )
    handles = [
        Patch(facecolor=COLORS[state], label=state)
        for state in ("TP", "TN", "FP", "FN")
    ]
    handles.append(
        Patch(facecolor=COLORS["Excluded"], label="Excluded / no aligned windows")
    )
    fig.legend(
        handles=handles,
        loc="upper left",
        bbox_to_anchor=(0.143, 0.90),
        frameon=False,
        ncols=5,
        fontsize=10.5,
        handlelength=1.4,
        columnspacing=1.8,
    )
    duration_min = (end - start) / 60e9
    for ax, label in zip(
        axes, ("Ground truth", "Userspace\noutcome", "Kernel\noutcome")
    ):
        ax.set_xlim(0, math.ceil(duration_min))
        ax.set_ylim(0, 1)
        ax.set_yticks([])
        ax.set_ylabel(
            label, rotation=0, ha="right", va="center", labelpad=13, fontsize=11
        )
        ax.tick_params(axis="x", length=0, pad=9)
        ax.grid(axis="x", color="#E5E7EB", linewidth=0.6)
    for group in truth_groups:
        a, b = (group["start_ns"] - start) / 60e9, (group["end_ns"] - start) / 60e9
        state = group["state"]
        axes[0].broken_barh(
            [(a, b - a)], (0.08, 0.84), facecolors=TRUTH_COLORS[state], zorder=3
        )
        text = "Attack: DrDoS_DNS" if state == "Attack" else "Benign"
        axes[0].text(
            (a + b) / 2,
            0.5,
            text,
            ha="center",
            va="center",
            fontsize=10,
            weight="bold",
            color="white" if state == "Attack" else "#273345",
            zorder=4,
        )
    for ax, run in zip(axes[1:], runs):
        ax.broken_barh(
            [(0, duration_min)], (0.08, 0.84), facecolors=COLORS["Excluded"], zorder=2
        )
        groups = merge_groups(run["rows"], "plot_state")
        for state, color in COLORS.items():
            spans = [
                ((g["start_ns"] - start) / 60e9, (g["end_ns"] - g["start_ns"]) / 60e9)
                for g in groups
                if g["state"] == state
            ]
            if spans:
                ax.broken_barh(
                    spans, (0.08, 0.84), facecolors=color, edgecolors="none", zorder=3
                )
        if run["unobserved_prefix_s"] > 120:
            ax.text(
                run["unobserved_prefix_s"] / 120,
                0.5,
                "No aligned windows",
                ha="center",
                va="center",
                fontsize=9,
                color="#414B59",
                zorder=4,
            )
    axes[-1].xaxis.set_major_locator(MultipleLocator(5))
    axes[-1].set_xlabel("Elapsed trace time (min)", labelpad=10)
    for extension in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"figure-11-window-classification.{extension}", dpi=300)
    plt.close(fig)
    for run in runs:
        print(
            json.dumps(
                {
                    "implementation": run["implementation"],
                    "counts": run["scores"],
                    "first_mapped_window_s": run["first_mapped_window_elapsed_s"],
                    "alignment_method": run["alignment"].get("method"),
                    "correlation": run["alignment"].get("correlation"),
                    "peak_ratio": run["alignment"].get("peak_ratio"),
                }
            )
        )


if __name__ == "__main__":
    main()
