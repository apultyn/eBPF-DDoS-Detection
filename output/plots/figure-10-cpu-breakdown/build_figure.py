"""Rebuild Figure 10 for the FABRIC and Raspberry Pi recordings.

Run from the repository root:
    .venv/Scripts/python.exe output/plots/figure-10-cpu-breakdown/build_figure.py

Raw recordings are read only. CPU cores are CPU nanoseconds / wall nanoseconds.
"""

import csv
import hashlib
import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator


OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
BIN_NS = 30_000_000_000
RUNS = (
    ("FABRIC", "data-fabric", "Userspace", "live", "usr-per-gen-3", "run.json"),
    ("FABRIC", "data-fabric", "Kernel", "xdp", "ker-per-gen-3", "run.json"),
    ("Raspberry Pi", "data-raspberry", "Userspace", "live", "usr-acc-gen-1", "run.json"),
    ("Raspberry Pi", "data-raspberry", "Kernel", "xdp", "ker-acc-gen-1", "run_kernelspace.json"),
)
COUNTERS = ("cpu_interval_ns", "host_busy_ns", "host_total_ns",
            "host_softirq_ns", "user_cpu_ns", "sys_cpu_ns")


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def select_phase(rows, origin, source):
    """Find the sustained flood using traffic only, before reading CPU deltas.

    Average packet rate in 30-second bins. Take the longest contiguous span
    above half the 95th-percentile full-bin rate, then trim one bin at each
    edge to exclude flood transitions. Split boundary windows proportionally.
    """
    count = math.ceil((int(rows[-1]["end_ns"]) - origin) / BIN_NS)
    packets = [0.0] * count
    durations = [0] * count
    previous_end = None
    total_packets = 0
    for row in rows:
        start = int(row["start_ns"]) - origin
        end = int(row["end_ns"]) - origin
        assert end > start >= 0
        assert previous_end is None or start == previous_end
        previous_end = end
        offered = int(row["packets"])
        if source == "live":
            assert row.get("kernel_drops") not in (None, "")
            offered += int(row["kernel_drops"])
        assert offered >= 0
        total_packets += offered
        for index in range(start // BIN_NS, (end - 1) // BIN_NS + 1):
            overlap = min(end, (index + 1) * BIN_NS) - max(start, index * BIN_NS)
            packets[index] += offered * overlap / (end - start)
            durations[index] += overlap
    assert math.isclose(sum(packets), total_packets, rel_tol=1e-12)
    rates = [n * 1e9 / duration for n, duration in zip(packets, durations)]
    ordered = sorted(rate for rate, duration in zip(rates, durations) if duration == BIN_NS)
    position = (len(ordered) - 1) * .95
    lower, upper = math.floor(position), math.ceil(position)
    p95 = ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    threshold = .5 * p95
    assert threshold > 0
    spans = []
    first = None
    for index in range(count + 1):
        high = index < count and durations[index] == BIN_NS and rates[index] >= threshold
        if high and first is None:
            first = index
        elif not high and first is not None:
            spans.append((first, index))
            first = None
    first, last = max(spans, key=lambda span: span[1] - span[0])
    start_ns, end_ns = (first + 1) * BIN_NS, (last - 1) * BIN_NS
    assert end_ns > start_ns
    return {
        "elapsed_seconds": [start_ns / 1e9, end_ns / 1e9],
        "high_rate_span_before_trimming_seconds": [first * BIN_NS / 1e9, last * BIN_NS / 1e9],
        "bin_seconds": BIN_NS / 1e9,
        "traffic_rate_p95_pps": p95,
        "traffic_threshold_pps": threshold,
        "traffic_bins": [{"start_elapsed_s": i * BIN_NS / 1e9,
                          "duration_s": duration / 1e9, "accounted_pps": rate}
                         for i, (duration, rate) in enumerate(zip(durations, rates))],
    }


def extract(testbed, data_folder, label, source, name, manifest_name):
    directory = REPO / "results" / data_folder / name
    info = json.loads((directory / manifest_name).read_text(encoding="utf-8-sig"))
    assert info["source"] == source, name
    assert info["config"]["block"] is False, name
    rows = read_csv(directory / "windows.csv")
    origin = int(rows[0]["start_ns"])
    phase = select_phase(rows, origin, source)
    phase_start_ns, phase_end_ns = (round(t * 1e9) for t in phase["elapsed_seconds"])
    # Resource samples are taken immediately after evaluation. eval_end_ns
    # is the recorded proxy for that sample's endpoint, on the wall clock.
    selected = [row for row in rows
                if phase_start_ns <= int(row["eval_end_ns"]) - origin < phase_end_ns]
    assert selected, name
    for row in selected:
        assert all(row.get(key) not in (None, "") for key in COUNTERS), name
        assert int(row["cpu_interval_ns"]) > 0, name
        assert all(int(row[key]) >= 0 for key in COUNTERS), name
        assert int(row["host_softirq_ns"]) <= int(row["host_busy_ns"]), name
        assert int(row["host_busy_ns"]) <= int(row["host_total_ns"]), name
        assert int(row["blocked_packets"]) == 0, name
    totals = {key: sum(int(row[key]) for row in selected) for key in COUNTERS}
    wall = totals["cpu_interval_ns"]
    process_ns = totals["user_cpu_ns"] + totals["sys_cpu_ns"]
    residual_ns = totals["host_busy_ns"] - process_ns
    assert residual_ns >= 0, name
    process = process_ns / wall
    rest = residual_ns / wall
    host = totals["host_busy_ns"] / wall
    assert math.isclose(process + rest, host, abs_tol=1e-12), name

    # Independent host monitor: each row is a delta ending at ts_ns;
    # the preceding row supplies its wall-time start. This is a cross-check,
    # not a counter combined with the process data in the bars.
    monitor_cores = relative_difference = None
    monitor_path = directory / "cpu.csv"
    if monitor_path.exists():
        monitor = read_csv(monitor_path)
        pairs = [(prev, row) for prev, row in zip(monitor, monitor[1:])
                 if phase_start_ns <= int(row["ts_ns"]) - origin < phase_end_ns]
        assert pairs, name
        monitor_wall = sum(int(row["ts_ns"]) - int(prev["ts_ns"])
                           for prev, row in pairs)
        assert monitor_wall > 0, name
        monitor_cores = sum(int(row["host_busy_ns"]) for prev, row in pairs) / monitor_wall
        relative_difference = abs(monitor_cores - host) / host
        assert relative_difference < 0.01, (name, relative_difference)
    return {
        "testbed": testbed,
        "testbed_provenance": "User identified the testbeds by data-fabric and data-raspberry directories.",
        "raw_directory": directory.relative_to(REPO).as_posix(),
        "manifest_name": manifest_name,
        "attachment_label": "generic (directory label; actual mode not independently recorded)",
        "implementation": label,
        "run": name,
        "blocking": False,
        "independent_recordings": 1,
        "sample_count": len(selected),
        "origin_ns": origin,
        "phase_start_elapsed_s": phase["elapsed_seconds"][0],
        "phase_end_elapsed_s": phase["elapsed_seconds"][1],
        "phase_selection": phase,
        "first_sample_endpoint_elapsed_s": (int(selected[0]["eval_end_ns"]) - origin) / 1e9,
        "last_sample_endpoint_elapsed_s": (int(selected[-1]["eval_end_ns"]) - origin) / 1e9,
        "measured_interval_seconds": wall / 1e9,
        "detector_process_cores": process,
        "rest_of_host_cores": rest,
        "host_busy_cores": host,
        "softirq_cores_diagnostic_only": totals["host_softirq_ns"] / wall,
        "host_total_counter_per_wall_second": totals["host_total_ns"] / wall,
        "monitor_host_cores_cross_check": monitor_cores,
        "monitor_relative_difference": relative_difference,
        "phase_observed_accounted_pps": sum(int(row["packets"]) +
            (int(row["kernel_drops"]) if source == "live" else 0)
            for row in selected) / (wall / 1e9),
        "counter_totals_ns": totals,
        "version": info["version"],
        "source_sha256": {filename: hashlib.sha256((directory / filename).read_bytes()).hexdigest()
                          for filename in (manifest_name, "windows.csv", "cpu.csv")
                          if (directory / filename).exists()},
    }


def main():
    runs = [extract(*entry) for entry in RUNS]
    evidence = {
        "figure": 10,
        "scope": "FABRIC and Raspberry Pi; one blocking-disabled recording per implementation and testbed.",
        "phase_origin": "First windows.csv start_ns in each recording.",
        "phase_selection": "Longest contiguous span of full 30-second traffic bins at or above half the 95th-percentile bin rate; trim one bin at each edge. Select whole resource intervals by eval_end_ns within the resulting phase.",
        "traffic_rate_definition": "packets + kernel_drops for userspace, packets for kernel; all selected runs have blocking disabled. Counts in windows crossing bin edges are apportioned by overlap duration.",
        "formula_process": "sum(user_cpu_ns + sys_cpu_ns) / sum(cpu_interval_ns)",
        "formula_host": "sum(host_busy_ns) / sum(cpu_interval_ns)",
        "formula_rest": "(sum(host_busy_ns) - sum(user_cpu_ns + sys_cpu_ns)) / sum(cpu_interval_ns)",
        "limitations": [
            "Phases are selected independently from each recording's observed traffic, not reference-clock aligned or a matched offered workload.",
            "Raspberry Pi userspace has a different flood onset/duration and a lower observed traffic rate than kernel. Do not interpret CPU differences as controlled same-load effects.",
            "Endpoint selection includes at most one boundary-straddling sample per recording; each interval is about 0.537 seconds.",
            "eval_end_ns precedes the resource snapshot immediately following evaluation; no exact resource snapshot timestamp is stored.",
            "Rest of host is an accounting residual, including unrelated activity; it is not a direct XDP or network-stack profile.",
            "Do not add host_softirq_ns as another stacked segment: host and task counters use different accounting and do not provide an exclusive softirq partition.",
            "In the userspace recording the softirq diagnostic exceeds the host-minus-process residual; it cannot be equated to that residual.",
            "One recording per implementation and testbed; no confidence intervals or causal claims.",
            "Each testbed's two builds record the same commit, but all record version.modified=true; identical source trees are not established.",
            "The Pi blocking-off recordings lack cpu.csv, but contain contemporaneous host/process counters in windows.csv. Independent host-monitor checks are available only for FABRIC.",
            "Other accuracy/attachment-mode repetitions are not pooled into the selected recordings.",
        ],
        "missing_for_requested_plot": [],
        "runs": runs,
        "matplotlib_version": matplotlib.__version__,
    }
    (OUT / "figure-10-data.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    columns = ["testbed", "implementation", "run", "raw_directory", "sample_count",
               "phase_start_elapsed_s", "phase_end_elapsed_s", "measured_interval_seconds",
               "detector_process_cores", "rest_of_host_cores", "host_busy_cores",
               "phase_observed_accounted_pps"]
    with (OUT / "figure-10-data.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.axisbelow": True,
                         "pdf.fonttype": 42, "ps.fonttype": 42,
                         "savefig.facecolor": "white"})
    fig, axes = plt.subplots(1, 2, figsize=(11.6, 5.8), sharey=True)
    fig.subplots_adjust(left=.085, right=.985, bottom=.18, top=.78, wspace=.12)
    fig.text(.085, .965, "Where CPU time is spent during the flood", fontsize=17, weight="bold", va="top")
    for ax, testbed in zip(axes, ("FABRIC", "Raspberry Pi")):
        cohort = [run for run in runs if run["testbed"] == testbed]
        process = [run["detector_process_cores"] for run in cohort]
        rest = [run["rest_of_host_cores"] for run in cohort]
        ax.bar([0, 1], process, width=.50, color="#2864A0", label="Detector process", zorder=3)
        ax.bar([0, 1], rest, bottom=process, width=.50, color="#E0A34B", label="Rest of host", zorder=3)
        labels = [f'{run["implementation"]}\n{run["phase_start_elapsed_s"]:.0f}–{run["phase_end_elapsed_s"]:.0f} s'
                  for run in cohort]
        ax.set_xticks([0, 1], labels, fontsize=10.5)
        ax.set_xlim(-.55, 1.85)
        ax.set_ylim(0, 1.75)
        ax.set_title(testbed, loc="left", fontsize=13, weight="bold", pad=12)
        ax.yaxis.set_major_locator(MultipleLocator(.25))
        ax.tick_params(axis="both", length=0, pad=9)
        ax.grid(axis="y", color="#DCE1E7", linewidth=.8)
        for i, run in enumerate(cohort):
            ax.text(i, run["host_busy_cores"] + .04, f'{run["host_busy_cores"]:.3f} total',
                    ha="center", va="bottom", fontsize=11, weight="bold", color="#273345")
            ax.text(i, process[i] + rest[i] / 2, f"{rest[i]:.3f}",
                    ha="center", va="center", fontsize=11, color="#302713")
        ax.text(0, process[0] / 2, f"{process[0]:.3f}", ha="center", va="center",
                fontsize=11, color="white", weight="bold")
        ax.annotate(f"{process[1]:.4f} cores\nin process",
                    xy=(1.245, process[1] / 2), xytext=(1.38, .105),
                    fontsize=9, color="#204C78", ha="left", va="center",
                    arrowprops={"arrowstyle": "-", "color": "#2864A0", "lw": 1,
                                "connectionstyle": "angle,angleA=0,angleB=90,rad=3"})
    axes[0].set_ylabel("Mean CPU use (cores)", labelpad=12)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper left", bbox_to_anchor=(.078, .91), frameon=False,
               ncols=2, fontsize=10.5, handlelength=1.4, columnspacing=2)
    for extension in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"figure-10-cpu-breakdown.{extension}", dpi=240)
    plt.close(fig)

    # Retain the traffic evidence used for phase selection as a diagnostic.
    fig, axes = plt.subplots(2, 2, figsize=(11.6, 6), sharex=True, sharey=True, layout="constrained")
    for ax, run in zip(axes.flat, runs):
        phase = run["phase_selection"]
        bins = phase["traffic_bins"]
        ax.step([b["start_elapsed_s"] + b["duration_s"] / 2 for b in bins],
                [b["accounted_pps"] / 1000 for b in bins], where="mid", color="#2864A0", lw=1.3)
        ax.axhline(phase["traffic_threshold_pps"] / 1000, color="#6B7280", ls="--", lw=.8)
        ax.axvspan(*phase["elapsed_seconds"], color="#E0A34B", alpha=.3)
        ax.set_title(f'{run["testbed"]} / {run["implementation"]}', loc="left", fontsize=11)
        ax.grid(alpha=.2)
        ax.set_ylim(bottom=0)
    for ax in axes[-1]:
        ax.set_xlabel("Elapsed time (s)")
    for ax in axes[:, 0]:
        ax.set_ylabel("Accounted rate (kpacket/s)")
    fig.suptitle("Traffic-based phase selection | shading: selected phase; dashed line: threshold", fontsize=12)
    fig.savefig(OUT / "figure-10-phase-selection.png", dpi=180)
    plt.close(fig)
    for run in runs:
        print(f'{run["testbed"]} / {run["implementation"]}: process={run["detector_process_cores"]:.6f}, '
              f'rest={run["rest_of_host_cores"]:.6f}, host={run["host_busy_cores"]:.6f} cores; '
              f'n={run["sample_count"]}; phase={run["phase_selection"]["elapsed_seconds"]}')


if __name__ == "__main__":
    main()
