"""Rebuild the FABRIC versions of Figures 8--11 from existing recordings.

Uses the same helper calculations and colors as the preceding figures.
The attached result3.tex supplies the figure inventory, not edit instructions.
"""

import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, PercentFormatter

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
DATA = REPO / "results" / "data-fabric"
RUNS = (("Userspace", "live", "usr-acc-gen-1"), ("Kernel", "xdp", "ker-acc-gen-1"))
SEGMENTS = (
    ("counted_in_windows", "Successfully received", "#2864A0"),
    ("interface_drops", "NIC drops", "#E0A34B"),
    ("socket_drops", "Socket drops", "#C76552"),
    ("late_drops", "Late drops", "#8069A6"),
    ("unaccounted", "Unaccounted", "#717A85"),
)


def helper(folder, module_name):
    path = OUT.parent / folder / "build_figure.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def write_csv(name, rows):
    with (OUT / name).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def save_figure(fig, name):
    for ext in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"{name}.{ext}", dpi=300)
    plt.close(fig)


def style():
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "axes.spines.bottom": True,
            "axes.axisbelow": True,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.facecolor": "white",
        }
    )


def accounting():
    runs = []
    for label, source, name in RUNS:
        directory = DATA / name
        manifest = json.loads((directory / "run.json").read_text(encoding="utf-8-sig"))
        assert manifest["source"] == source and manifest["config"]["block"] is False
        rows = read_csv(directory / "windows.csv")
        assert all(int(row["blocked_packets"]) == 0 for row in rows)
        stats = manifest["stats"]
        assert stats["blocked_packets"] == 0 and len(rows) == stats["windows"]["closed"]
        nic = manifest["live"]["nic_delta"]
        for key in (
            "dev.rx_packets",
            "dev.rx_drop",
            "ethtool.rx_packets",
            "ethtool.rx_out_of_buffer",
        ):
            assert (
                nic[key]
                == manifest["live"]["nic_end"][key] - manifest["live"]["nic_start"][key]
            )
        assert nic["ethtool.rx_packets"] == nic["dev.rx_packets"]
        assert nic["ethtool.rx_out_of_buffer"] == nic["dev.rx_drop"]
        counted = sum(int(row["packets"]) for row in rows)
        if source == "live":
            socket = manifest["live"]["socket"]["kernel_dropped"]
            late = stats["windows"]["late_packets"]
            assert socket == sum(int(row["kernel_drops"]) for row in rows)
            assert late == sum(int(row["late"]) for row in rows)
            assert (
                counted + late + stats["dropped_last_window"]["packets"]
                == stats["packets"]
            )
            assert (
                stats["packets"] + stats["skipped_frames"] + socket
                == nic["dev.rx_packets"]
            )
            assert manifest["live"]["socket"]["kernel_total"] == nic["dev.rx_packets"]
            status = {"socket_drops": "measured", "late_drops": "measured"}
        else:
            assert (
                "socket" not in manifest["live"]
                and "late_packets" not in stats["windows"]
            )
            assert counted == stats["packets"]
            socket = late = 0
            status = {"socket_drops": "not applicable", "late_drops": "not applicable"}
        denominator = nic["dev.rx_packets"] + nic["dev.rx_drop"]
        counts = {
            "counted_in_windows": counted,
            "interface_drops": nic["dev.rx_drop"],
            "socket_drops": socket,
            "late_drops": late,
        }
        counts["unaccounted"] = denominator - sum(counts.values())
        assert all(value >= 0 for value in counts.values())
        assert sum(counts.values()) == denominator
        shares = {key: value * 100 / denominator for key, value in counts.items()}
        assert math.isclose(sum(shares.values()), 100, abs_tol=1e-10)
        runs.append(
            {
                "implementation": label,
                "run": name,
                "counts": counts,
                "shares_percent": shares,
                "denominator_driver_counter_sum": denominator,
                "applicability": status,
                "version": manifest["version"],
                "duration_s": stats["wall_seconds"],
                "duplicate_interface_drop_observation": "dev.rx_drop == ethtool.rx_out_of_buffer; counted once",
                "independent_hardware_packet_total": None,
                "hardware_note": "rx_packets_phy is zero; ethtool.rx_packets repeats the driver received count, not an independently measured arrival denominator.",
                "final_partial_window": stats["dropped_last_window"],
                "source_sha256": {
                    p.relative_to(REPO)
                    .as_posix(): hashlib.sha256(p.read_bytes())
                    .hexdigest()
                    for p in (directory / "run.json", directory / "windows.csv")
                },
            }
        )
    write_json(
        "figure-09-evidence.json",
        {
            "figure": 9,
            "testbed": "FABRIC VM",
            "denominator": "Whole-run delta dev.rx_packets + delta dev.rx_drop; interface-counter estimate, not verified wire arrivals.",
            "runs": runs,
            "limitations": [
                "The interface-drop driver observation is included once, despite matching ethtool and procfs observations.",
                "Independent physical arrival counters are unavailable; the denominator is an explicit estimate.",
                "Unaccounted includes non-IP/background/boundary differences; it is not automatically packet loss. The userspace residual equals 405 parser-skipped frames.",
                "Kernel socket and userspace late-rejection categories are inapplicable, not imputed missing measurements.",
                "Different commits and modified source trees limit causal comparisons. Whole-recording counters are not aligned high-rate measurements.",
            ],
        },
    )
    table = []
    for run in runs:
        row = {
            "implementation": run["implementation"],
            "run": run["run"],
            "denominator_driver_counter_sum": run["denominator_driver_counter_sum"],
        }
        for key, label, color in SEGMENTS:
            row[key + "_packets"] = run["counts"][key]
            row[key + "_percent"] = run["shares_percent"][key]
        row.update(
            {key + "_status": value for key, value in run["applicability"].items()}
        )
        table.append(row)
    write_csv("figure-09-data.csv", table)

    style()
    fig, (full, detail) = plt.subplots(
        1, 2, figsize=(11, 4.8), gridspec_kw={"width_ratios": [1, 1.2]}
    )
    fig.subplots_adjust(left=0.09, right=0.985, top=0.68, bottom=0.11, wspace=0.30)
    fig.text(
        0.09,
        0.965,
        "Packet accounting on FABRIC VM",
        fontsize=16,
        weight="bold",
        va="top",
    )
    for ax in (full, detail):
        ax.set_xticks([0, 1], ["Userspace", "Kernel"])
        ax.set_xlim(-0.65, 1.65)
        ax.tick_params(axis="both", length=0, pad=9)
        ax.grid(axis="y", color="#DCE1E7", linewidth=0.8)
        ax.yaxis.set_major_formatter(
            PercentFormatter(100, decimals=2 if ax is detail else 0)
        )
    full.set_title(
        "Packets successfully received",
        loc="center",
        fontsize=12,
        weight="bold",
        pad=13,
    )
    full.set_ylim(0, 105)
    full.yaxis.set_major_locator(MultipleLocator(20))
    full.set_ylabel("Packet distribution (%)", labelpad=12)
    detail.set_title(
        "Packets dropped (magnified)", loc="center", fontsize=12, weight="bold", pad=13
    )
    detail.set_ylim(0, 0.16)
    detail.yaxis.set_major_locator(MultipleLocator(0.05))
    bottom_full, bottom_detail = [0.0, 0.0], [0.0, 0.0]
    for key, label, color in SEGMENTS:
        values = [run["shares_percent"][key] for run in runs]
        full.bar(
            [0, 1],
            values,
            width=0.48,
            bottom=bottom_full,
            color=color,
            label=label,
            zorder=3,
        )
        if key != "counted_in_windows":
            detail.bar(
                [0, 1], values, width=0.48, bottom=bottom_detail, color=color, zorder=3
            )
            if key == "socket_drops":
                detail.text(
                    0,
                    bottom_detail[0] + values[0] / 2,
                    f"{values[0]:.5f}%\nsocket drops",
                    color="white",
                    weight="bold",
                    ha="center",
                    va="center",
                    fontsize=9,
                )
            bottom_detail = [a + b for a, b in zip(bottom_detail, values)]
        bottom_full = [a + b for a, b in zip(bottom_full, values)]
    for i, run in enumerate(runs):
        full.text(
            i,
            50,
            f'{run["shares_percent"]["counted_in_windows"]:.4f}%\ncounted',
            ha="center",
            va="center",
            color="white",
            weight="bold",
            fontsize=9,
        )
        total = 100 - run["shares_percent"]["counted_in_windows"]
        detail.text(
            i,
            total + 0.004,
            f"{total:.5f}%",
            ha="center",
            va="bottom",
            fontsize=10,
            weight="bold",
        )
    handles, labels = full.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.082, 0.89),
        ncols=3,
        frameon=False,
        fontsize=10,
        handlelength=1.4,
        columnspacing=2,
    )
    save_figure(fig, "figure-09-packet-accounting")
    return runs


def cpu():
    module = helper("figure-10-cpu-breakdown", "fabric_cpu_helper")
    runs = [
        module.extract("FABRIC VM", "data-fabric", label, source, name, "run.json")
        for label, source, name in RUNS
    ]
    write_json(
        "figure-10-data.json",
        {
            "figure": 10,
            "testbed": "FABRIC VM",
            "runs": runs,
            "phase_selection": "Longest continuous span of full 30-second traffic bins at or above half the run's 95th-percentile rate; trim one bin at each edge.",
            "formula_process": "sum(user_cpu_ns + sys_cpu_ns) / sum(cpu_interval_ns)",
            "formula_host": "sum(host_busy_ns) / sum(cpu_interval_ns)",
            "formula_rest": "host cores - detector-process cores, over the same sample intervals",
            "limitations": [
                "Uses the same blocking-off accuracy cohort as Figures 9 and 11, rather than the earlier standalone resource cohort (*-per-gen-3).",
                "Rest of host is an accounting residual including unrelated work, not direct XDP profiling.",
                "No cpu.csv is present in these accuracy runs; the contemporaneous windows.csv process/host counters suffice.",
                "The two runs have different commits and modified source trees; the comparison is descriptive.",
                "Local phase selection does not validate trace alignment or equal offered traffic.",
            ],
        },
    )
    columns = (
        "implementation",
        "run",
        "sample_count",
        "phase_start_elapsed_s",
        "phase_end_elapsed_s",
        "measured_interval_seconds",
        "detector_process_cores",
        "rest_of_host_cores",
        "host_busy_cores",
        "phase_observed_accounted_pps",
    )
    write_csv(
        "figure-10-data.csv", [{key: run[key] for key in columns} for run in runs]
    )
    style()
    fig, ax = plt.subplots(figsize=(7.8, 4.9))
    fig.subplots_adjust(left=0.13, right=0.98, bottom=0.17, top=0.81)
    fig.text(
        0.13,
        0.95,
        "Where CPU time is spent during the flood",
        fontsize=15,
        weight="bold",
        va="top",
    )
    process = [run["detector_process_cores"] for run in runs]
    rest = [run["rest_of_host_cores"] for run in runs]
    ax.bar(
        [0, 1], process, width=0.48, color="#2864A0", label="Detector process", zorder=3
    )
    ax.bar(
        [0, 1],
        rest,
        bottom=process,
        width=0.48,
        color="#E0A34B",
        label="Rest of host",
        zorder=3,
    )
    ax.set_xticks([0, 1], ["Userspace", "Kernel"])
    ax.set_xlim(-0.6, 1.85)
    ax.set_ylim(0, 0.85)
    ax.set_ylabel("Mean CPU use (cores)", labelpad=12)
    ax.yaxis.set_major_locator(MultipleLocator(0.2))
    ax.tick_params(axis="both", length=0, pad=9)
    ax.grid(axis="y", color="#DCE1E7", linewidth=0.8)
    ax.legend(
        loc="lower left",
        bbox_to_anchor=(-0.015, 1.005),
        frameon=False,
        ncols=2,
        fontsize=10,
        handlelength=1.4,
        columnspacing=2,
    )
    for i, run in enumerate(runs):
        ax.text(
            i,
            run["host_busy_cores"] + 0.023,
            f'{run["host_busy_cores"]:.3f} total',
            ha="center",
            va="bottom",
            fontsize=11,
            weight="bold",
            color="#273345",
        )
        ax.text(
            i,
            process[i] + rest[i] / 2,
            f"{rest[i]:.3f}",
            ha="center",
            va="center",
            fontsize=11,
            color="#302713",
        )
    ax.text(
        0,
        process[0] / 2,
        f"{process[0]:.3f}",
        ha="center",
        va="center",
        fontsize=11,
        color="white",
        weight="bold",
    )
    ax.annotate(
        f"{process[1]:.4f} cores\nin detector process",
        xy=(1.23, process[1] / 2),
        xytext=(1.40, 0.055),
        fontsize=9.5,
        color="#204C78",
        ha="left",
        va="center",
        arrowprops={
            "arrowstyle": "-",
            "color": "#2864A0",
            "lw": 1,
            "connectionstyle": "angle,angleA=0,angleB=90,rad=3",
        },
    )
    save_figure(fig, "figure-10-cpu-breakdown")
    return runs


def main():
    workload = helper("figure-08-traffic-profile", "fabric_workload_helper")
    workload.OUT = OUT
    workload.main()
    packet_runs = accounting()
    cpu_runs = cpu()
    classification = helper("figure-11-window-classification", "fabric_outcome_helper")
    classification.DATA = DATA
    classification.OUT = OUT
    classification.TESTBED = "FABRIC VM"
    classification.RUNS = (
        ("Userspace", "usr", "run.json"),
        ("Kernel", "ker", "run.json"),
    )
    classification.main()
    for number, name in (
        (8, "traffic-profile"),
        (9, "packet-accounting"),
        (10, "cpu-breakdown"),
        (11, "window-classification"),
    ):
        for ext in ("png", "pdf", "svg"):
            assert (OUT / f"figure-{number:02d}-{name}.{ext}").stat().st_size > 1000
    summary = {
        "testbed": "FABRIC VM",
        "blocking": False,
        "comparison_runs": [run[2] for run in RUNS],
        "common_excerpt": "Figure 8 is a shared trace profile, not a separate live FABRIC recording.",
        "packet_accounting": [
            {
                "implementation": r["implementation"],
                "counts": r["counts"],
                "denominator": r["denominator_driver_counter_sum"],
            }
            for r in packet_runs
        ],
        "cpu": [
            {
                key: r[key]
                for key in (
                    "implementation",
                    "detector_process_cores",
                    "rest_of_host_cores",
                    "host_busy_cores",
                )
            }
            for r in cpu_runs
        ],
        "source_document": "C:/Users/jedre/Downloads/result3.tex (read as a figure reference; not edited)",
    }
    write_json("fabric-figure-manifest.json", summary)
    archive = OUT.parent / "fabric-plots.zip"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as bundle:
        for path in sorted(OUT.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                bundle.write(path, path.relative_to(OUT.parent))
    print(json.dumps(summary))
    print("Bundle:", archive)


if __name__ == "__main__":
    main()
