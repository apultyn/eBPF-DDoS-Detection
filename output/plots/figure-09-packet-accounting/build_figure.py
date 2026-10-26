"""Build provisional Pi packet-accounting bars and retain counter discrepancies.

The denominator is defined as dev.rx_packets + dev.rx_drop. It is not a
validated physical-wire total; the hardware totals do not reconcile with it.
"""

import csv
import hashlib
import json
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator, PercentFormatter

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
DATA = REPO / "results" / "data-raspberry"
RUNS = (
    ("Userspace", "live", "usr-acc-gen-1", "run.json"),
    ("Kernel", "xdp", "ker-acc-gen-1", "run_kernelspace.json"),
)
SEGMENTS = (
    ("counted_in_windows", "Successfully received", "#2864A0"),
    ("interface_drops", "NIC drops", "#E0A34B"),
    ("socket_drops", "Socket drops", "#C76552"),
    ("late_drops", "Late drops", "#8069A6"),
    ("unaccounted", "Unaccounted", "#717A85"),
)
DOCS = "https://www.kernel.org/doc/html/latest/networking/statistics.html"


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def extract(implementation, source, name, manifest_name):
    directory = DATA / name
    manifest_path = directory / manifest_name
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    assert manifest["source"] == source
    assert manifest["config"]["block"] is False
    assert manifest["stats"]["blocked_packets"] == 0
    rows = read_csv(directory / "windows.csv")
    assert all(int(row["blocked_packets"]) == 0 for row in rows)
    assert len(rows) == manifest["stats"]["windows"]["closed"]
    nic = manifest["live"]["nic_delta"]
    snapshot_keys = (
        "dev.rx_packets",
        "dev.rx_drop",
        "ethtool.rx_good_pkts",
        "ethtool.rx_pkts",
    )
    for key in snapshot_keys:
        assert (
            nic[key]
            == manifest["live"]["nic_end"][key] - manifest["live"]["nic_start"][key]
        )
    counted = sum(int(row["packets"]) for row in rows)
    received = nic["dev.rx_packets"]
    interface = nic["dev.rx_drop"]
    denominator = received + interface
    assert denominator > 0
    stats = manifest["stats"]
    if source == "live":
        socket = manifest["live"]["socket"]["kernel_dropped"]
        late = stats["windows"]["late_packets"]
        assert socket == sum(int(row["kernel_drops"]) for row in rows)
        assert late == sum(int(row["late"]) for row in rows)
        assert (
            counted + late + stats["dropped_last_window"]["packets"] == stats["packets"]
        )
        assert manifest["live"]["socket"]["kernel_total"] == received
        assert stats["packets"] + stats["skipped_frames"] + socket == received
        applicability = {"socket_drops": "measured", "late_drops": "measured"}
    else:
        # Structural zero for these two user-space capture stages, not an
        # imputation for a missing measurement. Other XDP/window losses stay
        # in the residual, including unknown counts in discarded windows.
        assert "socket" not in manifest["live"]
        assert "late_packets" not in stats["windows"]
        assert counted == stats["packets"]
        socket = late = 0
        applicability = {
            "socket_drops": "not applicable: no AF_PACKET capture socket",
            "late_drops": "not applicable: no userspace timestamp-to-window late rejection",
        }
    counts = {
        "counted_in_windows": counted,
        "interface_drops": interface,
        "socket_drops": socket,
        "late_drops": late,
    }
    counts["unaccounted"] = denominator - sum(counts.values())
    assert all(value >= 0 for value in counts.values())
    assert sum(counts.values()) == denominator
    shares = {key: value * 100 / denominator for key, value in counts.items()}
    assert math.isclose(sum(shares.values()), 100, abs_tol=1e-10)
    hardware = nic["ethtool.rx_good_pkts"]
    assert hardware == nic["ethtool.rx_pkts"]
    hardware_residual = hardware - sum(
        value for key, value in counts.items() if key != "unaccounted"
    )
    assert hardware_residual < 0  # Preserve this discrepancy; never clip it.
    return {
        "implementation": implementation,
        "testbed": "Raspberry Pi 400",
        "run": name,
        "raw_directory": directory.relative_to(REPO).as_posix(),
        "manifest_name": manifest_name,
        "blocking": False,
        "population": "Whole recording; one recording per implementation, not a matched traffic phase.",
        "started_at": manifest["started_at"],
        "finished_at": manifest["finished_at"],
        "window_count": len(rows),
        "duration_s": stats["wall_seconds"],
        "dev_rx_packets": received,
        "dev_rx_drop": interface,
        "denominator_driver_counter_sum": denominator,
        "counts": counts,
        "shares_percent": shares,
        "applicability": applicability,
        "hardware_good_packets": hardware,
        "hardware_residual_packets_if_used_as_denominator": hardware_residual,
        "hardware_residual_percent_if_used_as_denominator": hardware_residual
        * 100
        / hardware,
        "driver_sum_minus_hardware_packets": denominator - hardware,
        "driver_sum_excess_percent_of_hardware": (denominator - hardware)
        * 100
        / hardware,
        "skipped_frames": stats.get("skipped_frames"),
        "final_partial_window": stats["dropped_last_window"],
        "discarded_windows": stats["windows"].get("discarded"),
        "nic_warnings": manifest["live"].get("nic_warnings", []),
        "version": manifest["version"],
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (manifest_path, directory / "windows.csv")
        },
    }


def main():
    runs = [extract(*spec) for spec in RUNS]
    evidence = {
        "figure": 9,
        "status": "Provisional driver-counter accounting, not validated physical-interface arrival shares.",
        "denominator": "delta /proc/net/dev rx_packets + delta /proc/net/dev rx_drop",
        "unaccounted_formula": "denominator - counted_in_windows - interface_drops - socket_drops - late_drops",
        "counter_reference": DOCS,
        "limitations": [
            "Linux rx_packets may include packets dropped during host processing, and procfs combines dropped and missed counters. A physical-arrival sum requires driver-specific disjointness verification.",
            "The hardware rx_good_pkts/rx_pkts totals are smaller than the driver receive-plus-drop sum; using hardware totals with the requested components produces negative residuals.",
            "Bars are normalized only to the explicitly defined driver-counter sum. No hardware residual is clipped, and components are not renormalized to hardware totals.",
            "Do not add dev.rx_errs or ethtool.rx_errors: they overlap the reported driver drops in these recordings.",
            "The userspace residual is 389 parser-skipped frames, so unaccounted does not mean unexplained loss. Kernel residual is 630 packets, including possible non-IP/background, startup/partial-window or other counter differences.",
            "Kernel socket and userspace late-rejection stages are structurally inapplicable, not measured zero-loss equivalents. Other window discards remain unclassified in the residual.",
            "Whole-recording network counters cannot be restricted to a high-rate phase without interval snapshots. This chart uses whole recordings.",
            "All builds record modified source trees; these single-run descriptive observations do not establish controlled causal effects.",
        ],
        "needed_to_validate_original_seen_by_interface_caption": [
            "Actual kernel and NIC driver identity/version for the Pi runs (uname -a and ethtool -i eth0, or saved equivalents).",
            "Driver-specific definitions establishing which receive/drop/error counters count disjoint packet sets and why hardware packet totals disagree.",
            "Time-matched before/after netlink or sysfs snapshots separating rx_dropped and rx_missed_errors, together with hardware packet snapshots over the same interval; a rerun is needed if equivalent records do not exist.",
        ],
        "runs": runs,
    }
    (OUT / "figure-09-evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    table = []
    for run in runs:
        row = {
            "implementation": run["implementation"],
            "run": run["run"],
            "denominator_driver_counter_sum": run["denominator_driver_counter_sum"],
            "hardware_good_packets": run["hardware_good_packets"],
            "hardware_residual_packets": run[
                "hardware_residual_packets_if_used_as_denominator"
            ],
        }
        for key, label, color in SEGMENTS:
            row[key + "_packets"] = run["counts"][key]
            row[key + "_percent"] = run["shares_percent"][key]
        row.update(
            {key + "_status": value for key, value in run["applicability"].items()}
        )
        table.append(row)
    with (OUT / "figure-09-data.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(table[0]))
        writer.writeheader()
        writer.writerows(table)

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.spines.left": False,
            "axes.axisbelow": True,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "savefig.facecolor": "white",
        }
    )
    fig, ax = plt.subplots(figsize=(9.5, 4.8))
    fig.subplots_adjust(left=0.11, right=0.985, top=0.75, bottom=0.14)
    fig.text(
        0.11,
        0.97,
        "Packet accounting on Raspberry Pi 400",
        fontsize=16,
        weight="bold",
        va="top",
    )
    bottoms = [0.0, 0.0]
    for key, label, color in SEGMENTS:
        values = [run["shares_percent"][key] for run in runs]
        ax.bar(
            [0, 1],
            values,
            width=0.48,
            bottom=bottoms,
            color=color,
            label=label,
            zorder=3,
        )
        for i, value in enumerate(values):
            if value >= 3:
                ax.text(
                    i,
                    bottoms[i] + value / 2,
                    f"{value:.2f}%",
                    ha="center",
                    va="center",
                    fontsize=11,
                    weight="bold",
                    color="#302713" if key == "interface_drops" else "white",
                )
            bottoms[i] += value
    for i, run in enumerate(runs):
        ax.annotate(
            f'Unaccounted: {run["counts"]["unaccounted"]:,}\n'
            f'{run["shares_percent"]["unaccounted"]:.5f}%',
            xy=(i + 0.23, 100),
            xytext=(i + 0.36, 109),
            ha="left",
            va="center",
            fontsize=9,
            color="#495464",
            arrowprops={
                "arrowstyle": "-",
                "color": "#717A85",
                "lw": 0.9,
                "connectionstyle": "angle,angleA=0,angleB=90,rad=3",
            },
        )
    ax.set_xticks(
        [0, 1],
        [
            f'{run["implementation"]}\nN = {run["denominator_driver_counter_sum"]:,}'
            for run in runs
        ],
    )
    ax.set_xlim(-0.55, 1.95)
    ax.set_ylim(0, 116)
    ax.set_ylabel("Packet distribution (%)", labelpad=12)
    ax.yaxis.set_major_locator(MultipleLocator(20))
    ax.yaxis.set_major_formatter(PercentFormatter(100, decimals=0))
    ax.grid(axis="y", color="#DCE1E7", linewidth=0.8)
    ax.tick_params(axis="both", length=0, pad=9)
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(
        handles,
        labels,
        loc="upper left",
        bbox_to_anchor=(0.10, 0.90),
        frameon=False,
        ncols=3,
        fontsize=10,
        handlelength=1.4,
        columnspacing=2,
    )
    for extension in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"figure-09-packet-accounting.{extension}", dpi=240)
    plt.close(fig)
    for run in runs:
        print(
            json.dumps(
                {
                    "implementation": run["implementation"],
                    "denominator": run["denominator_driver_counter_sum"],
                    "counts": run["counts"],
                    "percent": run["shares_percent"],
                    "hardware_residual": run[
                        "hardware_residual_packets_if_used_as_denominator"
                    ],
                }
            )
        )


if __name__ == "__main__":
    main()
