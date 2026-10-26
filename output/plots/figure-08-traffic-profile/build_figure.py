"""Rebuild Figure 8 from saved PCAP reference counts and adjusted label truth.

Raw PCAP and corrected flow-label files remain on the experiment machines.
This script reads their existing derived outputs without changing them.
"""

import csv
from datetime import datetime, timedelta, timezone
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
DATA = REPO / "results" / "data-fabric"
REFERENCE = DATA / "ref-pcap"
GROUND_TRUTH = DATA / "eval-usr-acc-gen-1-adjusted"
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def parse_ns(text):
    whole, fraction = text.removesuffix("Z").split(".")
    delta = datetime.fromisoformat(whole).replace(tzinfo=timezone.utc) - EPOCH
    return (delta.days * 86400 + delta.seconds) * 10**9 + int(fraction.ljust(9, "0"))


def format_ns(value):
    seconds, nanos = divmod(value, 10**9)
    return (EPOCH + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S") + f".{nanos:09d}Z"


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    manifest = json.loads((REFERENCE / "run.json").read_text(encoding="utf-8-sig"))
    metrics = json.loads((GROUND_TRUTH / "metrics.json").read_text(encoding="utf-8-sig"))
    assert manifest["source"] == "pcap"
    assert manifest["config"]["block"] is False
    excerpt = metrics["run"]["excerpt"]
    trace_start = parse_ns(excerpt["trace_start"])
    trace_end = parse_ns(excerpt["trace_end"])
    assert trace_end > trace_start
    assert excerpt["packets_ip"] == manifest["stats"]["packets"]
    assert Path(excerpt["file"]).name == Path(manifest["inputs"][0]["path"]).name
    assert Path(metrics["run"]["reference"]).name == REFERENCE.name

    reference = read_csv(REFERENCE / "windows.csv")
    rates = []
    previous_end = None
    for row in reference:
        start, end = int(row["start_ns"]), int(row["end_ns"])
        assert end > start
        assert previous_end is None or previous_end == start
        assert int(row["skipped_before"]) == 0
        assert int(row["blocked_packets"]) == 0
        assert int(row["late"]) == 0
        previous_end = end
        packets = int(row["packets"])
        assert packets >= 0
        rates.append({
            "start_ns": start, "end_ns": end,
            "start_utc": format_ns(start), "end_utc": format_ns(end),
            "start_elapsed_s": (start - trace_start) / 1e9,
            "end_elapsed_s": (end - trace_start) / 1e9,
            "packets_ip": packets,
            "packet_rate_pps": packets * 1e9 / (end - start),
        })
    widths = {row["end_ns"] - row["start_ns"] for row in rates}
    assert len(widths) == 1
    width = widths.pop()
    partial = manifest["stats"]["dropped_last_window"]
    assert sum(row["packets_ip"] for row in rates) + partial["packets"] == manifest["stats"]["packets"]
    assert rates[0]["start_ns"] <= trace_start < rates[0]["end_ns"]
    assert rates[-1]["end_ns"] == parse_ns(partial["start"])
    assert 0 <= trace_end - rates[-1]["end_ns"] < width

    # Use the saved truth field, not predictions, packet-rate thresholds, or
    # a reconstructed single attack interval from aggregate latency summaries.
    # Its current-window bins and two-window overlap semantics are retained.
    labels = read_csv(GROUND_TRUTH / "windows.csv")
    assert len(labels) == metrics["counts"]["windows_total"]
    raw_name = Path(metrics["run"]["run_dir"]).name
    raw = read_csv(DATA / raw_name / "windows.csv")
    assert len(raw) == len(labels)
    offset = metrics["counts"]["offset_ns"]
    truth = []
    for row, original in zip(labels, raw):
        start, end = int(row["start_ns"]), int(row["end_ns"])
        assert row["epoch"] == original["epoch"]
        assert int(original["start_ns"]) - offset == start
        assert int(original["end_ns"]) - offset == end
        assert row["packets"] == original["packets"]
        assert row["truth"] in ("True", "False")
        assert (row["truth"] == "True") == bool(row["attack_labels"])
        assert end - start == width
        assert int(row["span_end_ns"]) == end
        assert int(row["span_end_ns"]) - int(row["span_start_ns"]) == metrics["counts"]["span_ns"]
        if end <= trace_start or start >= trace_end:
            continue
        clipped_start, clipped_end = max(start, trace_start), min(end, trace_end)
        truth.append({
            "start_ns": start, "end_ns": end,
            "span_start_ns": int(row["span_start_ns"]),
            "span_end_ns": int(row["span_end_ns"]),
            "plot_start_ns": clipped_start, "plot_end_ns": clipped_end,
            "plot_start_elapsed_s": (clipped_start - trace_start) / 1e9,
            "plot_end_elapsed_s": (clipped_end - trace_start) / 1e9,
            "truth_attack": row["truth"],
            "attack_labels": row["attack_labels"],
        })
    assert truth[0]["plot_start_ns"] == trace_start
    assert truth[-1]["plot_end_ns"] == trace_end
    assert all(a["plot_end_ns"] == b["plot_start_ns"] for a, b in zip(truth, truth[1:]))
    groups = []
    for row in truth:
        state = row["truth_attack"] == "True"
        label = row["attack_labels"] or "BENIGN"
        if groups and groups[-1]["attack"] == state and groups[-1]["label"] == label:
            groups[-1]["end_ns"] = row["plot_end_ns"]
        else:
            groups.append({"start_ns": row["plot_start_ns"], "end_ns": row["plot_end_ns"],
                           "attack": state, "label": label})

    write_csv(OUT / "figure-08-packet-rate.csv", rates)
    write_csv(OUT / "figure-08-ground-truth.csv", truth)
    paths = [REFERENCE / "run.json", REFERENCE / "windows.csv",
             GROUND_TRUTH / "metrics.json", GROUND_TRUTH / "windows.csv"]
    evidence = {
        "figure": 8,
        "source_mode": "Saved PCAP-derived reference and saved adjusted-label evaluation; original files remain on remote experiment machines.",
        "trace_start_utc": excerpt["trace_start"], "trace_end_utc": excerpt["trace_end"],
        "trace_duration_s": (trace_end - trace_start) / 1e9,
        "reference": str(REFERENCE.relative_to(REPO)),
        "reference_window_ns": width,
        "reference_windows": len(rates),
        "plotted_packets_ip": sum(row["packets_ip"] for row in rates),
        "manifest_packets_ip": manifest["stats"]["packets"],
        "pcap_frames_skipped_by_ip_parser": manifest["stats"]["skipped_frames"],
        "last_partial_window_omitted": partial,
        "tail_omitted_seconds": (trace_end - rates[-1]["end_ns"]) / 1e9,
        "peak_packet_rate_pps": max(row["packet_rate_pps"] for row in rates),
        "rate_formula": "packets / ((end_ns - start_ns) / 1e9); no smoothing, replay-speed scaling, or live-run rates.",
        "ground_truth_source": str(GROUND_TRUTH.relative_to(REPO)),
        "ground_truth_column": "truth, with attack_labels; all rows in the excerpt, without scoring exclusions.",
        "ground_truth_window_ns": width,
        "ground_truth_effective_span_ns": metrics["counts"]["span_ns"],
        "ground_truth_mode": metrics["counts"]["mode"],
        "ground_truth_windows": len(truth),
        "ground_truth_groups": groups,
        "source_sha256": {str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in paths},
        "limitations": [
            "The PCAP and original corrected flow labels were not independently reread; this figure uses their saved derived outputs.",
            "IP packet counts exclude frames skipped by the detector parser; this is not an all-Ethernet-frame rate.",
            "The final 204-packet partial reference window is omitted from the rate curve; its unplotted tail is about 0.0313 seconds.",
            "The first complete epoch bin begins just before the first excerpt packet; the plot clips it at trace start and retains its full-bin rate denominator.",
            "The truth strip preserves the saved evaluation's own trace-time window grid and combined two-window overlap rule; it is not recomputed on the PCAP reference grid.",
            "Warm-up and scoring exclusions do not mask ground truth, because this is a trace-label profile rather than a detector-score plot.",
            "Existing live alignment warnings are not repaired by this figure; no live prediction or received-traffic comparison is plotted.",
            "Saved ground truth records adjusted labels but contains no hash of the original corrected flow-label file.",
        ],
        "needed_for_independent_rebuild": [
            "Excerpt PCAP (01-12.pcap) or a fresh trace-time packet-count export with explicit window edges and packet inclusion rules.",
            "Corrected flow labels with start/end trace timestamps, attack type, benign/attack indicator, and the timestamp correction/UTC conversion metadata; alternatively fresh window-level truth on the reference grid with its overlap rule.",
            "Excerpt metadata and source hashes tying the exports to the replayed input.",
        ],
    }
    (OUT / "figure-08-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.axisbelow": True,
                         "pdf.fonttype": 42, "ps.fonttype": 42,
                         "savefig.facecolor": "white"})
    fig, (ax, strip) = plt.subplots(2, 1, figsize=(11, 5), sharex=True,
                                   gridspec_kw={"height_ratios": [4, .65]})
    fig.subplots_adjust(left=.12, right=.985, top=.86, bottom=.15, hspace=.20)
    fig.text(.12, .96, "Traffic profile of the replayed excerpt", fontsize=16, weight="bold", va="top")
    edges = [(row["start_ns"] - trace_start) / 60e9 for row in rates]
    edges.append((rates[-1]["end_ns"] - trace_start) / 60e9)
    y = [row["packet_rate_pps"] / 1000 for row in rates]
    ax.stairs(y, edges, fill=True, color="#2864A0", alpha=.13, linewidth=0)
    ax.stairs(y, edges, color="#2864A0", linewidth=.85)
    ax.set_ylabel("IP packet rate\n(kpacket/s)", labelpad=12)
    ax.set_ylim(0, 265)
    ax.yaxis.set_major_locator(MultipleLocator(50))
    ax.grid(axis="y", color="#DCE1E7", linewidth=.8)
    ax.spines["bottom"].set_visible(False)
    ax.tick_params(axis="both", length=0, pad=8, labelbottom=False)
    for group in groups:
        start = (group["start_ns"] - trace_start) / 60e9
        end = (group["end_ns"] - trace_start) / 60e9
        color = "#C47740" if group["attack"] else "#D6E3EF"
        strip.broken_barh([(start, end - start)], (.12, .76), facecolors=color)
        if end - start > 2:
            text = "Attack: " + group["label"] if group["attack"] else "Benign"
            strip.text((start + end) / 2, .5, text, ha="center", va="center",
                       color="white" if group["attack"] else "#273345", fontsize=10, weight="bold")
    strip.set_yticks([])
    strip.set_ylim(0, 1)
    strip.set_ylabel("Ground\ntruth", rotation=0, ha="right", va="center", labelpad=12, fontsize=10)
    strip.spines["bottom"].set_visible(False)
    strip.set_xlabel("Elapsed trace time (min)", labelpad=10)
    strip.set_xlim(0, (trace_end - trace_start) / 60e9)
    # The excerpt is 0.153 seconds shorter than 40 minutes; retain a readable
    # 40-minute tick at the rounded display boundary without altering data.
    strip.set_xlim(0, math.ceil((trace_end - trace_start) / 60e9))
    strip.xaxis.set_major_locator(MultipleLocator(5))
    strip.tick_params(axis="x", length=0, pad=7)
    for extension in ("png", "pdf", "svg"):
        fig.savefig(OUT / f"figure-08-traffic-profile.{extension}", dpi=240)
    plt.close(fig)
    print(json.dumps({"rate_windows": len(rates), "truth_windows": len(truth),
                      "plotted_ip_packets": evidence["plotted_packets_ip"],
                      "peak_pps": evidence["peak_packet_rate_pps"],
                      "truth_groups_elapsed_s": [
                          [(g["start_ns"] - trace_start) / 1e9,
                           (g["end_ns"] - trace_start) / 1e9, g["label"]] for g in groups]}))


if __name__ == "__main__":
    main()
