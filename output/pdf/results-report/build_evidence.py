"""Rebuild the report's derived evidence; raw recordings are read only."""
from pathlib import Path
import csv
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
sys.path.insert(0, str(REPO))
from analysis.compare_performance import describe_run, cpu_ratio

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW = REPO / "results" / "data-from-tests"
FIGURES = ROOT / "resources" / "testing-figures"
FIGURES.mkdir(parents=True, exist_ok=True)
SOURCE = Path("C:/Users/jedre/Downloads")
for source in (SOURCE / "testing-figures").glob("*.png"):
    shutil.copy2(source, FIGURES / source.name)

original = (SOURCE / "Results.tex").read_bytes()
summary_start = original.index(b"\\subsection{Summary}")
(ROOT / "Summary-unchanged.tex").write_bytes(original[summary_start:])

names = ["usr-per-gen-3", "ker-per-gen-3", "usr-per-gen-1", "ker-per-gen-1"]
runs = []
for name in names:
    directory = RAW / name
    run = describe_run(directory)
    with (directory / "windows.csv").open(newline="", encoding="utf-8-sig") as f:
        windows = list(csv.DictReader(f))
    origin = int(windows[0]["start_ns"])
    with (directory / "cpu.csv").open(newline="", encoding="utf-8-sig") as f:
        host = list(csv.DictReader(f))
    # Approximate visually identified high-rate phase on each recording's clock.
    phase = [r for r in host if 850 <= (int(r["ts_ns"]) - origin) / 1e9 < 1575]
    run["high_rate_phase"] = {
        "elapsed_seconds": [850, 1575],
        "selection": "sample endpoints within the interval; not reference-clock aligned",
        "host_cpu": cpu_ratio(phase, ("host_busy_ns",), "host_total_ns"),
    }
    run["source_hashes"] = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in directory.iterdir()
        if p.name in ("run.json", "windows.csv", "cpu.csv", "memory.csv")
    }
    runs.append(run)

evaluations = {}
for name in ("usr-acc-gen-1", "ker-acc-gen-1"):
    path = RAW / ("eval-" + name) / "metrics.json"
    evaluations[name] = json.loads(path.read_text(encoding="utf-8-sig"))

throughput = json.loads((REPO / "results/throughput/throughput.json").read_text())
selected_throughput = [r for r in throughput["runs"] if r["name"] in names]
evidence = {
    "scope": "Four individual FABRIC recordings corresponding to the supplied plots; no pooled repetitions or causal effects.",
    "runs": runs,
    "evaluations": evaluations,
    "throughput": selected_throughput,
    "original_fragment_sha256": hashlib.sha256(original).hexdigest(),
    "original_summary_sha256": hashlib.sha256(original[summary_start:]).hexdigest(),
    "latency_population": "evaluated=true and warm_up=false; differences computed as integer nanoseconds before conversion",
}
(ROOT / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.facecolor": "white"})
labels = ["User / off", "Kernel / off", "User / on", "Kernel / on"]
colors = ["#0078a8", "#0078a8", "#b65a00", "#b65a00"]
fig, axes = plt.subplots(1, 2, figsize=(10.7, 3.9), layout="constrained")
for ax, key, title in zip(axes, ("evaluation", "decision"),
                           ("Verdict computation", "Window end to verdict")):
    for i, run in enumerate(runs):
        stats = run["latency_after_warmup_ms"][key]
        ax.plot([stats["p50"], stats["p95"]], [i, i], color=colors[i], linewidth=2)
        ax.scatter(stats["p50"], i, color=colors[i], s=35, marker="o", zorder=3)
        ax.scatter(stats["p95"], i, color=colors[i], s=45, marker="|", zorder=3)
    ax.set_yticks(range(4), labels)
    ax.invert_yaxis()
    ax.set_xlabel("Time (ms)")
    ax.set_title(title, loc="left", fontweight="bold")
    ax.grid(axis="x", alpha=.2)
axes[0].set_xlim(0, .47)
axes[1].set_xlim(9.9, 11.6)
fig.suptitle("Local timing after warm-up | circle: median; end marker: 95th percentile", fontsize=11)
fig.savefig(FIGURES / "local-latency.png", dpi=200)
plt.close(fig)

for run in runs:
    print(json.dumps({"name": run["name"],
                      "high_rate_host_cpu": run["high_rate_phase"]["host_cpu"]["weighted_mean"],
                      "whole_run_host_cpu": run["cpu"]["host_busy_percent"]["weighted_mean"],
                      "latency_n": run["latency_after_warmup_ms"]["decision"]["n"],
                      "main_median_mib": run["memory"]["main_mib"]["p50"]}))
