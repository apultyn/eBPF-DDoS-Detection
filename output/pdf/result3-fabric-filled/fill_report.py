"""Fill the six FABRIC sections and summary cells in a workspace copy."""

import hashlib
import json
from pathlib import Path
import re
import shutil

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator
from extract_evidence import flood, cpu_stats, read_csv

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
EVIDENCE = json.loads((OUT / "fabric-evidence.json").read_text())
RUNS = EVIDENCE["runs"]
U, K = (RUNS[f"{p}-acc-gen-1"] for p in ("usr", "ker"))
BU, BK = (RUNS[f"{p}-per-gen-1"] for p in ("usr", "ker"))
FIGURES = OUT / "resources/testing-figures"
FABRIC_FIGURES = FIGURES / "fabric"


def n(value):
    return f"{value:,}"


def pc(value, digits=1):
    return f"{value:.{digits}f}"


def expand(template, **values):
    for key, value in values.items():
        template = template.replace("@" + key + "@", str(value))
    assert not re.search(r"@[a-z_]+@", template)
    return template


def table(rows, caption, label, headers=("Userspace", "Kernel")):
    body = "\n".join("    " + " & ".join(map(str, row)) + r" \\" for row in rows)
    return (r"\begin{table}[H]" + "\n  \\centering\n  \\small\n"
            r"  \begin{tabular}{@{}lrr@{}}" + "\n    \\toprule\n    & "
            + " & ".join(headers) + r" \\" + "\n    \\midrule\n" + body
            + "\n    \\bottomrule\n  \\end{tabular}\n  \\caption{" + caption
            + "}\n  \\label{" + label + "}\n\\end{table}\n")


def figure(name, caption, label):
    return (r"\begin{figure}[H]" + "\n  \\centering\n  \\includegraphics[width=\\linewidth]{resources/testing-figures/fabric/"
            + name + ".png}\n  \\caption{" + caption + "}\n  \\label{" + label + "}\n\\end{figure}\n")


def workload():
    def v(key):
        return [r["evaluation"]["counts"][key] for r in (U, K)]
    rows = [("Windows closed", *map(n, v("windows_total"))),
            ("Excluded: before excerpt", *v("excluded_before_excerpt")),
            ("Excluded: after excerpt", *v("excluded_after_excerpt")),
            ("Excluded: warm-up", *v("excluded_warmup")),
            ("Excluded: not evaluated", *v("excluded_not_evaluated")),
            ("Windows scored", *map(n, v("windows_scored"))),
            ("Alignment correlation", *(pc(r["evaluation"]["run"]["offset"]["correlation"], 3) for r in (U, K))),
            ("Peak ratio to next candidate", *(pc(r["evaluation"]["run"]["offset"]["peak_ratio"], 3) for r in (U, K))),
            (r"Flood onset vs.\ label start (s)", *(f'${r["flood_onset_vs_label_s"]:+.2f}$' for r in (U, K))),
            ("Flood duration in counted traffic (s)", *(pc(r["phase"]["duration_s"], 1) for r in (U, K)))]
    return table(rows, "Evaluation coverage and alignment on the FABRIC VM, blocking disabled. Both runs use the saved evaluator alignment; no onset correction is applied.", "tab:fabric-coverage") + expand(r"""
Both FABRIC evaluations score 4,393 windows, including 2,881 attack-labelled
and 1,512 benign-labelled windows (Table~\ref{tab:fabric-coverage}). Unlike
the Pi userspace evaluation, both cover the beginning of the excerpt.
The counted flood begins @us@~s relative to the labelled attack start in
userspace and @ks@~s in the kernel run. However, both runs fail the evaluator's
correlation and peak-ratio criteria. Their flood durations are @ud@ and
@kd@~s, compared with @rd@~s in the offline reference under the same
traffic-based rule. Matching the onset therefore does not validate the
remaining replay timeline.

For the FABRIC phase summaries, the median is centred over nine consecutive
windows. The first and last qualifying window starts are the cutpoints of
a half-open flood interval; boundary windows belong to exactly one phase.
Elapsed phase times are measured from the first recorded window, not process
launch. The runs also report different source commits and modified source
trees, so the implementation comparisons below are descriptive observations.
""", us=f'${U["flood_onset_vs_label_s"]:+.2f}$', ks=f'${K["flood_onset_vs_label_s"]:+.2f}$',
        ud=pc(U["phase"]["duration_s"], 1), kd=pc(K["phase"]["duration_s"], 1), rd=pc(EVIDENCE["reference_flood"]["duration_s"], 1))


def loss():
    result = figure("figure-09-packet-accounting", "Packet accounting on the FABRIC VM with blocking disabled. Shares use the whole-run interface-counter estimate; right: magnified non-counted components.", "fig:fabric-loss")
    rows = [("Interface-counter estimate", n(U["accounting"]["denominator"]), "100.000", n(K["accounting"]["denominator"]), "100.000")]
    for key, label, digits in (("interface", r"Interface drops (\texttt{rx\_drop})", 5), ("socket", "Capture-socket drops", 5),
                               ("late", "Late drops", 6), ("unaccounted", "Unaccounted / other", 6), ("counted", "Counted in windows", 5)):
        values = []
        for r in (U, K):
            if r is K and key in ("socket", "late"):
                values.extend(("--", "--"))
            else:
                values.extend((n(r["accounting"]["counts"][key]), pc(r["accounting"]["percent"][key], digits)))
        rows.append((label, *values))
    body = "\n".join("    " + " & ".join(row) + r" \\" for row in rows)
    result += r"""\begin{table}[H]
  \centering
  \footnotesize
  \setlength{\tabcolsep}{4pt}
  \begin{tabular}{@{}lrrrr@{}}
    \toprule
    & \multicolumn{2}{c}{Userspace} & \multicolumn{2}{c}{Kernel} \\
    \cmidrule(lr){2-3}\cmidrule(lr){4-5}
    & Packets & \% & Packets & \% \\
    \midrule
""" + body + r"""
    \bottomrule
  \end{tabular}
  \caption{Whole-run packet accounting on the FABRIC VM, blocking disabled.
  The denominator is $\Delta\mathrm{rx\_packets}+\Delta\mathrm{rx\_drop}$,
  an interface-counter estimate rather than an independently verified wire
  total. Identical observations of interface loss in \texttt{rx\_drop} and
  \texttt{rx\_out\_of\_buffer} are counted once.}
  \label{tab:fabric-loss}
\end{table}
"""
    return result + expand(r"""
Both FABRIC implementations count almost the entire interface-counter
estimate: @uc@\% for userspace and @kc@\% for the kernel run
(Figure~\ref{fig:fabric-loss}, Table~\ref{tab:fabric-loss}). The userspace
run records 104,156 socket drops and 13 late drops; the kernel path has
neither of these userspace capture stages. Interface drops are higher in
the kernel recording, 9,689 versus 3,251, but its counted total is still
97,731 packets larger. This is a much smaller difference than on the Pi.

The residual is 405 packets in each run. In userspace it is exactly the
number of parser-skipped frames; the kernel residual is retained without
assigning a loss cause. The saved evaluator reports window-loss estimates
of @ul@\% and @kl@\%, respectively, over windows fully inside the mapped
excerpt. These are alignment-dependent estimates, distinct from the
whole-run counter balance and from the 75-window scoring exclusion.
""", uc=pc(U["accounting"]["percent"]["counted"], 5), kc=pc(K["accounting"]["percent"]["counted"], 5),
        ul=pc(100 * U["evaluation"]["run"]["losses"]["window_loss"], 2), kl=pc(100 * K["evaluation"]["run"]["losses"]["window_loss"], 2))


def cpu():
    result = figure("figure-10-cpu-breakdown", "CPU time during each FABRIC run's counted flood, blocking disabled. The stacks show mean cores in the detector process and the rest of the host; the latter includes unrelated work and kernel packet processing.", "fig:fabric-cpu")
    result += expand(r"""
The FABRIC flood intervals are @ua@--@ub@~s for userspace and
@ka@--@kb@~s for the kernel run, measured from the first recorded
window using the nine-window median rule above. Figure~\ref{fig:fabric-cpu}
uses these same intervals.

""", ua=pc(U["phase"]["start_elapsed_s"], 1), ub=pc(U["phase"]["end_elapsed_s"], 1),
        ka=pc(K["phase"]["start_elapsed_s"], 1), kb=pc(K["phase"]["end_elapsed_s"], 1))
    rows = [(r"Host CPU, whole run (\% of all cores)", *(pc(r["cpu_whole"]["host_percent_all_cores"], 2) for r in (U, K))),
            (r"Host CPU, flood (\% of all cores)", *(pc(r["cpu_flood"]["host_percent_all_cores"], 1) for r in (U, K))),
            (r"Detector process, flood (\% of one core)", pc(U["cpu_flood"]["process_percent_one_core"], 1), pc(K["cpu_flood"]["process_percent_one_core"], 2)),
            ("Counted rate, flood mean (kpps)", *(pc(r["cpu_flood"]["counted_mean_kpps"], 1) for r in (U, K))),
            ("Counted rate, maximum window (kpps)", *(pc(r["cpu_flood"]["counted_max_window_kpps"], 1) for r in (U, K))),
            (r"Host CPU time per counted packet ($\mu$s)", *(pc(r["cpu_flood"]["host_us_per_counted_packet"], 2) for r in (U, K)))]
    result += table(rows, "CPU utilisation and counted traffic on the FABRIC VM, blocking disabled. CPU percentages use ratios of summed contemporaneous counters. CPU time per counted packet includes all host work, including work on traffic subsequently dropped.", "tab:fabric-cpu")
    return result + expand(r"""
During the flood, the counted rates are almost equal, @ur@ versus
@kr@~kpps, while host utilisation is @uh@\% for userspace and @kh@\%
for the kernel implementation. Host CPU time per counted packet is
@ut@ versus @kt@~$\mu$s (Table~\ref{tab:fabric-cpu}). The detector
process accounts for @up@\% of one core in userspace and @kp@\% in
the kernel run. XDP's per-packet work is outside that process and remains
part of host CPU. Without a same-traffic no-detector baseline these
measurements do not isolate detector-only overhead.
""", ur=pc(U["cpu_flood"]["counted_mean_kpps"], 1), kr=pc(K["cpu_flood"]["counted_mean_kpps"], 1),
        uh=pc(U["cpu_flood"]["host_percent_all_cores"], 1), kh=pc(K["cpu_flood"]["host_percent_all_cores"], 1),
        ut=pc(U["cpu_flood"]["host_us_per_counted_packet"], 2), kt=pc(K["cpu_flood"]["host_us_per_counted_packet"], 2),
        up=pc(U["cpu_flood"]["process_percent_one_core"], 1), kp=pc(K["cpu_flood"]["process_percent_one_core"], 2))


def detection():
    scores = [r["evaluation"]["scores"]["window"] for r in (U, K)]
    rows = [("Attack-labelled windows", *(n(s["TP"] + s["FN"]) for s in scores)),
            ("Benign-labelled windows", *(n(s["TN"] + s["FP"]) for s in scores))]
    rows += [(label, *(n(s[key]) for s in scores)) for key, label in (("TP", "True positives (TP)"), ("FP", "False positives (FP)"), ("TN", "True negatives (TN)"), ("FN", "False negatives (FN)"))]
    rows += [(label, *(pc(s[key] * scale, digits) for s in scores)) for key, label, scale, digits in
             (("recall", r"Recall (\%)", 100, 1), ("precision", r"Precision (\%)", 100, 1),
              ("fpr", r"False-positive rate (\%)", 100, 1), ("f1", "F1 score", 1, 3), ("accuracy", r"Accuracy (\%)", 100, 1))]
    result = table(rows, "Saved window-level detection quality on the FABRIC VM, blocking disabled. Both columns retain the evaluator alignment and are provisional because its alignment criteria fail.", "tab:fabric-detection")
    rows = []
    for key, label in (("before", "Before flood: windows / flagged"), ("flood", "Flood: windows / flagged"), ("tail", "Low-rate tail: windows / flagged")):
        rows.append((label, *(n(r["phases"][key]["windows"]) + " / " + pc(r["phases"][key]["flagged_percent"], 1) + r"\%" for r in (U, K))))
    rows.extend([("Flood windows not flagged", *(r["phases"]["flood"]["not_flagged"] for r in (U, K))),
                 (r"\quad with an empty two-window span", *(r["phases"]["flood"]["not_flagged_empty_combined_span"] for r in (U, K)))])
    result += table(rows, "FABRIC scored-window flag rates by each recording's own traffic phase. The three half-open phase populations partition all 4,393 scored windows per run.", "tab:fabric-phases")
    result += figure("figure-11-window-classification", "Provisional window classification over time on the FABRIC VM. Grey marks excluded windows. The shared trace clock uses saved offsets; both alignments retain correlation and peak-ambiguity warnings.", "fig:fabric-outcomes")
    return result + r"""
Under the saved alignments, the two FABRIC implementations have similar
observed detection quality: recall is 92.2\% versus 91.9\%, precision
98.8\% versus 98.6\%, and F1 0.954 versus 0.951 for userspace and kernel,
respectively (Table~\ref{tab:fabric-detection}). These small differences do
not establish an implementation advantage or statistical equivalence.

Both implementations flag the first window of their counted flood and
approximately 99.9\% of scored flood windows. The one unflagged userspace
flood window and two unflagged kernel flood windows have empty two-window
spans. Most false negatives occur in the low-rate tail: 223 of 224 for
userspace and 232 of 234 for the kernel implementation. Tail flag rates are
85.4\% and 84.8\% (Table~\ref{tab:fabric-phases}). Figure~\ref{fig:fabric-outcomes}
shows these windows on the saved trace mappings; the unresolved replay
timing prevents treating this as a validated temporal comparison.
"""


def blocking():
    rows = [(r"Intentionally blocked in XDP (\%)", *(pc(r["blocking"]["blocked_percent"], 2) for r in (BU, BK))),
            (r"Passed XDP (\%)", *(pc(r["blocking"]["passed_percent"], 3) for r in (BU, BK))),
            (r"Interface drops (\%)", *(pc(r["blocking"]["interface_drop_percent"], 5) for r in (BU, BK))),
            ("New block events", *(r["blocking"]["new_events"] for r in (BU, BK))),
            ("Refreshes of active entries", *(r["blocking"]["refreshes"] for r in (BU, BK))),
            ("Unique sources blocked", *(len(r["blocking"]["unique_blocked_sources"]) for r in (BU, BK))),
            (r"\quad verified attack sources", "--", "--"),
            ("Windows flagged", *(r["manifest"]["stats"]["flagged_windows"] for r in (BU, BK))),
            (r"Host CPU, whole run (\% of all cores)", *(pc(r["cpu_whole"]["host_percent_all_cores"], 2) for r in (BU, BK))),
            (r"Host CPU, flood (\% of all cores)", *(pc(r["cpu_flood"]["host_percent_all_cores"], 2) for r in (BU, BK)))]
    return table(rows, r"Blocking-enabled FABRIC runs, \texttt{usr-per-gen-1} and \texttt{ker-per-gen-1}. Percentages use the whole-run interface-counter estimate. New block events exclude refreshes. Per-source attack identity cannot be verified without the corrected flow-label file.", "tab:fabric-blocking") + r"""
With blocking enabled, XDP intentionally drops 99.07\% of the interface-counter
estimate for userspace and 99.08\% for the kernel run. Approximately 0.92\%
passes XDP, including traffic subsequently lost at the capture socket or
excluded by the parser. Interface drops account for 0.00982\% and 0.00571\%,
respectively (Table~\ref{tab:fabric-blocking}).

Userspace records 47 new block events affecting seven distinct sources and
23 refreshes; the kernel run records 46 new events affecting six sources
and 29 refreshes. Thus the successful per-IP update totals are 70 and 75.
Both manifests record a 60~s expiry and no blocklist errors. The source
counts describe successful updates, not verified malicious-source counts.

The flood is located from counted plus intentionally blocked packets,
with recorded socket drops added for userspace. Its intervals are
853.6--1581.6~s and 855.2--1583.2~s on the local first-window clocks.
Host utilisation during those intervals is 1.52\% and 1.32\%, versus
37.1\% and 14.2\% in the blocking-disabled runs. This workload suppresses
almost all post-XDP traffic; it does not measure full-stream counting
capacity. Both recordings end as interrupted after approximately 44.5
minutes, with recorded window/block totals retained over the observed run.
"""


def other():
    def lat(r, key, statistic):
        return r["latency_after_detector_warmup_ms"][key][statistic]
    rows = [("Cgroup main memory, median (MiB)", *(pc(r["memory"]["main_mib"]["p50"], 2) for r in (BU, BK))),
            ("Separately charged BPF maps (KiB)", *(pc(r["memory"]["bpf_maps_bytes"] / 1024, 1) for r in (BU, BK))),
            ("Main + BPF maps (MiB)", *(pc(r["memory"]["main_plus_bpf_maps_mib"]["p50"], 2) for r in (BU, BK))),
            ("Window end to verdict, median / p95 (ms)", *(pc(lat(r, "decision", "p50"), 2) + " / " + pc(lat(r, "decision", "p95"), 2) for r in (U, K))),
            ("Verdict computation, median / p95 (ms)", *(pc(lat(r, "evaluation", "p50"), 2) + " / " + pc(lat(r, "evaluation", "p95"), 2) for r in (U, K)))]
    return table(rows, r"FABRIC memory with blocking enabled and local decision timing with blocking disabled. Memory medians are sample-based; separately charged maps are added once. Timing uses evaluated windows with detector \texttt{warm\_up=false}, distinct from the 75-window scoring mask.", "tab:fabric-other") + r"""
Including the recorded BPF maps, median memory is 7.20~MiB for userspace and
7.26~MiB for the kernel implementation (Table~\ref{tab:fabric-other}). Main
memory alone is slightly smaller in the kernel run, but its separately
charged maps are larger: 251.6 versus 119.0~KiB. Program/JIT memory is not
included in these totals.

The kernel implementation's median time from window end to verdict is
10.82~ms, compared with 10.22~ms for userspace; verdict computation is
0.20 versus 0.14~ms. Both 95th-percentile decision delays are below 11.4~ms
against the 536.9~ms window length. These are local window-closing and
verdict-availability measurements, independent of trace-to-live alignment.
They do not measure attack-onset response, individual-packet execution time
or end-to-end application latency.
"""


def cpu_image(path, runs=(U, K), testbed="FABRIC VM"):
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "axes.spines.left": False, "axes.axisbelow": True, "pdf.fonttype": 42})
    fig, ax = plt.subplots(figsize=(7.8, 4.9))
    fig.subplots_adjust(left=.13, right=.98, bottom=.18, top=.73)
    fig.text(.13, .95, "Where CPU time is spent during the flood", fontsize=15, weight="bold", va="top")
    fig.text(.13, .875, f"{testbed}  |  Blocking off  |  Nine-window traffic-median phase rule", fontsize=10, color="#495464", va="top")
    process = [r["cpu_flood"]["process_cores"] for r in runs]
    rest = [r["cpu_flood"]["rest_cores"] for r in runs]
    ax.bar([0, 1], process, width=.48, color="#2864A0", label="Detector process", zorder=3)
    ax.bar([0, 1], rest, bottom=process, width=.48, color="#E0A34B", label="Rest of host", zorder=3)
    ax.set_xticks([0, 1], [f'{label}\n{r["phase"]["start_elapsed_s"]:.1f}–{r["phase"]["end_elapsed_s"]:.1f} s'
                            for label, r in zip(("Userspace", "Kernel"), runs)], fontsize=10)
    maximum = 1.75 if max(r["cpu_flood"]["host_cores"] for r in runs) > 1 else .85
    ax.set_xlim(-.6, 1.85); ax.set_ylim(0, maximum)
    ax.set_ylabel("Mean CPU use (cores)", labelpad=12)
    ax.yaxis.set_major_locator(MultipleLocator(.25 if maximum > 1 else .2))
    ax.tick_params(axis="both", length=0, pad=9)
    ax.grid(axis="y", color="#DCE1E7", linewidth=.8)
    ax.legend(loc="lower left", bbox_to_anchor=(-.015, 1.005), frameon=False, ncols=2, fontsize=10)
    for i, r in enumerate(runs):
        ax.text(i, r["cpu_flood"]["host_cores"] + .023, f'{r["cpu_flood"]["host_cores"]:.3f} total', ha="center", va="bottom", weight="bold", color="#273345")
        ax.text(i, process[i] + rest[i] / 2, f"{rest[i]:.3f}", ha="center", va="center", color="#302713")
    ax.text(0, process[0] / 2, f"{process[0]:.3f}", ha="center", va="center", color="white", weight="bold")
    ax.annotate(f"{process[1]:.4f} cores\nin detector process", xy=(1.23, process[1] / 2), xytext=(1.40, maximum * .065), fontsize=9,
                color="#204C78", ha="left", va="center", arrowprops={"arrowstyle": "-", "color": "#2864A0", "lw": 1})
    fig.savefig(path, dpi=240)
    plt.close(fig)


def main():
    source = Path(EVIDENCE["input_tex"])
    assert hashlib.sha256(source.read_bytes()).hexdigest() == EVIDENCE["input_tex_sha256"]
    for name, digest in EVIDENCE["source_sha256"].items():
        assert hashlib.sha256((REPO / name).read_bytes()).hexdigest() == digest, name
    text = source.read_text(encoding="utf-8-sig")
    blocks = iter((workload(), loss(), cpu(), detection(), blocking(), other()))
    text, count = re.subn(r"(\\paragraph\{FABRIC VM\}\s*)\\fillin\{\}", lambda m: m.group(1) + next(blocks).strip() + "\n", text)
    assert count == 6
    text = text.replace(r"    FABRIC VM        & \fillin{} & Userspace & Off / On \\" + "\n" + r"                     & \fillin{} & Kernel    & Off / On \\",
                        r"    FABRIC VM        & \texttt{usr-acc-gen-1} & Userspace & Off \\" + "\n"
                        + r"                     & \texttt{ker-acc-gen-1} & Kernel & Off \\" + "\n"
                        + r"                     & \texttt{usr-per-gen-1} & Userspace & On \\" + "\n"
                        + r"                     & \texttt{ker-per-gen-1} & Kernel & On \\")
    summary = {
        "Packets counted": r"78.55\,M vs.\ 78.46\,M", "Host CPU, flood": r"14.2 vs.\ 37.1\%",
        "CPU per counted packet": r"2.7 vs.\ 6.7\,$\mu$s", "Recall": r"91.9 vs.\ 92.2\%$^{b}$",
        "False-positive rate": r"2.4 vs.\ 2.2\%$^{b}$", "Host CPU, blocking on": r"1.32 vs.\ 1.52\%",
        r"Memory incl.\ BPF maps": r"7.26 vs.\ 7.20\,MiB", "Window end to verdict": r"10.82 vs.\ 10.22\,ms"}
    lines = []
    filled_summary = 0
    for line in text.splitlines():
        key = line.strip().split("&")[0].strip()
        if key in summary and r"\fillin{}" in line:
            line = line.replace(r"\fillin{}", summary[key])
            filled_summary += 1
        lines.append(line)
    assert filled_summary == 8
    text = "\n".join(lines) + "\n"
    text = text.replace(r"disabled unless stated. $^{a}$Userspace onset-aligned.",
                        r"disabled unless stated. $^{a}$Pi userspace onset-aligned. $^{b}$FABRIC uses the saved evaluator alignments; both remain provisional.")
    # Remove the original visible planning bullets, leaving the report prose.
    text = re.sub(r"\n- Tests done\n.*?\n  - \(Throughput\)\n", "\n", text, count=1, flags=re.S)
    text = text.replace("flood of approximately 11~minutes", "flood of approximately 8~minutes")
    text = text.replace("s after detector start for\nuserspace", "s after the first recorded window for\nuserspace")
    text = text.replace("Traffic profile of the replayed excerpt, computed from the trace\n  itself. Bottom: window-level ground truth from the corrected flow labels.",
                        "Traffic profile of the replayed excerpt from saved offline PCAP-reference windows. Bottom: saved window-level ground truth from the corrected-label evaluation, using combined-window semantics.")
    text = text.replace(r"\caption{Whole-host CPU utilisation on the Raspberry Pi 400 with blocking" + "\n  disabled, including software-interrupt time.}",
                        r"\caption{CPU breakdown on the Raspberry Pi 400 with blocking disabled, over the counted-flood intervals used in Table~\ref{tab:cpu}. Values are mean cores, split into detector process and rest of host, including software-interrupt time.}")
    assert not re.search(r"\\paragraph\{FABRIC VM\}\s*\\fillin", text)
    assert r"FABRIC VM        & \fillin{}" not in text
    assert len(re.findall(r"\\label\{tab:fabric-", text)) == 7
    (OUT / "result3.tex").write_text(text, encoding="utf-8")
    FIGURES.mkdir(parents=True, exist_ok=True)
    FABRIC_FIGURES.mkdir(parents=True, exist_ok=True)
    for folder, name in (("figure-08-traffic-profile", "figure-08-traffic-profile.png"),
                         ("figure-09-packet-accounting", "figure-09-packet-accounting.png"),
                         ("figure-10-cpu-breakdown", "figure-10-cpu-breakdown.png"),
                         ("figure-11-window-classification", "figure-11-window-classification.png")):
        shutil.copy2(REPO / "output/plots" / folder / name, FIGURES / name)
    for name in ("figure-09-packet-accounting.png", "figure-11-window-classification.png"):
        shutil.copy2(REPO / "output/plots/fabric" / name, FABRIC_FIGURES / name)
    cpu_image(FABRIC_FIGURES / "figure-10-cpu-breakdown.png")
    # Replace the earlier combined-testbed image with a Pi-only rendering
    # using the source document's broader phase definition and same numbers.
    pi_runs = []
    pi_hashes = {}
    for prefix in ("usr", "ker"):
        path = REPO / "results/data-raspberry" / f"{prefix}-acc-gen-1/windows.csv"
        pi_rows = read_csv(path)
        phase = flood(pi_rows)
        a, b = phase["first_index"], phase["stop_index_exclusive"]
        pi_runs.append({"phase": phase, "cpu_flood": cpu_stats(pi_rows[a:b])})
        pi_hashes[path.relative_to(REPO).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    cpu_image(FIGURES / "figure-10-cpu-breakdown.png", pi_runs, "Raspberry Pi 400")
    (OUT / "pi-cpu-figure-evidence.json").write_text(json.dumps({"runs": pi_runs, "source_sha256": pi_hashes}, indent=2) + "\n", encoding="utf-8")
    for path in re.findall(r"\\includegraphics(?:\[[^\]]*\])?\{([^}]+)\}", text):
        assert (OUT / path).is_file(), path
    print("Filled 6 FABRIC sections, 4 run rows, 8 summary cells; verified all figure paths and source hashes.")


if __name__ == "__main__":
    main()
