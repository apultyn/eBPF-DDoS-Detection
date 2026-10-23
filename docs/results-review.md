# Review of the imported test results

Reviewed 2026-10-23. The import lives under `results/results/`: 16 live runs
(eight scenarios, two repetitions), eight saved accuracy evaluations and one
offline `ref-pcap` reference. No detector code, raw measurements or existing
evaluations were changed during this review.

The main concern is measurement validity: **resolve replay timing and alignment
before using the saved accuracy or attack-latency scores as report results**.
The recordings do not show an obvious evaluator backlog or large memory problem
at this workload, but they also cannot establish maximum throughput or a causal
performance improvement between implementations.

## 1. High priority: the live/reference traffic timelines disagree

All eight `eval-*/metrics.json` files report weak, ambiguous alignment:

| Diagnostic | Observed | Existing evaluator check |
| --- | --- | --- |
| Best correlation | 0.7363-0.7444 | At least 0.9 |
| Best/next candidate ratio | 1.0009-1.0038 | At least 1.2 |
| Time containing 1%-99% of cumulative packets | Reference 1246.077 s; live 1491.427-1496.259 s | Same traffic timing after a constant offset |
| Time containing 10%-90% of cumulative packets | Reference 422.518 s; live approximately 623-627 s | Same traffic shape |

The cumulative-packet spans use each recording's packet counts and window
timestamps. They do not depend on the recording's absolute start time. Their
difference therefore cannot be explained just by a different start offset.
It suggests replay timing distortion/drift or another mismatch in the traffic
being compared; these measurements do not identify the cause. Window-resolution
quantiles are diagnostic approximations, not individual packet timestamps.

Examples of source evidence are
[reference windows](../results/results/ref-pcap/windows.csv),
[user-space evaluation](../results/results/eval-usr-acc-gen-1/metrics.json) and
[kernel evaluation](../results/results/eval-ker-acc-nat-2/metrics.json).
All evaluations have `tcpreplay=null` and `replay_timing=null`; sender logs were
not included. Near-equal packet totals do not validate replay speed.

**Address first:** recover the exact sender command/output and PCAP/excerpt
identity; compare several traffic landmarks throughout the run. If a single
offset does not fit, repeat the runs with a frozen original-rate replay command,
readiness synchronization and saved sender logs. Do not optimize alignment
against detector flags or silently stretch ground-truth timestamps to improve
scores. The new label plots retain the current warnings and say provisional.

## 2. High priority: provisional detection quality is weak and imbalanced

The saved primary `window` metrics span:

| Quantity | Across eight accuracy runs |
| --- | --- |
| Accuracy | 65.83%-66.31% |
| Recall | 64.05%-64.54% |
| Precision | 99.74%-99.89% |
| F1 | 78.02%-78.39% |
| False negatives | 1475-1495 per run |
| Scored attack windows | 4159-4160 per run |
| Scored benign windows | 233-234 per run |

About 94.7% of scored windows have attack truth. High precision is therefore
insufficient evidence of good detection: an always-attack prediction would
already have about 94.7% accuracy on this population. This baseline is descriptive,
not a proposed detector. Recheck recall and false negatives after fixing timing;
the current mismatch prevents attributing the low recall to the algorithm alone.
Use all confusion counts, recall, FPR, prevalence and coverage in the report.
Small differences between implementations do not demonstrate equivalence.

## 3. High priority: onset latency and attack coverage need qualification

Only NTP and DNS have scored coverage in this excerpt. Ten other label types are
`not_covered`, not missed attacks; `attacks_detected=2`, `attacks_total=12` must
not be presented as a 2/12 detection success rate. The existing evaluator groups
by attack label, which also does not establish independent attack episodes.

NTP's recorded onset is 3879 s before the excerpt begins. The NTP values of
4022.97-4087.40 s in the saved latency files include time before observation.
They cannot measure response to a newly starting NTP attack on the live run.
Mark this onset as left-censored/ongoing at capture start. DNS onset is covered,
but its latency remains provisional because alignment fails.

The first 75 evaluator warm-up windows include 46 attack-truth windows in every
accuracy evaluation. An assumed benign training/startup period is not supported
by those labels; broad overlapping flow labels are not proof of a high-rate
flood either. Verify startup and label timing before calibrating the detector.

`latency.csv` uses the first flagged window's `end_ns` minus label onset.
Actual live verdict availability is later, at `eval_end_ns`. Keep attack-onset
latency, `(eval_end_ns - end_ns)` decision delay and
`(eval_end_ns - eval_start_ns)` computation time distinct. Examples:
[latency rows](../results/results/eval-usr-acc-gen-1/latency.csv) and
[run timestamp definitions](../results/results/ker-acc-nat-1/run.json).

## 4. Packet loss is present; intentional blocks must stay separate

User-space accuracy runs report these capture socket drops:

| Run | Dropped packets | Share of socket-offered packets |
| --- | ---: | ---: |
| usr-acc-gen-1 | 104156 | 0.1326% |
| usr-acc-gen-2 | 195543 | 0.2489% |
| usr-acc-nat-1 | 48942 | 0.0623% |
| usr-acc-nat-2 | 46217 | 0.0588% |

NIC drops range from 1495 to 11087 across the accuracy runs. These are worth
recording and explaining, although their size alone does not explain a roughly
35% false-negative share. In this import `dev.rx_drop` and
`ethtool.rx_out_of_buffer` are equal observations of the same loss: do not add
them. Missing sender logs prevent a complete sender-to-detector loss balance.
The saved alignment-dependent `window_loss` should not be treated as authoritative
until timing is validated.

Performance runs intentionally block 99.02%-99.09% of accounted packets. Both
implementations' `packets`/`bytes` already exclude XDP-blocked traffic. Therefore
processed packets equal `packets`; subtracting `blocked_packets` again is wrong.
For user-space capture, measured socket losses are another uncounted stage.

NIC counters also depend on attachment mode. In native blocking runs here,
`dev.rx_packets` excludes XDP drops. For example,
[ker-per-nat-1](../results/results/ker-per-nat-1/run.json) has 737078 NIC packets
and 77821010 intentional blocks. A comparison of NIC received packets with the
full excerpt that ignores those blocks would incorrectly report about 99% loss.
Establish counter positions before adding NIC, driver and XDP quantities.

## 5. Resource use is low at this mitigation workload

These are descriptive whole-run observations, not matched-interval estimates of
the effect of offloading. Host busy percentages are the sums of memwatch's busy
time divided by total CPU time across all cores. Memory main is the sampled
median of `anon + kernel + sock`, before separately charged BPF maps.

| Run | Intentional blocks, % of counted + blocked | Host busy % | Median main MiB |
| --- | ---: | ---: | ---: |
| usr-per-gen-1 | 99.085 | 0.518 | 7.086 |
| usr-per-gen-2 | 99.066 | 0.563 | 7.043 |
| usr-per-nat-1 | 99.091 | 0.545 | 6.969 |
| usr-per-nat-2 | 99.078 | 0.523 | 7.039 |
| ker-acc-per-1 | 99.087 | 0.575 | 7.012 |
| ker-per-gen-2 | 99.063 | 0.584 | 7.070 |
| ker-per-nat-1 | 99.062 | 0.660 | 6.941 |
| ker-per-nat-2 | 99.017 | 0.536 | 7.031 |

Sources: each run's `memory_summary.json`, `memory.csv`, `cpu.csv` and
`run.json`. Main-memory peaks are 7.254-7.461 MiB; memory summaries have no
warnings. Add 121832 bytes of separately charged maps for user-space blocking
and 257600 bytes for the kernel implementation when comparing total memory.
Whole-machine BPF snapshots include unrelated maps; do not sum every snapshot
entry as detector memory. Program/JIT memory is outside these map totals.

Low average CPU is plausible when blocking almost the entire workload. It is
not evidence of full-stream counting capacity or maximum sustainable throughput.
There is no same-traffic no-detector baseline or load sweep in the import.
Different recording lengths, idle tails and residual traffic also affect
whole-run averages. Compare verified common intervals and repetitions later.

Reassuring checks: all 17 raw window series are ordered, contiguous and
nonoverlapping, with no epoch jumps/skips. Small total discrepancies are
explained by recorded late/final partial windows; the reference explicitly
drops its final 204-packet partial window. The largest live evaluation time is
9.328 ms against a 536.871 ms window, and closing-delay medians are about
10.2-10.8 ms. There is no evidence of evaluator backlog at this load.

## 6. Repetition identity and provenance need repair

- `ker-acc-per-1` has `source=xdp`, `config.block=true` and resource recordings:
  it is a performance run despite its name. It appears to be the missing first
  kernel generic performance repetition, but confirm the attachment mode from
  experiment records. Preserve the original path and document the alias.
- All 17 manifests say `version.modified=true`. Four different commits appear
  among the live runs: `5793cd56`, `73fe3a2c`, `7c8e11da`, `3e8e5250`.
  Recover source diffs/build hashes or rerun a frozen revision before treating
  runs as interchangeable repetitions. A commit cannot reconstruct a dirty build.
- Actual generic/native attachment mode is absent from detector manifests.
  The directory suffix is an experiment label, not independent verification.
- Several first runs ended `interrupted`; check replay coverage rather than
  automatically discarding or automatically accepting them. The import alone
  also does not establish results on both report testbeds or six datasets.

Recommended order: verify traffic identity/timing and provenance; correct onset
coverage interpretation; rerun synchronized experiments if necessary; reevaluate
quality; then compare common-interval resources and independent run repetitions.
The detailed **plan only** for those steps and report figures is
[report-analysis-plan.md](report-analysis-plan.md). The current per-run plotting
implementation and counter definitions are in
[PLOTTING.md](../analysis/PLOTTING.md).
