# Figure 10: CPU time during the flood

This creates the requested stacked bar chart for FABRIC and Raspberry Pi.
The testbed identities follow the user's `data-fabric` and `data-raspberry`
directory assignments. Generic attachment modes are directory labels and
are not independently verified in the manifests.

| Testbed | Implementation | Directory under `results/` | Manifest |
| --- | --- | --- | --- |
| FABRIC | Userspace | `data-fabric/usr-per-gen-3` | `run.json` |
| FABRIC | Kernel | `data-fabric/ker-per-gen-3` | `run.json` |
| Raspberry Pi | Userspace | `data-raspberry/usr-acc-gen-1` | `run.json` |
| Raspberry Pi | Kernel | `data-raspberry/ker-acc-gen-1` | `run_kernelspace.json` |

All four manifests have `config.block=false`; the selected phases contain
zero recorded blocked packets. Each testbed's two recordings share a commit
identifier, but all builds report modified source trees. Other accuracy and
attachment-mode repetitions are not pooled into the selected recordings.
Each bar represents one recording, with no inference across repetitions.

## Rebuild and outputs

From the repository root, using the existing environment with matplotlib:

```powershell
.\.venv\Scripts\python.exe output/plots/figure-10-cpu-breakdown/build_figure.py
```

- `figure-10-cpu-breakdown.png`: raster preview.
- `figure-10-cpu-breakdown.pdf` and `.svg`: vector figures.
- `figure-10-data.csv`: the numbers behind the bars.
- `figure-10-data.json`: counter totals, source hashes, selection, checks, and missing data.
- `figure-10-phase-selection.png`: traffic-rate traces with the selected phases highlighted.
- `figure-10-caption.tex`: figure environment ready to adapt to the full report.

## Selection and calculation

The Raspberry Pi userspace flood occurs much earlier than its kernel flood.
Reusing the previous 850–1575 s phase would include substantial quiet traffic.
The updated chart uses the same **traffic-only** phase-selection rule on all
four recordings, without inspecting CPU measurements to choose the phase:

1. Compute packet rate in 30-second bins on each recording's local clock.
   Count `packets + kernel_drops` for userspace and `packets` for kernel.
   These are observed accounted rates, not sender measurements. Apportion
   boundary-crossing windows by overlap duration; omit the partial final bin
   from phase selection and percentile calculation.
2. Find the longest continuous span whose bin rates are at least half the
   95th percentile of all full-bin rates in that recording.
3. Trim the first and last 30-second bins to exclude transition edges.

Elapsed zero is the first `windows.csv.start_ns`. This gives:

| Testbed | Implementation | Selected local interval, s | CPU samples |
| --- | --- | ---: | ---: |
| FABRIC | Userspace | 870–1560 | 1285 |
| FABRIC | Kernel | 870–1560 | 1285 |
| Raspberry Pi | Userspace | 300–1020 | 1341 |
| Raspberry Pi | Kernel | 930–1530 | 1117 |

Use whole resource intervals selected by endpoint:
`phase_start <= (eval_end_ns - origin_ns) / 1e9 < phase_end`.
The resource snapshot follows evaluation immediately; `eval_end_ns` is its
recorded timestamp proxy. A selected interval may straddle the phase start
by less than one sample (about 0.537 seconds). Traffic is not aligned to a
validated common reference interval. The independent local selection does
not establish equal offered traffic or corresponding packets across runs.

Host and process CPU deltas in **the same rows of `windows.csv`** are collected
by the same sampler. For each recording, let `T = sum(cpu_interval_ns)`:

| Quantity | Formula |
| --- | --- |
| Detector process, cores | `sum(user_cpu_ns + sys_cpu_ns) / T` |
| Whole host busy, cores | `sum(host_busy_ns) / T` |
| Rest of host, cores | `(sum(host_busy_ns) - sum(user_cpu_ns + sys_cpu_ns)) / T` |

One core means one CPU-second per wall-clock second. No core-count assumption
or conversion from host percentages is required. Do not average the rounded
`cpu_share` values, or subtract process percent from whole-host percent.

"Rest of host" is the residual of two accounting measurements. It includes
kernel packet work, monitoring, and unrelated host activity. It is not a
direct measurement of XDP execution time or an exclusive softirq/stack split.
In particular, the userspace recording's separately recorded softirq counter
is larger than this residual, so those values must not be equated or stacked
as additional disjoint categories. The requested two-segment accounting
view is available; a clean execution-context partition would require further
profiling. No no-detector baseline is subtracted.

The script checks valid nonnegative counters, positive intervals, disabled
blocking, zero blocked packets, and that the two segments sum to host busy.
For FABRIC it also compares host cores against the independent `cpu.csv`
monitor. The blocking-off Pi runs do not have `cpu.csv`, but have all necessary
contemporaneous CPU counters in `windows.csv`, so no extra CPU recording is
needed to produce their bars. The Pi blocking-on runs are excluded based on
manifest configuration, including the unusually named `ker-acc-per-1`.

## Interpretation and remaining experimental limits

No required data are missing for the requested two-testbed chart. However,
the Pi userspace phase has a substantially lower observed packet rate than
the kernel phase (approximately 67.7k versus 104.7k packets/s). Its onset and
duration also differ. These CPU values describe the supplied runs; they do
not establish controlled same-load savings, maximum capacity, or a causal
testbed comparison. Observed rates and build identities are retained in the
CSV/JSON for interpretation.

An exact softirq/XDP/network-stack attribution would require an execution-context
profile. Controlled comparisons would require matched, verified replay rates
and timing plus independent repetitions. Those additions are not required to
compute the displayed host-minus-process residual.
