# Per-run plots

Install the analysis dependencies, then run from the repository root:

```sh
python -m pip install -r analysis/requirements.txt
python -m analysis.plot results/ --out results/plots --format png pdf
```

The input is a directory: a single raw detector run, an evaluation directory,
or a tree containing many runs (including this import's `results/results/`).
Discovery uses `run.json` plus `windows.csv`, not scenario directory names.
Repetitions stay separate. Raw data and evaluation outputs are never changed.

Examples:

```sh
# One run's attack: packet rate, decimal MB/s and residual processed packet rate.
python -m analysis.plot results/results/usr-per-nat-1 --kind traffic --out results/plots

# Separate plots for CPU and memory measurements.
python -m analysis.plot results/results/ker-per-nat-1 --kind resources --out results/plots

# Labels from an existing evaluation, including its exclusions and warnings.
python -m analysis.plot results/results/eval-usr-acc-gen-1 --kind accuracy --out results/plots

# Select an evaluation stored elsewhere, and inspect a smaller interval.
python -m analysis.plot results/results/usr-acc-gen-1 --kind accuracy \
    --evaluation path/to/evaluation --xlim 700 1000 --out results/zoom

# Expose small amounts of traffic while retaining true zero values.
python -m analysis.plot results/ --kind traffic --symlog --out results/traffic-log
```

`--format` accepts one or more of `png`, `pdf`, `svg` (default `png`).
`--xlim` is elapsed **seconds**, with the full recording shown by default.
Figures are saved under `OUT/<raw-run-name>/`; a directly supplied evaluation
uses its own directory name. `OUT/plot_manifest.json` records inputs, outputs,
evaluation warnings and failures for that invocation. Batch failures do not
prevent the remaining runs from being plotted; any failure yields exit code 1.
Duplicate run basenames in different subtrees are rejected before plotting;
give each cohort its own input and output directory.

## Outputs

With the default `--kind all`:

| Files per run | When | Content |
| --- | --- | --- |
| `traffic.*` | Every raw run, including the offline reference | Accounted arrival, counted, blocked and capture-loss packet rates; processed/blocked MB/s; post-block processed packet rate; flagged-window shading |
| `host_cpu.*` | Performance (`config.block=true`) | Whole-machine busy percentage, including XDP and other processes |
| `host_softirq.*` | Performance | Softirq share of all host CPU time |
| `busiest_core.*` | Performance | Busy percentage of the busiest core |
| `process_cpu.*` | Performance | Detector process CPU; 100% is one core |
| `memory.*` | Performance with `memory.csv` | Cgroup main, cgroup current, and main plus separately charged BPF maps where a fixed footprint is recorded |
| `heap.*` | Performance | Go heap allocation |
| `accuracy_window.*` | Accuracy, with a matching evaluation | Actual and predicted binary labels and TP/TN/FP/FN outcome strip |

Resource plots use `cpu.csv` from memwatch where available, falling back to
the window-level host counters. Process and heap measurements always come
from `windows.csv`. Unavailable resources are omitted. `--kind resources`
can also plot diagnostic resources in other raw runs.

Accuracy plots consume `analysis.evaluate` outputs. With a raw run input,
sibling evaluation directories are matched by `metrics.json.run.run_dir`
(the final path component, accepting Linux or Windows separators). Use
`--evaluation` to disambiguate or select a different location. Raw and evaluated
epochs, original-clock starts, packet counts and available verdicts are then
checked for identity; unrelated or stale evaluations fail instead of being
attributed to the selected raw run. This check also applies to explicit inputs.
Missing truth is never synthesized from packet rates. Automatic batch plotting
records a skip when no evaluation is available; explicit `--kind accuracy`
fails if labels cannot be plotted, or if blocking was enabled.

`--prediction window_or_ip` selects the existing alternative evaluation
definition: window malicious **or** at least one flagged IP. Default is
`window`. Both ground truth and predictions are masked in excluded,
unevaluated or unavailable rows, so warm-up and out-of-excerpt windows cannot
look like correctly predicted benign observations. Ground truth follows the
effective span already used by the evaluator, including combined windows.
Figures omit footer notes and warnings. Evaluations with warnings retain a
provisional title, and the warning details remain in the manifest. These
figures visualize the existing evaluation; they do not repair its clock
alignment or validate its labels.

## Interpret the counters correctly

- `packets` and `bytes` already exclude XDP-blocked traffic in both
  implementations. The remaining processed rate is `packets / window_seconds`;
  subtracting `blocked_packets` again would be wrong.
- Kernel `accounted arrivals = packets + blocked_packets`. For user-space
  capture, add measured `kernel_drops` (capture socket losses). This is a
  **partial reconstruction**, excluding upstream losses and background/stage
  differences; it is not sender throughput or a maximum-capacity measurement.
  Missing terms leave a gap, not a zero. The counted line remains available
  when total arrivals cannot be reconstructed.
- User-space block counters are sampled when a window closes. Their displayed
  rates are approximate window averages and include the closing grace period.
  Kernel block counters belong to the window of the actual drop.
- Rate denominators use each row's actual `end_ns - start_ns`; missing windows
  stay gaps. Timestamps are parsed as 64-bit integers before subtracting them.
  Byte rates are decimal MB/s; resource memory is binary MiB.
- CPU percentages have different denominators: host CPU/softirq are shares
  of **all** host CPU time; process CPU is summed over threads relative to
  **one** core. Process CPU excludes per-packet XDP work. Host utilization
  includes unrelated work; no traffic baseline is subtracted.
- `memory.csv.main = anon + kernel + sock`. Kernel subcomponents must not be
  added again. In these runs the loader's BPF maps are charged outside the
  detector cgroup; the plot adds `bpf_memory.total_bytes` to main only when
  equal start/end footprints are recorded. This assumes the preallocated map
  layout described by the run metadata. Program/JIT memory is excluded. For
  future experiments, verify map charge ownership before reusing that total.
  `current` includes file cache and is a different measurement; heap is only
  the Go heap. None of these is total machine RAM utilization.
- Shading in traffic/resource plots marks raw `malicious=true` windows,
  including any startup period. It does not mark blocked packets or
  `flagged_ips` alone. Sparse, short flagged windows can appear as faint thin
  lines when the full run is shown; use `--xlim` to inspect them. Accuracy
  plots instead respect the evaluator's explicit exclusions. The offline
  reference uses trace elapsed
  time; live raw plots use wall elapsed time. No automatic cross-run alignment
  or averaging is performed here.

The current import's issues and evidence are recorded in
[results-review.md](../docs/results-review.md). The requested **plan only** for
future aggregation, extraction and report figures is in
[report-analysis-plan.md](../docs/report-analysis-plan.md).

## Verification

```sh
python -m pytest analysis/tests/test_plot.py
python -m pytest analysis/tests
```

The regression checks cover packet accounting, missing measurements, exact
nanosecond timestamps, real durations/gaps, scoring exclusions, evaluation
discovery and headless plotting. Generated files belong under the ignored
`results/` directory.

Validation on the imported data generated 73 figures (17 traffic, 48 resource,
8 accuracy) in PNG and PDF with no batch errors; representative raster and PDF
exports were visually checked. All 19 plotting tests passed. The full analysis
suite returned 77 passed and four existing failures in
`test_evaluation_memory.py::test_batch_compaction_preserves_scores_latency_and_warnings`:
the full and compact label paths emit the same overlapping attack labels in
different orders (`UDP;Syn` versus `Syn;UDP`). The failure reproduces when that
existing test runs alone without the plotting module; its scores, counts and
warnings agree. The evaluator has not been changed as part of plotting.
