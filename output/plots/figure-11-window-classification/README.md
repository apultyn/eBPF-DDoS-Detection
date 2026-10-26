# Figure 11: window classification over time, Raspberry Pi 400

Three strips share the excerpt's **trace clock**: ground truth, userspace
window classification, and kernel window classification. Both updated
evaluations use **manual trace offsets**, which are used verbatim. The earlier
correlation/ambiguity warnings are absent from these updated evaluations and
are no longer printed on the figure. No offsets or predictions are fitted
or changed by this plotting script.

## Inputs

- `results/data-raspberry/eval-usr-acc-gen-1-adjusted/{metrics.json,windows.csv}`.
- `results/data-raspberry/eval-ker-acc-gen-1-adjusted/{metrics.json,windows.csv}`.
- Their original raw `usr-acc-gen-1` and `ker-acc-gen-1` recordings, including
  `run.json` and `run_kernelspace.json`, respectively, for identity checks.

Both recordings have blocking disabled. The shared axis starts at the first
excerpt packet, 2018-12-01 14:21:52.153161 UTC, and ends at
15:01:51.999846 UTC, approximately 40 minutes later. Saved evaluation window
timestamps are already in trace time; their offsets must not be subtracted a
second time. Each strip retains its own native grid, with no resampling.

## Strip semantics

The ground-truth strip uses the **kernel evaluation's saved truth grid**, which
covers the full excerpt. Its truth remains visible through warm-up/scoring
exclusions because label availability is independent of prediction scoring.
Both corrected evaluations use the same excerpt and label interpretation,
but their native grids differ, so transition edges can differ by a fraction
of one window. Each outcome is checked against its own evaluation's truth,
not reassigned from the top strip.

Outcomes use `outcome_window`, corresponding to the `malicious` detector flag.
They do not use the alternative window-or-IP prediction:

| State | Meaning | Userspace windows | Kernel windows |
| --- | --- | ---: | ---: |
| TP | Attack truth, attack prediction | 2191 | 2577 |
| TN | Benign truth, benign prediction | 420 | 1477 |
| FP | Benign truth, attack prediction | 12 | 34 |
| FN | Attack truth, benign prediction | 691 | 305 |
| Total scored | Sum of the four states | 3314 | 4393 |

Grey means a saved exclusion (warm-up, unevaluated, excerpt boundaries) or no
native windows mapped to that trace interval. Those causes remain distinct
in the data. In particular, userspace has no aligned windows for the first
579.661421464 seconds, approximately 9.66 minutes. This is a property of the
saved alignment and coverage, not proof of missing physical capture or a
benign result. Kernel covers the beginning but has its own grey warm-up.

Bins are 536.870912 ms wide. Combined-mode truth considers the current and
previous window, a 1.073741824 s effective span. All colors occupy their real
current-window durations. Adjacent identical states are merged only for
drawing; no isolated FP/FN state is widened for visibility. Use vector exports
or CSV for inspecting individual subsecond windows.

## Updated alignment metadata

| Implementation | Method | Saved wall-minus-trace offset, ns |
| --- | --- | ---: |
| Userspace | manual | 249266234898618176 |
| Kernel | manual | 249275979665349376 |

The new manual-offset metadata does not contain correlation or peak-ratio
measurements. Old diagnostics are not carried forward. Remaining saved warnings
concern interface/socket losses and are retained in the evidence JSON. The
script preserves the supplied time mappings without independently validating
replay timing. Different scored-window counts also mean the rows are not paired
observations. Warning text on the figure is selected from current metadata;
rebuilding FABRIC's automated evaluations still preserves their own warnings.

For validated temporal comparison, recover sender replay logs and independent
packet/traffic landmarks throughout each run. Resolve the timing and rerun
evaluation with corrected labels and trace provenance; repeat synchronized
replay if a constant offset cannot explain the recordings. The original
corrected flow labels and PCAP remain on the experiment machines.

## Rebuild and outputs

```powershell
.\.venv\Scripts\python.exe output/plots/figure-11-window-classification/build_figure.py
```

- `figure-11-window-classification.png`, `.pdf`, `.svg`: the three-strip figure.
- `figure-11-outcomes.csv`: every plotted native outcome window and exclusion reason.
- `figure-11-ground-truth.csv`: the complete ground-truth strip and effective spans.
- `figure-11-evidence.json`: source hashes, counts, alignment diagnostics, and limitations.
- `figure-11-caption.tex`: report fragment with a qualified caption.

Build checks compare every saved evaluation row with its raw epoch, packet
count and timestamp mapping, verify all four outcomes from truth/prediction,
reconcile outcome totals against metrics.json, preserve exclusion masks,
and verify contiguous native grids and full top-strip coverage.
