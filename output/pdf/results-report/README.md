# Revised results fragment

`Results.tex` is the replacement Results text up to, but excluding, the Summary. It includes all 15 supplied plots, a derived local-timing plot, and descriptions of memory, host/process CPU, traffic rates, timing and classification metrics. Use the same `resources/testing-figures/` directory layout in the full report. The fragment requires `graphicx`, `float` and `booktabs`.

`main.tex` provides a standalone preview. `Summary-unchanged.tex` preserves the original Summary and everything after it byte for byte, and is deliberately not included in the preview. The original file in Downloads is unchanged. The preserved Summary still contains the old placeholder findings and is not part of this revision.

The revision uses the supplied FABRIC recordings and the repository's matching raw measurements. It does not claim results from a Raspberry Pi or all six proposed datasets. Directory attachment labels are not independently verified. Observed comparisons are descriptive and are not significance tests or capacity benchmarks.

## Evidence

- Original input: `C:/Users/jedre/Downloads/Results.tex` and `C:/Users/jedre/Downloads/testing-figures/`.
- Raw resource runs: `results/data-from-tests/{usr,ker}-per-gen-{1,3}/` in the repository. Run 1 has blocking enabled and run 3 has blocking disabled, according to `run.json`.
- Accuracy: `results/data-from-tests/eval-{usr,ker}-acc-gen-1/metrics.json`, the saved latency rows, and the other accuracy evaluations for the reported diagnostic ranges.
- Throughput: `results/throughput/throughput.json` and `throughput.md`. A best sustained interval contains 112 whole windows, or 60.129542144 s, selected independently by packet rate in each recording.
- Measurement definitions: `analysis/PLOTTING.md`, `analysis/PERFORMANCE.md`, `analysis/compare_performance.py`, and `analysis/evaluate.py`.
- Existing validation findings: `docs/results-review.md`. Its old directory references precede the move to `results/data-from-tests/`.

`evidence.json` records the selected raw-run summaries, hashes, saved accuracy evaluations and throughput results. CPU means use sums of valid counter pairs. The approximate high-rate phase selects samples ending at elapsed times in [850, 1575) s; it is not a validated common trace interval. Memory medians are sample based and include startup. Timing distributions use only evaluated rows with `warm_up=false`; integer timestamps are subtracted before converting units. This detector flag is distinct from the evaluator's 75-window scoring exclusion.

Rebuild the evidence and local-timing PNG from the repository root with a Python environment containing matplotlib:

```powershell
.\.venv\Scripts\python.exe output/pdf/results-report/build_evidence.py
```

Compile `main.tex` twice with pdfLaTeX, or open the project directory in the Codex LaTeX editor.
