# FABRIC versions of Figures 8–11

These are the FABRIC counterparts of the four plots referenced in `result3.tex`.
The supplied TeX was used as a figure inventory and was not edited. Pi figures
are preserved in their original output directories.

## Consistent cohort

Figures 9, 10 and 11 all use the generic-mode-labelled, blocking-disabled runs
`results/data-fabric/usr-acc-gen-1` and `results/data-fabric/ker-acc-gen-1`.
Their adjusted evaluations provide the saved classification outcomes. This is
one recording per implementation, not a pool of repetitions or native modes.
The builds have different commits and both report modified source trees.
The attachment mode is a directory label, not independent driver verification.

The earlier combined-testbed Figure 10 used FABRIC's `*-per-gen-3` resource
recordings. This set instead uses `*-acc-gen-1`, matching the accuracy cohort
and the Pi convention of one common blocking-off run per implementation.
Consequently its FABRIC CPU numbers differ from that earlier figure.

## Figures and interpretation

- **Figure 8, traffic profile:** the same replayed excerpt is used across both
  testbeds, so its trace-only profile is shared. It is rebuilt from saved
  `ref-pcap/windows.csv` counts and adjusted ground-truth outputs. The raw PCAP
  and original corrected labels remain remote. Rates use 536.870912 ms windows
  and parsed IP packets; the final 204-packet partial reference window is
  omitted. Ground truth uses saved combined-window semantics (1.073741824 s).
- **Figure 9, packet accounting:** whole-run components divided by the explicit
  estimate `delta dev.rx_packets + delta dev.rx_drop`, equal to 78,563,556 in
  each run. The left panel is the complete stack; the right panel magnifies
  only non-counted components on its clearly labelled percentage scale. No
  minimum segment size is imposed. Matching `dev.rx_drop` and
  `ethtool.rx_out_of_buffer` observations are counted once. Independent wire
  arrival totals are unavailable; this is interface-counter accounting.
- **Figure 10, CPU breakdown:** contemporaneous process/host deltas from
  `windows.csv`, expressed as CPU seconds per wall second (cores). The same
  selection rule as the preceding CPU figure identifies both local high-rate
  intervals as 870–1560 s: 30-second traffic bins, longest continuous span at
  least half the recording's 95th-percentile bin rate, with one edge bin
  trimmed on each side. The rest of host is host busy minus process CPU and
  includes unrelated activity. No no-detector baseline is subtracted.
- **Figure 11, classification strips:** saved `outcome_window` values on each
  native trace-time grid, not the alternative window-or-IP prediction. Grey
  denotes exclusions or no aligned windows. Both FABRIC alignments are
  ambiguous (correlations 0.744/0.738 and peak ratios 1.003/1.001), so the plot
  remains provisional. No onset correction or time stretching is applied.

## Main numbers

| Packet accounting | Userspace | Kernel |
| --- | ---: | ---: |
| Counted in windows | 78,455,731 | 78,553,462 |
| Interface drops | 3,251 | 9,689 |
| Socket drops | 104,156 | Not applicable |
| Late drops | 13 | Not applicable |
| Unaccounted / other | 405 | 405 |
| Counted share of defined denominator | 99.86275% | 99.98715% |

Userspace's residual is exactly 405 parser-skipped frames, so residual does
not imply unexplained packet loss. The kernel residual is retained without
assigning a loss cause. Its socket/late categories are structurally
inapplicable rather than missing measurements replaced with zero.

| High-rate CPU, cores | Userspace | Kernel |
| --- | ---: | ---: |
| Detector process | 0.56155 | 0.00433 |
| Rest of host | 0.13273 | 0.27839 |
| Whole host busy | 0.69428 | 0.28272 |

| Saved window outcomes | Userspace | Kernel |
| --- | ---: | ---: |
| TP | 2657 | 2647 |
| TN | 1479 | 1475 |
| FP | 33 | 37 |
| FN | 224 | 234 |
| Total scored | 4393 | 4393 |

These are descriptive measurements of the selected recordings. Different
builds, replay timing and unresolved alignments limit causal interpretation.

## Files and rebuild

Each figure is exported as PNG, vector PDF and SVG, with the same filenames as
the Pi set inside this separate `fabric/` folder. CSVs retain plotted values
and per-window states; JSONs retain formulas, hashes, warnings and provenance.
Keep the folder when copying images into a report to avoid replacing Pi images.
`fabric-figures.tex` supplies a qualified optional fragment; its image paths
assume this folder is copied to `resources/testing-figures/fabric/`.

From the repository root:

```powershell
.\.venv\Scripts\python.exe output/plots/fabric/build_figures.py
```

The script reuses the adjacent Figure 8, 10 and 11 helper calculations. Keep
those source directories in the checkout when rebuilding. It checks raw-run
identity, packet balances, duplicate counter observations, CPU counter sums,
classification totals and exclusion masks. Exported images were visually
inspected. The generated `output/plots/fabric-plots.zip` bundles this folder.
