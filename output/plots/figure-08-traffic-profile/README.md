# Figure 8: excerpt traffic profile and corrected-label ground truth

This figure uses existing derived data. The original PCAP and corrected flow
labels remain on the FABRIC/Raspberry Pi experiment machines, as confirmed by
the user. No large file transfer is necessary for this saved-output version.

## Inputs

- Packet counts and trace-time boundaries:
  `results/data-fabric/ref-pcap/windows.csv`, with its adjacent `run.json`.
  The manifest records offline `source=pcap` processing of `01-12.pcap`.
- Corrected-label window truth:
  `results/data-fabric/eval-usr-acc-gen-1-adjusted/windows.csv`, column `truth`,
  with `attack_labels` and adjacent `metrics.json`.
- Excerpt first/last packet times from the saved evaluation metadata:
  2018-12-01 14:21:52.153161–15:01:51.999846 UTC.

The upper curve uses the offline reference only, never live received counts,
processing speed, detector verdicts, or correlations. Its rate is
`packets / ((end_ns - start_ns) / 1e9)` for each 536.870912 ms trace window,
without smoothing or time stretching. Counts include successfully parsed
IPv4/IPv6 packets; they are not counts of every Ethernet frame.

There are 4,471 completed reference windows, containing 78,567,550 IP packets.
The manifest reports another 204 IP packets in the omitted final partial
window. Their absence from the curve covers only the last approximately
0.0313 seconds; no zero rate is fabricated there. The PCAP reader also reports
1,838 skipped frames, which are outside the displayed IP rate. The first
epoch-aligned window starts before the first excerpt packet: its rate uses
the original full-window denominator and is clipped visually at trace start.

## Ground-truth semantics

The strip uses the saved adjusted evaluation's existing trace-time grid and
preserves all `truth` values inside the excerpt. A window is attack-labelled
when a corrected attack-flow interval overlaps its effective evaluation span.
This evaluation uses **combined mode**, so each 536.870912 ms current-window
bin has truth determined over the current and previous window, a
1.073741824 s span. The strip is drawn over current-window bins, as in the
evaluation. It is not recomputed or resampled onto the reference grid.

The saved strip changes from benign to `DrDoS_DNS` at elapsed
852.821042456 s, approximately 14.214 minutes. Attack-labelled windows extend
through the lower-rate tail to the excerpt end. These values come from the
label-derived `truth` field, independently of the packet rate and detector
prediction columns. Adjacent identical window states are merged only for
rendering; the CSV retains every window and its effective span.

Warm-up/scoring exclusions do not hide ground truth: they concern evaluation
of a detector, not the availability of trace labels. The existing saved live
alignment warnings are not repaired here, and the figure does not compare
live predictions or live packet timing with ground truth.

## Rebuild and outputs

From the repository root:

```powershell
.\.venv\Scripts\python.exe output/plots/figure-08-traffic-profile/build_figure.py
```

- `figure-08-traffic-profile.png`, `.pdf`, `.svg`: figure exports.
- `figure-08-packet-rate.csv`: original reference-window counts, boundaries, and rates.
- `figure-08-ground-truth.csv`: saved label truth, effective spans, and clipped plot bounds.
- `figure-08-evidence.json`: provenance, hashes, accounting checks, and limitations.
- `figure-08-caption.tex`: caption/figure fragment for the report.

The build checks contiguous window grids, exact integer timestamps, disabled
blocking, zero skipped epochs/late packets, reference packet accounting,
excerpt identity, full ground-truth coverage, expected combined spans, and
the saved evaluation's identity against its original raw run.

## What an independent rebuild would require

The PCAP and original corrected flow-label file were not independently read
for this figure; the saved evaluation does not retain a hash of its label input.
To regenerate both series on one exact window grid, use the remote originals
or provide a small export containing:

1. Exact trace-window `start_ns`, `end_ns`, packet counts, and packet inclusion rules.
2. Corrected flow interval start/end timestamps, labels and benign/attack flags,
   plus timestamp correction/UTC conversion metadata; alternatively export
   window-level truth on the same grid and state its overlap rule.
3. Excerpt metadata and source hashes tying the export to the replayed PCAP.

Both raw files may remain remote if those derived tables are exported there.
