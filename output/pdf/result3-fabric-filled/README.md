# result3.tex with FABRIC results filled

`result3.tex` is a completed workspace copy of the supplied fragment. The
original in Downloads was not overwritten. `main.tex` is a standalone preview
wrapper; all referenced images are included under `resources/testing-figures/`.

## Filled material

- All six FABRIC paragraphs: coverage, packet accounting, CPU, detection,
  blocking, and memory/local decision delay.
- Four FABRIC run rows, using `usr/ker-acc-gen-1` for blocking off and
  `usr/ker-per-gen-1` for blocking on.
- Seven FABRIC tables and three figure references with distinct labels.
- All eight FABRIC summary-column entries, with an explicit provisional
  qualification for alignment-dependent scores.

The Raspberry Pi numerical tables and interpretation were retained. Other
original placeholders (Pi attack-source identities, the literature comparison,
and final RQ discussion) remain outside the FABRIC additions. Blocked-source
attack identity is explicitly unavailable in the FABRIC table: the saved
per-window ground truth lacks the per-flow IP labels needed to verify it.

## Methods and checks

`extract_evidence.py` records source hashes, configurations, counter balances,
full metrics, phase populations, timing distributions, and memory accounting
in `fabric-evidence.json`. `fill_report.py` verifies those hashes and fills
the fragment reproducibly. No raw data or saved evaluations are modified.

To match the source's Pi method, FABRIC flood summaries use the centred median
of nine counted windows exceeding 10,000 packets. The first and last qualifying
window starts are half-open phase cutpoints; every scored FABRIC window belongs
to exactly one phase. Blocking-run phase selection adds blocked traffic and
available socket drops. Phase origin is the first recorded window, not process
launch. CPU percentages use ratios of counter sums, not means of rounded shares.

For document consistency, this copy also:

- Removes the visible introductory planning bullets.
- Corrects the shared trace's high-rate duration from approximately 11 to
  approximately 8 minutes (reference nine-window flood span: 489.1 seconds).
- Qualifies the shared plot as saved offline-PCAP-reference counts and
  saved corrected-label truth, not newly reprocessed remote inputs.
- Clarifies the Pi phase-time origin without changing its numerical table.
- Renders separate Pi and FABRIC CPU stacks over each table's broad flood
  definition. This replaces the older combined-testbed CPU image and the
  earlier interior-phase FABRIC plot inside this report copy only.

Block events count new admissions (47/46), separately from refreshes (23/29);
successful per-IP updates are their sums (70/75). Both FABRIC blocking manifests
record a 60-second TTL. Memory adds separately charged maps once. Timing is
measured on evaluated, detector-warm-up-free windows, distinct from the
75-window accuracy-scoring exclusion.

The source Pi phase-rate table omits one boundary window per implementation
when its three populations are summed. Its existing figures/text were not
used as numerical evidence for FABRIC; the FABRIC phase populations partition
all scored windows exactly. Saved alignment warnings and differing modified
builds remain visible in the FABRIC text. Physical-wire arrival totals and
malicious identities of blocked IPs are not invented.

## Rebuild

From the repository root:

```powershell
.\.venv\Scripts\python.exe output/pdf/result3-fabric-filled/extract_evidence.py
.\.venv\Scripts\python.exe output/pdf/result3-fabric-filled/fill_report.py
```

Compile `main.tex` twice with pdfLaTeX or open the project in the Codex LaTeX
editor. The standalone `main.pdf` is the preview. Copy `result3.tex` and its
`resources/` subtree together when integrating into the full report. Figure
and table numbers are assigned by the surrounding report's counters.
