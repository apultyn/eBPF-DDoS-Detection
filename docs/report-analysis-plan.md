# Further analysis and figures for the report

This is a plan, not an implementation of aggregation, metric extraction or new experiments. It follows the requested “Further analysis” in `testing-plotting.md` and the research questions and metric definitions in `Final_Report.pdf`, especially sections 1.1, 3.2.4 and 5.1–5.6. The report is source material to reconcile with the measurements; its draft numerical claims are not evidence.

The scripts delivered for the current plotting task inspect individual runs: attack traffic, performance resources, and predicted versus actual accuracy labels. The work below would add validated comparisons, repeated-run summaries and report figures after the data-quality issues have been resolved. Existing local plots remain useful for diagnosis even when a run is unsuitable for a report comparison.

## 1. Freeze the experiment inventory and repair prerequisites

Create a versioned experiment manifest with one row per raw run directory, referring to files without moving or renaming the original data. Discover runs from `run.json`, not solely from directory names. In this checkout the imported data are under `results/results/`; `eval-*` directories are derived outputs and `ref-pcap` is an offline reference, not another live repetition.

Record at least:

| Group | Required manifest fields and sources |
| --- | --- |
| Identity | Unique run ID, relative raw directory, testbed, repetition/block ID, timestamp, scenario, inclusion status and reason |
| Implementation | `run.json.source` (`live` for user space, `xdp` for kernel), `config.block`, requested and verified actual XDP attachment mode, interface, seed, full detector configuration |
| Provenance | Commit, `version.modified`, archived source diff or source-tree hash, binary/BPF-object hashes, kernel, CPU/core count, RAM, driver, offload settings, monitoring command and sampling interval |
| Traffic | Excerpt and PCAP hashes, label-file and label-conversion metadata hashes, day, UTC trace start/end, packet/byte counts, replay command/rate and sender output, clock/replay-start observations |
| Execution | `started_at`, `finished_at`, `end_reason`, actual capture coverage, readiness procedure, complete/missing files |
| Evaluation | Reference hash, evaluator revision/options, offset method and diagnostics, excluded-window counts, scored coverage, warnings and acceptance decision |

Use an explicit matrix rather than inferring the whole study from eight scenario names:

| Testbed | XDP mode | User-space accuracy | Kernel accuracy | User-space performance | Kernel performance |
| --- | --- | --- | --- | --- | --- |
| FABRIC | Generic | planned paired repetitions | planned paired repetitions | planned paired repetitions | planned paired repetitions |
| FABRIC | Native | planned paired repetitions | planned paired repetitions | planned paired repetitions | planned paired repetitions |
| Raspberry Pi 400 | Generic | collect or identify separate evidence | collect or identify separate evidence | collect or identify separate evidence | collect or identify separate evidence |

Raspberry Pi native mode is outside the documented testbed's capabilities. Confirm the testbed from recorded evidence before assigning imported runs to FABRIC; `enp7s0` and a directory suffix are not a full hardware record. Plot missing cells as unavailable. Do not invent Pi results from the current import.

Current import issues to resolve before claiming a completed matrix:

- The scenarios have two repetitions, but `ker-acc-per-1` is actually a blocking-enabled performance run (`source=xdp`, `config.block=true`). Record its intended generic mode only after finding attachment evidence; preserve its original name in the manifest.
- Several different commits are present, and runs report modified source trees. Compare the actual diffs/build artifacts before treating them as equivalent repetitions. A commit ID alone cannot reconstruct a dirty build. If the source snapshots cannot be recovered, show the old measurements separately and rerun a frozen revision for the main comparison.
- Sender `tcpreplay.txt`, authoritative attachment metadata, and the original excerpt/label provenance must be retained with future runs. Current evaluation JSON embeds excerpt information but is not a replacement for the original PCAP and metadata.
- Some first runs ended through interruption. Verify that the replay and required analysis interval were fully captured before deciding whether to include them; an interrupted tail is not automatically a failed experiment or automatically complete.

**Gate A:** every included run has an unambiguous scenario, recoverable configuration, documented traffic and a common comparison interval. Missing provenance is visible in the manifest and report.

## 2. Validate replay timing and label alignment before scoring comparisons

The present eight accuracy evaluations all warn about alignment: correlations are approximately 0.74 and best/next peak ratios approximately 1.00, below the existing `analysis.alignment` checks of 0.9 and 1.2. An offset can always be returned by a search; that does not validate the correspondence with ground truth. Keep the current scores and label timelines marked provisional.

The audit also finds that the interval containing 1–99% of packet mass is about 1,491–1,496 s in live accuracy runs versus about 1,246 s in the reference. Early cumulative-packet quantiles suggest still greater stretch. This is evidence of a traffic-shape/timing mismatch to investigate, not proof of a specific replay configuration. Nearly matching total packet counts cannot establish original-rate replay or correct timing.

Plan the checks in this order:

1. Recover the exact PCAP/excerpt metadata and sender command/output for every run. Verify reference and live traffic identity, original-rate replay, timestamp rewriting, packet types, replay duration and start/stop coverage. Compare the report's stated 14:21:52–15:03:06 interval with the evaluated excerpt's 14:21:52.153161–15:01:51.999846 UTC; choose and document the actual interval.
2. Compare reference/live packet-rate traces and cumulative-packet quantiles across the full replay, including the leading and trailing periods. Check several independent features or landmarks, not just the largest plateau. Inspect the PCAP for gaps and any early attack relative to labels.
3. Test whether one constant clock offset actually fits the whole trace. Plot residual landmark timing versus elapsed time. A trend or changing slope indicates timing distortion that a constant shift cannot correct. Do not choose an offset to maximize accuracy.
4. Prefer reruns with per-run readiness synchronization, saved replay logs and a frozen replay command when timing is distorted. A fitted scale or piecewise time map would need independently observed replay/packet landmarks and an explicit validation method; it must not silently change the existing original-rate experiment or be fitted against detector flags. Present any such salvage as a separately described exploratory analysis.
5. Once timing passes, rerun the existing `analysis.evaluate` on each accuracy run with the same labels, excerpt, reference and warm-up settings. Save all outputs and warnings. Use `analysis.compare` for the existing per-run side-by-side table; it does not perform repeated-run inference.
6. For head-to-head accuracy, verify the same trace coverage, effective window span and warm-up policy. Native window boundaries can differ. Preserve the native-window scores and disclose denominator differences; if a shared-grid sensitivity analysis is added later, define its truth and prediction mapping beforehand and report it separately.

The physical window is 536.870912 ms; combined mode judges the current and preceding windows, a 1.073741824 s span. Preserve this overlap in ground-truth labeling. The evaluator's 75-window exclusion is distinct from the detector's `warm_up` flag and four-history-sample minimum. Record the actual elapsed warm-up time and require benign startup if that is an experimental premise; do not label a startup benign solely because few packets were sent.

**Gate B:** alignment passes the existing correlation and peak-ratio checks, replay-rate and landmark checks agree, and the scored interval has documented label coverage. Passing correlation alone is insufficient. Unresolved failures permit diagnostic figures and exploratory results, not a definitive detection-quality comparison.

## 3. Define each reported quantity before extracting it

### Packet accounting and unintended loss

Separate intentional blocking from unintended loss. For blocking-enabled runs, a large reduction in `stats.packets` is expected because blocked traffic is not counted in the detector's packet/byte windows. It must not be reported as detector packet loss.

Build an accounting table with packet counts and denominators for each observed stage:

| Stage | Available source | Planned interpretation |
| --- | --- | --- |
| Sender attempted/successful/failed | Parsed `tcpreplay.txt`: `actual_packets`, `successful`, `failed`, `truncated`, retry counts, `actual_seconds` | Sender-side delivery evidence; preserve failures/retries separately |
| NIC | `run.json.live.nic_delta`, including `dev.rx_packets`, `dev.rx_drop`, applicable driver counters | Receiver-side evidence; document driver/XDP-mode counter semantics and background traffic |
| XDP blocked | Per-window `blocked_packets`, `blocked_bytes`; run `stats.blocked_packets` | Intentional policy drops, reported as count and share of the appropriate received population |
| AF_PACKET socket (user space) | `live.socket.kernel_total`, `kernel_dropped`, kernel/fallback timestamp counters | Capture offered/dropped counts; compute socket drop fraction using this socket's offered count |
| Detector | Per-window `packets`, `bytes`; `stats.packets`; late/discarded/skipped statistics | Successfully counted post-block traffic, with final partial-window treatment recorded |
| Reference expectation | Validated, aligned `ref-pcap/windows.csv` integrated over the same interval | Expected IP packets for a restricted interval, with interpolation/boundary limitations |

For a common interval and comparable counters, report unintended missing fraction as `1 - (observed post-block packets + intentional blocked packets) / expected incoming packets`. For accuracy runs blocked is zero. Do not directly subtract counters over different intervals or frame/IP populations. `dev.rx_packets` may already be downstream of an XDP decision depending on driver/mode; do not assume NIC and block counts can always be added. First establish each counter's position and whether driver-specific totals overlap.

Existing `metrics.json.run.losses.window_loss` is `1 - observed / expected` over raw windows wholly inside the excerpt. This is not necessarily the same set as the scored windows: it does not apply all scoring exclusions. Retain its exact definition, and define a separate loss over the common scored/phase interval if needed. It depends on validated timing and cannot currently repair the ambiguous alignments. Preserve negative residuals for investigation rather than clipping them to zero.

Current imports lack sender logs, so complete sender-to-detector loss and replay-rate claims are unavailable. NIC/socket counters can still support qualified local accounting. Future runs should also record pre-block ingress totals at an equivalent observation point if available counters cannot close the balance.

### Decision delay, processing time, block update delay and attack latency

Keep these four measurements distinct:

| Measurement | Definition and unit | Population and limitation |
| --- | --- | --- |
| Decision delay | `(eval_end_ns - end_ns) / 1e6`, ms | Evaluated windows; includes scheduling, boundary grace/wait, map reads and verdict computation |
| Evaluation processing time | `(eval_end_ns - eval_start_ns) / 1e6`, ms | Evaluated windows; useful for explaining decision delay, not per-packet latency |
| Block update delay | `(blocked_at_ns - end_ns) / 1e6`, ms | Only rows with a block update; summarize update coverage as well as delay. This timestamps the update, not the first observed dropped packet |
| Attack detection latency | Existing `latency.csv.latency_s`: first flagged `end_ns` minus label onset, seconds | Only attacks whose onset and subsequent scored observation are covered and whose alignment is valid |

Check timestamp order and clock domain before computing differences. Kernel `run.json.notes` states that its TAI window boundaries are converted to wall time; keep raw integers until subtraction. If needed, a separately named “verdict available after attack onset” latency can use aligned `eval_end_ns`, but it differs from the existing end-of-window latency and should not replace it without a methods change.

The evaluator currently emits one row per **attack label**, using the first occurrence in the day's labels and merging that label's coverage. Do not call these independent attack episodes. NTP starts before this excerpt: its roughly 4,030 s reported onset latency is left-censored and does not measure response to a newly starting attack in the run. Record it as “ongoing at excerpt start; onset not observed.” DNS onset is within the excerpt, but its current sub-second estimate is provisional because alignment fails. Ten other labels have no scored coverage; `attacks_detected=2` out of `attacks_total=12` is not a 2/12 success rate. Show covered labels, onset-covered labels, missed labels and uncovered labels separately.

For a later episode-level extension, define disjoint attack episodes, onset coverage, overlap between labels and end-of-observation censoring before extraction. Never replace missed/not-covered/left-censored values with zero delay or exclude them silently from a latency claim.

### Traffic rate and throughput

Derive rates from non-overlapping raw windows, with `duration_s = (end_ns - start_ns) / 1e9`. Use `packets / duration_s` (packets/s), `bytes / 1e6` (MB per window), `bytes / duration_s / 1e6` (MB/s), and `8 * bytes / duration_s / 1e6` (Mbit/s). Bytes are the detector's counted bytes, not automatically Ethernet wire bytes. Do not sum `evaluated_packets` in combined mode: adjacent evaluations overlap.

Show post-block counted, intentionally blocked, and their sum only where measured at compatible stages. For kernel runs `packets + blocked_packets` describes traffic observed by the counting/blocking path. For user-space runs `packets` is after AF_PACKET capture and can miss socket drops, so this sum is a partial observation unless loss is included. The sender/reference trace is the offered workload, not an inferred live incoming-rate measurement.

At a fixed original replay rate these measurements show observed packet processing and filtering under that workload. They do not measure maximum sustainable throughput or legitimate application goodput. Blocking intentionally reduces forwarded traffic. Claims about higher service availability need a separate benign client/application probe; maximum-rate sweeps are outside the current report scope unless the experimental design is explicitly expanded. If no such experiment is planned, rename the draft throughput results to traffic rate/packet accounting and limit the claim accordingly.

### CPU and memory

- Use whole-machine CPU from `cpu.csv`: `100 * sum(host_busy_ns) / sum(host_total_ns)` for the included intervals. Softirq uses the same total denominator; report `host_max_core_share` separately to expose one saturated core. An average of percentages is only equivalent for equal denominators. `/proc/stat` measurements are coarse at short intervals, so use weighted interval summaries and show the sampling resolution.
- `windows.csv.cpu_share` and process user/system times cover only the user-space process, where `1.0` is one fully busy core. They exclude XDP's per-packet work. Treat them as supporting diagnostics and never compare kernel/user-space offload costs using process CPU alone.
- Compare total host CPU under controlled conditions. A future same-traffic no-detector baseline can estimate incremental overhead; without that baseline, label values as whole-host utilization rather than detector-only CPU.
- In these imports `memory.csv.main` is `anon + kernel + sock`, with BPF maps charged outside the monitored detector cgroup. For total detector memory use `main + run.json.bpf_memory.total_bytes` for **both** implementations, including the user-space XDP blocklist. Check cgroup ownership in each future setup to avoid adding maps twice. Show map bytes separately, along with cgroup `current` as a different measurement; overlapping `memory.stat` components must not be stacked or summed arbitrarily.
- Use MiB (`bytes / 2^20`) for memory and label it explicitly. Summarize time-weighted typical memory, peak within the common analysis interval, and BPF-map bytes per run. A whole-run `memory_summary.json` peak can include setup, idle tail or a different capture length; recompute the comparison interval later rather than treating it as automatically comparable. Program/JIT memory is not included in the recorded map total; document that boundary.

**Gate C:** metric names, formulas, units, populations and missing-value handling are fixed, and accounting reconciles within explained boundary/background differences. No whole-system claim rests only on process measurements or post-block detector counts.

## 4. Aggregate repetitions without treating windows as independent experiments

Use the replay/run as the experimental unit. Thousands of windows and 0.5 s resource samples are correlated observations within a run, especially with overlapping combined windows. They are not thousands of independent repetitions.

For the next collection, freeze a complete configuration/revision and collect a third or more **complete matched blocks**: each block contains the four implementation/XDP combinations for each purpose on the same testbed and excerpt. Alternate or randomize ordering across blocks, record the order, use a fresh detector state, and synchronize each replay individually. Start a new repetition group if the code, hardware or replay changes. Do not automatically pair current directories by `-1`/`-2` suffix without checking their experimental history.

Within each accepted run:

1. Restrict to a validated common trace interval; report capture tails separately. Define benign/heavy-attack/slow-attack phases from labels/reference independently of predictions, and only after verifying that those phases actually exist in the excerpt.
2. Compute one summary per run and phase: weighted CPU, typical and peak total memory, packet accounting/rates, decision-delay median/p95/max, and latency/status per covered onset. For short phases disclose the number of windows and percentile limitations.
3. Keep native-window TP/FP/TN/FN and compute accuracy, precision, recall, F1 and FPR per run. Keep `prediction=window` primary, `window_or_ip` as a named sensitivity analysis; do not count both rows as repetitions. Preserve undefined denominators as missing, not zero.

Across runs within each fixed testbed/mode/purpose/excerpt/configuration cohort, show every run as a point and report the number of accepted runs. With two runs, use their mean and range as a descriptive summary. With three, retain the raw points and range; a standard deviation may describe repetition spread, but neither a normal approximation nor a tiny bootstrap makes that sample strong evidence of significance.

Primary comparisons should be paired kernel-minus-user-space differences within a verified block and fixed XDP mode. Native-minus-generic comparisons are a separate contrast within implementation and testbed. Do not combine hardware and XDP effects into one average. Report absolute differences first (CPU percentage points, MiB, ms, packets/s); where meaningful also report per-block relative change `100 * (kernel - user) / user`. A zero or undefined baseline makes relative change unavailable. State the sign convention, metric and aggregation rule rather than averaging incompatible percentage gains into a single “improvement.”

For quality metrics, use the distribution of per-run scores as the repetition result. A pooled confusion matrix can be supplementary and must be labeled as a window-weighted descriptive total; pooling repeated replays weights the same labeled traffic repeatedly and does not increase the independent dataset size. Per-attack breakdowns remain descriptive where there are only one or two covered labels. Statistical equivalence needs a predeclared practical tolerance and sufficient independent runs/traffic; similar point estimates or a non-significant test do not prove equivalence.

For summary time-series figures, align accepted runs in trace elapsed time and rebin counts by interval overlap, preserving packet and byte totals. Use the same fixed bin edges for all compared runs. Compute rates after rebinning, weight resource samples by covered duration, leave genuine gaps missing, and show the number of contributing runs. Show mean with min–max spread for the small current sample rather than a confidence ribbon. An alignment-derived view of blocking runs needs an independent ingress/sender timeline: do not align solely on `packets`, whose shape changes when blocking succeeds.

**Gate D:** all accepted repetitions remain visible, pairing is justified, and uncertainty reflects independent runs rather than sample/window count. If only the current mixed-revision observations are available, report exploratory comparisons without causal or equivalence claims.

## 5. Map evidence to report tables and figures

| Report location | Planned table/figure | Data and required qualification |
| --- | --- | --- |
| 3.2.1–3.3 and appendices C/D | Testbed/configuration table; completed scenario matrix; excerpt timeline and replay/QC table | Manifest, hardware/attachment evidence, excerpt/labels, sender logs; actual dates/time zone, repetition counts, exclusions and revisions |
| 5.1 Memory | Paired run points for typical and peak total memory; one aligned memory timeline per mode/testbed; map-memory breakdown table | Blocking performance cohorts; include map charges consistently and state memory boundary |
| 5.2 CPU | Paired weighted whole-host CPU and softirq; aligned CPU timeline; busiest-core panel | Same performance intervals; distinguish fraction of all cores from fraction of one core |
| 5.3 Packet loss and traffic rate (revise current throughput framing) | Packet-path accounting table; offered/count/blocked traffic timeline; local-loss fractions with denominators | Sender/reference/NIC/socket/block counters; mark unavailable sender stages and avoid goodput/capacity claims |
| 5.4 Decision delay and detection latency | Per-run decision-delay median/p95 points and empirical CDF; separate onset/status table for attack latency | Raw `eval_*` and `end_ns` for decision delay; validated `latency.csv` for onset latency; exclude left-censored onset from latency averages and show its status |
| 5.5 Detection quality (expand Accuracy & Recall) | TP/FP/TN/FN and accuracy/precision/recall/F1/FPR table; run points; one representative truth/prediction timeline; covered-label breakdown | Accepted blocking-off accuracy cohorts; primary `window` prediction, attack prevalence and coverage shown; representative run selected by a stated rule rather than best score |
| 5.6 Summary and reliability | Paired absolute effect points with raw repetitions; acceptance/missingness/provenance table | Separate testbeds/modes and performance versus accuracy cohorts; no single average across unrelated quantities |

Use consistent scenario colors, units, trace elapsed axes and attack-phase markers across figures. Retain per-run diagnostic plots in an appendix or linked archive; the report should use a small number of comparisons that answer the two research questions. Export vector PDF/SVG for line/table figures and high-resolution PNG when needed, with the generating configuration and exact input manifest saved alongside them.

## 6. Reconcile the draft before writing conclusions

The attached PDF is internally inconsistent and should be corrected after the validated extraction, not copied into new figures:

- Sections 1 and 3 describe CIC-DDoS2019 at original rate; chapter 5 and figures 8–18 claim six datasets. Keep only measured datasets and testbeds. The current import does not substantiate six-dataset results or a Raspberry Pi comparison.
- Section 3.3's excerpt end differs from the excerpt embedded in current evaluation JSON. State the exact checked PCAP interval, UTC convention and label offset, and whether an attack was already in progress. Fill the hardware and sender placeholders from evidence.
- The abstract, chapter 5 and conclusion contain unsupported or placeholder numerical improvements, including inconsistent percentages. Replace them with accepted measurements and clearly defined denominators, or leave the claims pending. The draft claim of “statistically insignificant” quality differences has no demonstrated design/test in the current results.
- Sections 3.2.4 and 5.4/conclusion mix decision delay, attack-detection latency and per-packet processing latency. Use the distinct definitions above; current window timestamps cannot measure per-packet latency.
- Methodology measures performance with blocking on and quality with blocking off. Keep those comparisons separate. Explain that performance combines counting placement with the resulting blocking behavior; different residual traffic can affect CPU/memory, and is not solely a per-packet implementation cost.
- Section 6.4 says FABRIC uses native mode, whereas the experiment procedure includes generic and native. Reflect the actual accepted matrix, and avoid attributing differences across testbeds to hardware alone.

## 7. Proposed implementation sequence and completion criteria

1. **Inventory and repeatability:** create the manifest and acceptance ledger, recover missing provenance, freeze code and traffic, settle cohort/pairing rules. Deliver a visible list of accepted, exploratory and excluded runs with reasons.
2. **Timing and coverage:** resolve replay/reference mismatch, verify labels and startup conditions, and recollect synchronized runs where necessary. Deliver a QC table and landmark/residual plots; no final quality score proceeds without Gate B.
3. **Metric extraction:** implement a later extraction layer that reuses the existing evaluator/parser, emits per-run/per-phase tidy tables and preserves counters/statuses. Validate invariants on hand-checked intervals: confusion totals equal scored windows, block plus passed accounting is explained, durations are positive, timestamp order is sensible, resource weights and unit conversions match raw examples. Keep this extraction separate from figure rendering.
4. **Repeated-run comparison:** produce paired tables and points with the small-sample rules above; add an explicit inclusion ledger and sensitivity analyses for supported timing/coverage choices. Deliver tables whose every row links to raw runs and the configuration used.
5. **Report figures and editing:** generate only the accepted evidence mapped to sections 5.1–5.6, then replace draft claims and captions consistently. A single documented command should later rebuild tables and figures from the frozen manifest without editing the raw results. Record tool versions, source revision and output hashes.

Completion means that every report number traces to an accepted cohort and explicit formula, every comparison states its independent run count and coverage, all plots use documented units, and missing evidence appears as unavailable rather than an inferred result. Additional datasets, application-goodput experiments, maximum-load sweeps or new detector calibration belong to an explicitly expanded experiment plan; they are not necessary to plot or summarize the existing original-rate runs.
