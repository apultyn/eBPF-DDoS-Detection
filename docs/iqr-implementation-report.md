# IQR Threshold Implementation Report

## Overview

The `userspace/iqr` package implements the interquartile-range (IQR) threshold model used by the baseline DDoS detector. It evaluates both total packet counts for a closed time window and packet counts for individual source IPs represented by `flow.Key`.

The model learns from recent normal-traffic samples. A sample that is flagged malicious is not added to the corresponding history, preventing attack traffic from raising the threshold used by later evaluations.

## Implementation

The implementation is centered on `Detector` in `userspace/iqr/threshold.go` and the bounded `history` type in `userspace/iqr/history.go`. A detector stores:

- One rolling history for total packets per window.
- One rolling history for each tracked source IP, held in a least-recently-used (LRU) cache with a hard cap on the number of addresses.
- One rolling history shared by all source IPs, filled with the counts of every candidate in normal windows.
- A configurable maximum history size with FIFO eviction.
- A mutex protecting all detector and history state.

### Threshold calculation

For a history of normal-traffic samples, `history.threshold` performs these steps:

1. Copies and sorts the samples.
2. Computes the 25th percentile (`Q1`) and 75th percentile (`Q3`) using linear interpolation.
3. Computes the interquartile range, `IQR = Q3 - Q1`.
4. Computes the base threshold as `max(Q3 + IQRMultiplier * IQR, BaseThreshold)`.
5. Adds `OffsetMultiplier * sampleStandardDeviation` to the base threshold.

With `DefaultConfig`, the formula is:

```text
threshold = max(Q3 + 1.5 * IQR, 200) + 2 * sampleStandardDeviation
```

The floor applies to the IQR-based base before the standard-deviation offset is added.

Every verdict reports which term of the `max` was used. `Verdict.FromFloor` is true when `BaseThreshold` was larger than the quartile term, and `Verdict.QuartileBound` carries the value of `Q3 + IQRMultiplier * IQR` whichever term won. Together they show how far the traffic's own statistics lie from the floor, which is what is needed to calibrate `BaseThreshold`.

### Detector construction and configuration

`DefaultConfig` uses the thesis parameters `BaseThreshold = 200`, `IQRMultiplier = 1.5`, and `OffsetMultiplier = 2`. It also supplies package defaults of four minimum samples, a maximum history size of 500, at most 1000 tracked source IPs (`MaxTrackedIPs`), the hybrid IP mode (`IPMode`), and a shared history of 5000 samples (`MaxSharedHistorySize`), which is 500 windows of 10 candidates.

`BaseThreshold` is uncalibrated for this detector. The thesis chose 200 by trial and error for its own dataset and a 1 s window, whereas this detector evaluates combined 1 s values built from 0.5 s windows on different traffic. The value is kept as a parameter and is to be recalibrated from the `FromFloor` and `QuartileBound` fields once the detector has been run on CIC-DDoS2019.

`NewDetector` creates an empty window history, an empty per-IP cache and an empty shared history. `MaxHistorySize` values less than or equal to zero are normalized by `newHistory` to a capacity of one, a `MaxTrackedIPs` of zero selects the default of 1000, and a `MaxSharedHistorySize` of zero selects the default of 5000. A `Config` built by hand without `IPMode` gets `IPModePerIP`, the behaviour before the modes were added. Other configuration values are accepted as provided; callers should configure them deliberately.

### Window evaluation

`EvaluateWindow` compares `WindowStats.TotalPackets` with the current window threshold. While the history has fewer than `MinSamples` entries, it reports a non-malicious verdict with `Verdict.WarmUp` set and adds the sample for warm-up. Once enough samples exist, it adds only samples that do not exceed the threshold.

`WindowStats.WindowStart` is retained as caller metadata but is not used in the threshold calculation. The detector assumes callers evaluate windows in the desired chronological order.

### Per-IP evaluation

`EvaluateIPs` judges all candidate sources of one window in a single call; `EvaluateIP` is the same for a window with one candidate. `Config.IPMode` selects the history each source is judged against:

| Mode | A source is judged against | Warm-up while |
| --- | --- | --- |
| `per-ip` | its own history | its own history has fewer than `MinSamples` samples |
| `shared` | the history shared by all sources | the shared history has fewer than `MinSamples` samples |
| `hybrid` (default) | its own history once that has `MinSamples` samples, the shared history until then | both histories are short |

`Verdict.Shared` reports which history a verdict came from (during warm-up, the one still filling), and `ips.csv` writes it as `threshold_source` (`own` or `shared`).

The hybrid mode exists because of how per-IP warm-up interacts with freezing. A source's own history fills only in windows that are not flagged, so a source first seen during an attack never collects `MinSamples` samples while the attack keeps every window flagged. In `per-ip` mode it therefore stays in warm-up and cannot be flagged for the whole attack, and only the window-level verdict reports the attack. In `hybrid` mode the same source is judged against the shared history from its first window.

The shared mode appears to be what the thesis does: its per-IP endpoint answers a whole list of addresses with a single threshold (§3.2.5.2), and the data pipe publishes one rate limit "for each IP equivalent to the IP threshold" (§3.2.6).

Within one window, every candidate is judged against the shared history as it stood before the window. The window's counts are added to the shared history only after all candidates have been judged, and only if the window is not malicious. The order of the candidates therefore does not change any verdict, and a large count cannot raise the threshold of the candidates judged after it.

In `per-ip` and `hybrid` modes, a source's own history is updated as before: during warm-up and after it, its count is added only when the enclosing window is not malicious.

At most `MaxTrackedIPs` addresses hold a history at any time. Each evaluation moves the address to the front of a recency list; when a new address arrives and the cache is full, the address evaluated least recently is evicted, and its entry and sample buffer are reused for the newcomer. An evicted address that returns starts over with an empty history: in `per-ip` mode with a new warm-up, in `hybrid` mode judged against the shared history until its own has refilled. `shared` mode keeps no per-source histories. `TrackedIPs()` and `EvictedIPs()` report the current number of tracked addresses and the total number of evictions.

When `windowIsMalicious` is true, the IP history is frozen regardless of the individual IP verdict. This prevents traffic from a malicious window from contaminating any per-IP baseline. When the enclosing window is normal, the observed IP count is added after evaluation, including a count that is individually flagged malicious. That behavior matches the package's documented interpretation of the thesis and is an intentional edge-case policy.

## Complexity and memory

For a history containing `n` samples:

- Threshold calculation: `O(n log n)` time because samples are copied and sorted, plus `O(n)` standard-deviation work.
- Evaluation after warm-up: `O(n log n)` time for threshold calculation.
- Adding a sample: `O(1)` normally, or `O(n)` when FIFO eviction shifts a full history.
- Window history memory: `O(MaxHistorySize)` samples.
- Per-IP history memory: bounded by `MaxTrackedIPs * MaxHistorySize` samples of 8 bytes, which is 4 MB with the defaults, regardless of run time or how many distinct addresses are seen. Once the cap is reached, evictions reuse existing buffers and nothing further is allocated.
- Shared history memory: `MaxSharedHistorySize` samples, 40 kB with the default. Its threshold is computed once per window, not once per candidate.
- Cache lookup, promotion, and eviction: `O(1)`.

The detector serializes evaluations with one mutex, so it is safe for concurrent use but concurrent calls do not calculate thresholds in parallel.

## Tests

The test suite is in `userspace/iqr/threshold_test.go` and covers:

- Linear-interpolated percentile calculations.
- Sample standard deviation, including empty and single-value histories.
- FIFO eviction of old samples.
- Default configuration values from the thesis.
- Window warm-up, threshold calculation, attack detection, and rejection of malicious samples from window history.
- Per-IP history freezing during a malicious window.
- Parsing of the IP modes and their defaults.
- In `hybrid` mode, a new source judged against the shared history during an attack, a known source judged against its own, the switch to the source's own history once it is warm, warm-up only while both histories are short, and the fallback to the shared history after eviction.
- In `per-ip` mode, a new source kept in warm-up during an attack.
- In `shared` mode, every source judged against one threshold and no per-source histories kept.
- The shared history learning only after the window, and staying frozen during malicious windows.
- Isolation between different source IP histories.
- LRU eviction of the least recently evaluated address, the hard cap on tracked addresses under a rotating-source attack, and the default cap when `MaxTrackedIPs` is zero.
- Reporting of warm-up at both levels.
- Reporting of whether the floor or the quartile term set the threshold, at both levels.

Run the package tests from the repository root with:

```powershell
go test ./userspace/iqr -v -count=1
```

## Benchmarks

The package currently has no benchmark functions. Performance is dominated by sorting each bounded history during threshold calculation. A benchmark should vary `MinSamples`, `MaxHistorySize`, and the number of tracked IP histories if threshold evaluation becomes a performance-sensitive part of packet processing.

## Limitations and usage considerations

- The first `MinSamples` evaluations are always reported as non-malicious, so callers should choose a warm-up period appropriate for their traffic.
- A malicious window does not update the window history, and `windowIsMalicious` prevents all per-IP histories from updating for that window.
- In `per-ip` mode, a source never seen before cannot be flagged per IP until its own history is past warm-up, and that history only fills in windows that are not flagged. While an attack keeps every window flagged, a new attacking source therefore stays in warm-up, and only the window-level verdict reports the attack. The default `hybrid` mode avoids this by judging such a source against the shared history.
- The shared history is built from the top-K candidates of normal windows, so it describes the heaviest normal sources rather than all of them. A legitimate source that is heavier than the usual candidates (a NAT gateway, a busy server) can be flagged against it until its own history is warm in `hybrid` mode, and always in `shared` mode.
- No mode can flag the sources of a spoofed flood in which every address sends about one packet per window: no individual count stands out. During such a flood the top-K candidates are mostly the normal sources, which outnumber any single spoofed address.
- An address evicted from the cache loses its history and must warm up again if it returns.
- The detector assumes it starts during normal traffic. Samples taken during warm-up are not checked, so starting during an attack poisons the baseline.
- `BaseThreshold` is inherited from the thesis and uncalibrated for this detector; see `Verdict.FromFloor`.
- Threshold calculation allocates a copy of the history for sorting on every evaluated sample.
- Counts are converted from `uint64` to `float64`; extremely large counts can lose integer precision.
- The implementation uses sample standard deviation (`n - 1` denominator), although the thesis does not specify whether sample or population deviation is intended.
- IP parsing and representation are owned by the `flow` package; the detector treats each `flow.Key` as an opaque history key.

## Summary

The `userspace/iqr` package provides a bounded, concurrent rolling-baseline detector for window-level and source-IP-level traffic counts. It combines Tukey-style IQR outlier detection with a configurable base and standard-deviation offset, freezes histories during malicious windows, and avoids allowing flagged window samples to skew future thresholds. Per-IP state is capped by an LRU cache, so memory use is constant. Its main operational considerations are warm-up behavior, the uncalibrated floor, and the cost of sorting histories during evaluation.