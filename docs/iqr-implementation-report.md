# IQR Threshold Implementation Report

## Overview

The `userspace/iqr` package implements the interquartile-range (IQR) threshold model used by the baseline DDoS detector. It evaluates both total packet counts for a closed time window and packet counts for individual source IPs.

The model learns from recent normal-traffic samples. A sample that is flagged malicious is not added to the corresponding history, preventing attack traffic from raising the threshold used by later evaluations.

## Implementation

The implementation is centered on `Detector` in `userspace/iqr/threshold.go` and the bounded `history` type in `userspace/iqr/history.go`. A detector stores:

- One rolling history for total packets per window.
- One rolling history for each source IP.
- A configurable maximum history size with FIFO eviction.
- A mutex protecting all detector and history state.

### Threshold calculation

For a history of normal-traffic samples, `history.threshold` performs these steps:

1. Copies and sorts the samples.
2. Computes the 25th percentile (`Q1`) and 75th percentile (`Q3`) using linear interpolation.
3. Computes the interquartile range, `IQR = Q3 - Q1`.
4. Computes the base threshold as `max(Q3 + IQRMultiplier * IQR, FloorValue)`.
5. Adds `OffsetMultiplier * sampleStandardDeviation` to the base threshold.

With `DefaultConfig`, the formula is:

```text
threshold = max(Q3 + 1.5 * IQR, 200) + 2 * sampleStandardDeviation
```

The floor applies to the IQR-based base before the standard-deviation offset is added.

### Detector construction and configuration

`DefaultConfig` uses the thesis parameters `FloorValue = 200`, `IQRMultiplier = 1.5`, and `OffsetMultiplier = 2`. It also supplies package defaults of four minimum samples and a maximum history size of 500.

`NewDetector` creates an empty window history and an initially empty map of per-IP histories. `MaxHistorySize` values less than or equal to zero are normalized by `newHistory` to a capacity of one. Other configuration values are accepted as provided; callers should configure them deliberately.

### Window evaluation

`EvaluateWindow` compares `WindowStats.TotalPackets` with the current window threshold. While the history has fewer than `MinSamples` entries, it reports a non-malicious verdict and adds the sample for warm-up. Once enough samples exist, it adds only samples that do not exceed the threshold.

`WindowStats.WindowStart` is retained as caller metadata but is not used in the threshold calculation. The detector assumes callers evaluate windows in the desired chronological order.

### Per-IP evaluation

`EvaluateIP` creates a separate history for each IP. During warm-up, samples are added only when the enclosing window is not malicious. After warm-up, the IP count is compared with that IP's threshold.

When `windowIsMalicious` is true, the IP history is frozen regardless of the individual IP verdict. This prevents traffic from a malicious window from contaminating any per-IP baseline. When the enclosing window is normal, the observed IP count is added after evaluation, including a count that is individually flagged malicious. That behavior matches the package's documented interpretation of the thesis and is an intentional edge-case policy.

## Complexity and memory

For a history containing `n` samples:

- Threshold calculation: `O(n log n)` time because samples are copied and sorted, plus `O(n)` standard-deviation work.
- Evaluation after warm-up: `O(n log n)` time for threshold calculation.
- Adding a sample: `O(1)` normally, or `O(n)` when FIFO eviction shifts a full history.
- Window history memory: `O(MaxHistorySize)` samples.
- Per-IP history memory: `O(numberOfIPs * MaxHistorySize)` in the worst case, because histories remain in the IP map after creation.

The detector serializes evaluations with one mutex, so it is safe for concurrent use but concurrent calls do not calculate thresholds in parallel.

## Tests

The test suite is in `userspace/iqr/threshold_test.go` and covers:

- Linear-interpolated percentile calculations.
- Sample standard deviation, including empty and single-value histories.
- FIFO eviction of old samples.
- Default configuration values from the thesis.
- Window warm-up, threshold calculation, attack detection, and rejection of malicious samples from window history.
- Per-IP history freezing during a malicious window.
- Isolation between different source IP histories.

Run the package tests from the repository root with:

```powershell
go test ./userspace/iqr -v -count=1
```

## Benchmarks

The package currently has no benchmark functions. Performance is dominated by sorting each bounded history during threshold calculation. A benchmark should vary `MinSamples`, `MaxHistorySize`, and the number of tracked IP histories if threshold evaluation becomes a performance-sensitive part of packet processing.

## Limitations and usage considerations

- The first `MinSamples` evaluations are always reported as non-malicious, so callers should choose a warm-up period appropriate for their traffic.
- A malicious window does not update the window history, and `windowIsMalicious` prevents all per-IP histories from updating for that window.
- Per-IP histories are retained in the map indefinitely. Long-running deployments with many distinct source IPs may need an explicit expiration policy outside this package.
- Threshold calculation allocates a copy of the history for sorting on every evaluated sample.
- Counts are converted from `uint64` to `float64`; extremely large counts can lose integer precision.
- The implementation uses sample standard deviation (`n - 1` denominator), although the thesis does not specify whether sample or population deviation is intended.
- The detector does not validate IP string syntax; the IP value is treated as an opaque history key.

## Summary

The `userspace/iqr` package provides a bounded, concurrent rolling-baseline detector for window-level and source-IP-level traffic counts. It combines Tukey-style IQR outlier detection with a configurable floor and standard-deviation offset, freezes histories during malicious windows, and avoids allowing flagged window samples to skew future thresholds. Its main operational considerations are warm-up behavior, retained per-IP state, and the cost of sorting histories during evaluation.