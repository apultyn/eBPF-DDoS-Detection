# Count-Min Sketch Implementation Report

## Overview

The `userspace/countmin` package implements a Count-Min Sketch for estimating the frequency of string keys, such as source IP addresses observed in a network stream. It is intended for userspace DDoS detection and supports constant-size updates and queries relative to the number of distinct keys.

A Count-Min Sketch never underestimates the true frequency of a key. Hash collisions can cause an estimate to be higher than the true frequency.

## Implementation

The implementation is centered on the `Sketch` type in `userspace/countmin/sketch.go`. It stores:

- `width` counters per row.
- `depth` independent rows.
- A `uint64` counter matrix.
- One `maphash.Seed` per row.
- A running `total` of all deltas passed to `Add`.

### Construction

`New(epsilon, delta)` derives the matrix dimensions from the standard Count-Min Sketch parameters:

- `width = ceil(e / epsilon)`
- `depth = ceil(ln(1 / delta))`

`epsilon` controls the allowed error relative to the total stream count. Smaller values use more memory and improve accuracy. `delta` controls the probability that the error bound is exceeded. Smaller values increase confidence and require more rows.

Invalid values are rejected when `epsilon` or `delta` is less than or equal to zero, or greater than or equal to one.

`NewWithDimensions(width, depth)` is provided for tests and callers that want to select the matrix dimensions directly. Zero dimensions are normalized to one so that the resulting sketch remains usable.

### Updating counts

`Add(key, delta)` hashes the key once per row using that row's independent `maphash` seed. The corresponding counter in every row is incremented by `delta`, and `total` is incremented by the same amount.

Because every row receives the key's contribution, collisions can only increase counters associated with that key. This is the property that prevents undercounting.

### Estimating counts

`Estimate(key)` hashes the key in each row and returns the smallest counter found. The minimum reduces the effect of collisions: a collision must affect every row to increase the final estimate.

For a zero-depth sketch, `Estimate` returns zero defensively. The documented construction functions always create at least one row.

### Reset and inspection

`Reset()` clears all counters and the running total without reallocating the matrix. `Total()`, `Width()`, and `Depth()` expose the corresponding sketch metadata.

The zero value of `Sketch` is not a valid initialized sketch. Callers should use `New` or `NewWithDimensions`.

## Complexity and memory

For a sketch with width `w` and depth `d`:

- `Add`: `O(d)` time.
- `Estimate`: `O(d)` time.
- `Reset`: `O(w * d)` time.
- Memory: `O(w * d)` counters plus `O(d)` hash seeds.

The cost of an update or estimate does not depend on the number of distinct keys in the stream.

## Tests

The test suite is in `userspace/countmin/sketch_test.go` and covers:

- Validation of `epsilon` and `delta`.
- Non-zero dimensions from parameter-based construction.
- Exact counting for a single key.
- The never-undercounts property under deliberate collisions.
- The probabilistic error bound using a deterministic input stream.
- Reset behavior for counters and the running total.

Run the package tests from the repository root with:

```powershell
go test ./userspace/countmin -v -count=1
```

Run all Go tests matching the userspace package tree with:

```powershell
go test ./userspace/countmin/... -v -count=1
```

The `-count=1` option disables cached test results, which is useful when verifying a fresh run.

## Benchmarks

The package includes two benchmarks:

- `BenchmarkAdd` measures adding keys to a sketch with dimensions `2048 x 5`.
- `BenchmarkEstimate` measures estimating keys from a populated sketch with dimensions `2048 x 5`.

Run the benchmarks with memory statistics using:

```powershell
go test ./userspace/countmin -run '^$' -bench . -benchmem -v -count=1
```

`-run '^$'` skips the regular tests, while `-bench .` selects all benchmarks. A representative run on Windows/amd64 produced approximately:

```text
BenchmarkAdd-16       36 ns/op    0 B/op   0 allocs/op
BenchmarkEstimate-16  34 ns/op    0 B/op   0 allocs/op
```

Benchmark values depend on the processor, Go version, and system load.

A compiled test binary can also be run directly:

```powershell
go test -c -o countmin.test.exe ./userspace/countmin
.\countmin.test.exe -test.bench . -test.benchmem -test.v
```

The `test.` prefix is required when passing test flags directly to the compiled binary.

## Limitations and usage considerations

- Estimates may be higher than the true count because of hash collisions.
- Counters and the running total are `uint64` values; callers should avoid workloads that overflow them.
- The sketch does not support removing one key or decaying individual entries. For sliding-window detection, use a separate sketch per window and discard the completed sketch.
- `maphash` seeds are generated when a sketch is constructed, so separate sketches do not intentionally share row hash functions.

## Summary

This implementation provides a compact, probabilistic frequency counter suitable for high-volume userspace packet processing. It combines independent per-row hashing with minimum-based queries to guarantee no undercounting, while allowing the memory and accuracy trade-off to be selected through `epsilon` and `delta` or explicit dimensions.
