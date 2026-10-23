# JSON performance comparison and latency

Run from the repository root; the comparison script uses only the Python
standard library:

```sh
python -m analysis.compare_performance results/ --out results/comparison.json
python -m analysis.compare_performance results/ --blocking on --out results/performance-comparison.json
```

Pass one results tree or multiple raw run directories. Discovery finds
`run.json` and reads its adjacent `windows.csv`, optional `cpu.csv`,
`memory.csv` and `memory_summary.json`. Overlapping input paths are deduplicated.
Offline PCAP runs are excluded unless `--include-offline` is supplied; their
trace boundaries cannot be subtracted from live wall-clock timestamps.
Keep the output outside raw run directories.

The JSON contains:

- `runs`: measurements, full detector config, build metadata, coverage and
  warnings for each recording.
- `groups`: per-run summaries grouped by implementation, source, blocking,
  directory attachment label, window length and detector mode. Each run has
  equal weight. Windows from different runs are never pooled.
- `comparisons`: user-space versus kernel differences between the medians of
  those per-run summaries. A positive `kernel_reduction_percent` means the
  kernel value is smaller. These are descriptive, unpaired comparisons;
  matching hardware, workloads and builds have not been established.

Each distribution has `n`, `missing`, `invalid_negative`, mean, min, median
(`p50`), p95, p99 and max. Quantiles use linear interpolation at `(n-1)*q`.
Missing measurements are JSON `null`, never zero. CPU distributions also
have a counter-weighted mean, computed from complete, valid numerator and
denominator pairs. Invalid CPU intervals, including zero denominators, are
counted in `invalid_intervals`. Resource distributions cover their complete
recordings, including setup and idle tails; they are not matched traffic phases.

`gen`/`nat` in directory names supply **unverified attachment labels**.
The first generic kernel performance repetition has been renamed from
`ker-acc-per-1` to `ker-per-gen-1`. It now groups with `ker-per-gen-2`, giving
two repetitions in each of the four blocking performance cohorts. The script
uses the corrected directory label and does not infer aliases.

## What the current timestamps measure

All values below are in milliseconds. Subtraction uses integer nanoseconds
before conversion, preserving timestamp precision.

| JSON metric | Difference | Meaning |
| --- | --- | --- |
| `evaluation` | `eval_end_ns - eval_start_ns` | Verdict computation, including kernel per-IP map reads; excludes packet capture/counting work |
| `queue` | `eval_start_ns - closed_at_ns` | Delay between closing the window and beginning evaluation |
| `window_close` | `closed_at_ns - end_ns` | Grace period, scheduling and window aggregation/map snapshot work |
| `decision` | `eval_end_ns - end_ns` | Time after a window ends until its verdict is available |
| `block_update` | `blocked_at_ns - end_ns` | Time until the block update call completes |
| `verdict_to_block_update` | `blocked_at_ns - eval_end_ns` | Additional time after evaluation until that call completes |

`latency_ms` includes only rows with `evaluated=true`, including warmup.
`latency_after_warmup_ms` further requires `warm_up=false`; unknown warmup
flags are counted in coverage and excluded from this second population.
Block metrics use only rows with update timestamps. Such a timestamp is
recorded even if a map update returns an error: it is not proof of successful
mitigation or the first packet dropped. Missing timestamps stay missing.
Negative differences are excluded and counted, with a warning.

The current live windows are 536.870912 ms long, and both implementations wait
about 10 ms after a boundary. Consequently, a small reduction in processing
cost may barely affect decision delay. Onset-to-verdict latency also includes
the remaining time before the window closes and any further windows needed
for a detection. These CSVs do **not** measure individual packet execution
time, forwarding latency or application RTT.

## Findings from the imported recordings

Generated on 2026-10-23 from `results/results/`. These native-mode directory
cohorts each contain two runs. Numbers are medians of run summaries;
"decision p95" is the median of each run's p95, not a pooled percentile.

| Blocking | Implementation | Host busy, weighted % | Evaluation p95, ms | Decision p95, ms | Main + BPF maps median, MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| On | User space | 0.534 | 0.368 | 11.231 | 7.120 |
| On | Kernel | 0.598 | 0.416 | 11.338 | 7.232 |
| Off | User space | 10.504 | 0.312 | 11.140 | Not measured |
| Off | Kernel | 3.743 | 0.435 | 11.367 | Not measured |

There is no observed decision-delay improvement in these runs. Kernel verdict
evaluation is slightly slower, which is compatible with doing extra map reads
while moving packet counting out of the process. That does not establish
higher per-packet latency. The blocking-off recordings show substantially
lower whole-host CPU with the kernel detector; in the blocking-on recordings,
about 99% of accounted traffic is blocked, leaving little sustained counting
work. Different traffic timing, builds and capture tails limit causal claims.

For CPU, prefer `host_busy_percent.weighted_mean` to process CPU: process
CPU omits XDP packet work. A lower process spike alone cannot demonstrate a
whole-machine improvement. Host CPU is still not detector-only overhead;
that requires a same-traffic baseline without the detector.

RAM is indeed similar. The memory comparison adds stable, separately charged
maps for both implementations: 121832 bytes for the user-space blocklist and
257600 bytes for the kernel maps in these blocking recordings. It does not
sum all maps on the machine or add slab/per-CPU subcomponents to `kernel`
again. Memory quantiles are sample based, not time weighted; Go heap is a
separate diagnostic. Program/JIT memory is outside this measurement.

## How to test whether latency improves

1. **First compare local decision timing.** Use `latency_ms` and its warmup-free
   counterpart in the JSON. Report median, p95, p99, max and sample count for
   each independent run. Compare the same traffic phase and settings, with
   blocking on/off kept separate. A load sweep is useful: headroom may prevent
   queueing and long delays near saturation even when low-load medians agree.
2. **For attack-onset latency, validate the replay first.** Measure from a
   covered attack onset to `eval_end_ns` of the first correct flagged window,
   or to `blocked_at_ns` for a mitigation-update endpoint. Verify sender timing
   and trace/live alignment across several landmarks. Save the sender command,
   replay log and exact PCAP/excerpt identity. Include missed attacks and
   censored/uncovered onsets as statuses, not zero-valued latencies.
3. **For application latency, add a benign probe during replay.** Use a
   request/response service on the victim and timestamp requests and replies
   at a separate client. Measure RTT, p50/p95/p99 and loss/timeouts at fixed
   request rates under increasing attack load, with no detector, user space
   and kernel variants. Verify the benign probe is not blocked. A single
   client clock suffices for RTT; one-way latency needs synchronized endpoint
   clocks and a stated synchronization error. This measures service impact,
   including queueing and server scheduling, rather than just detector code.
4. **For XDP execution cost, profile it separately.** With BPF runtime stats
   enabled during a dedicated measurement run, snapshot `run_time_ns` and
   `run_cnt` for the attached program before and after the traffic interval.
   `delta(run_time_ns) / delta(run_cnt)` gives average BPF execution time per
   invocation, not tail latency or end-to-end latency. Restore the previous
   stats setting afterward; instrumentation adds overhead. The upstream
   [bpftool documentation](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-prog.rst)
   describes the `kernel.bpf_stats_enabled` setting and runtime statistics.

For supporting CPU profiling on Linux, identify the attached program ID with
`sudo bpftool prog show`, then run, during traffic:

```sh
sudo bpftool prog profile id PROGRAM_ID duration 30 cycles instructions
```

Replace `PROGRAM_ID` with the actual ID. This reports hardware counters, not
RTT. `bpftool prog run ... repeat N` is another option for an isolated BPF
microbenchmark; its reported duration is averaged over test runs and does not
represent the live packet path. See the same upstream manual. Neither BPF-only
measurement is a complete comparison with user-space capture and counting.

The existing `eval-*/latency.csv` files use the first flagged **window end**
minus attack onset, not verdict availability. All eight saved evaluations
have alignment warnings; NTP starts before the observed excerpt and cannot
provide a newly starting attack's latency. Those values must not be used
to claim a latency gain. The script carries saved evaluation warnings into
the JSON without averaging those onset latencies. See
[the existing results review](../docs/results-review.md) for the timing evidence.

## Verification

```sh
python -m pytest analysis/tests/test_compare_performance.py -q
```

Tests cover integer timestamp precision, timing populations, missing/invalid
measurements, weighted CPU, map-memory accounting, separate clock domains,
unknown scenario labels, run-level aggregation and CLI output preservation.
