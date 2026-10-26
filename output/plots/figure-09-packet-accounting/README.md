# Figure 9: provisional Raspberry Pi packet accounting

The requested five-component figure can be drawn using an explicitly defined
**driver-counter sum**. It cannot yet be presented as a verified partition of
all packets physically seen by the interface: the hardware and driver counters
do not reconcile. The figure and caption state this limitation directly.

## Inputs and population

Whole-recording counts, with blocking disabled:

- `results/data-raspberry/usr-acc-gen-1/{run.json,windows.csv}`.
- `results/data-raspberry/ker-acc-gen-1/{run_kernelspace.json,windows.csv}`.

Each recording lasts approximately 44.5 minutes. These are individual runs,
not pooled repetitions or aligned high-rate phases. The interface is `eth0`.

## Denominator and segments

Define `D = live.nic_delta.dev.rx_packets + live.nic_delta.dev.rx_drop`.
This is a reproducible counter sum, not a validated physical arrival count.
Each plotted share is `100 * component / D`:

| Component | Userspace | Kernel |
| --- | ---: | ---: |
| Counted in windows: sum of `windows.csv.packets` | 21,123,303 | 73,643,163 |
| Interface drops: `dev.rx_drop` | 18,201,335 | 5,238,189 |
| Socket drops: `live.socket.kernel_dropped` | 33,356,522 | Not applicable |
| Late drops: `stats.windows.late_packets` | 6,283,426 | Not applicable |
| Unaccounted: residual of the four quantities above | 389 | 630 |
| Defined driver-counter denominator | 78,964,975 | 78,881,982 |

The kernel path has no AF_PACKET capture socket or userspace timestamp-to-window
late rejection, so those categories are structurally inapplicable. Their lack
of bar height does not assert that every possible kernel loss is measured zero.
The kernel records one discarded startup window and a final incomplete window
containing 20 packets; counts for all excluded startup traffic are unavailable.
These and any other unresolved differences remain in the residual.

Userspace checks close exactly:

```text
window packets + late packets + final partial packets = stats.packets
21,123,303 + 6,283,426 + 0 = 27,406,729

stats.packets + skipped frames + socket drops = dev.rx_packets = socket offered
27,406,729 + 389 + 33,356,522 = 60,763,640
```

Thus its residual is known parser-skipped frames, not unexplained loss. Kernel
`sum(windows.packets) = stats.packets = 73,643,163`; the difference from
`dev.rx_packets = 73,643,793` is 630. Do not subtract intentional blocks again:
both manifests and all windows record zero blocked packets. Do not sum the
overlapping `evaluated_packets` values from combined detector evaluations.

## Why the original caption needs qualification

Linux documents that `rx_packets` can include packets later dropped in host
processing and that `/proc/net/dev` folds dropped/missed fields together.
Counter additivity therefore needs driver-specific validation:
[Linux interface statistics](https://www.kernel.org/doc/html/latest/networking/statistics.html).

The saved independent hardware counters expose a concrete discrepancy:

| Check | Userspace | Kernel |
| --- | ---: | ---: |
| Hardware `ethtool.rx_good_pkts` (= `rx_pkts` and sum of RX size buckets) | 78,031,635 | 78,490,062 |
| Driver-counter sum above | 78,964,975 | 78,881,982 |
| Driver sum minus hardware | 933,340 | 391,920 |
| Excess as share of hardware | 1.1961% | 0.4993% |
| Residual if hardware is denominator and requested loss counts are retained | -932,951 | -391,290 |

Negative residuals are retained in the CSV/JSON. They are not clipped or
normalized away. The main bars use the explicitly stated driver-counter sum;
they are **provisional accounting**, not proof that all five components are
disjoint shares of physical arrivals. Adding receive error counters would
introduce further overlap; they are not additional segments.

Both manifests also warn that the ethtool RX-byte counter went backwards.
The displayed packet deltas themselves equal the saved end-minus-start
snapshots, but that does not resolve their different definitions or the
hardware mismatch. Kernel/driver version and counter semantics were not
recorded in these manifests. Current upstream Broadcom GENET counter names
match these ethtool names, but that alone does not identify the exact running
driver or establish its accounting behavior.

For the original "share of packets seen by the interface" caption, provide:

1. Kernel and NIC driver identity/version for the Pi recordings (`uname -a`,
   `ethtool -i eth0`, or saved equivalents).
2. Definitions of the actual driver's counters establishing a disjoint
   receive/drop balance and explaining the hardware mismatch.
3. Time-matched start/end snapshots separating `rx_dropped` and
   `rx_missed_errors` (netlink `ip -s -s -j link` or sysfs), together with
   hardware receive counts. Rerun if equivalent records do not exist.

## Rebuild and outputs

```powershell
.\.venv\Scripts\python.exe output/plots/figure-09-packet-accounting/build_figure.py
```

- `figure-09-packet-accounting.png`, `.pdf`, `.svg`: provisional stacked bars.
- `figure-09-data.csv`: counts, percentages, applicability, and hardware residuals.
- `figure-09-evidence.json`: formulas, hashes, checks, discrepancies, and missing evidence.
- `figure-09-caption.tex`: qualified caption/figure fragment.

The build checks manifest identity, disabled blocking, saved counter deltas,
window sums, socket and late totals, downstream userspace accounting, nonnegative
plotted segments, a 100% sum under the defined denominator, and preservation
of negative residuals under hardware normalization. No minimum visible height
is substituted for the tiny residual segments.
