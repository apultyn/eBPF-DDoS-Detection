# scripts

| Script | Purpose |
|---|---|
| `excerpt.py` | cut an excerpt out of a day of CIC-DDoS2019 pcaps for live replay, refusing gaps between files and early attacks; writes `<name>.excerpt.json` |
| `run-detector.sh` | run one live evaluation run of either variant on the detector machine, under memwatch, never with blocking |
| `memwatch.py` | run a command in its own cgroup and log its memory (below) |

How `excerpt.py` and `run-detector.sh` are used together is described in
[docs/live-evaluation.md](../docs/live-evaluation.md).

## memwatch.py — memory of a run, measured through cgroup v2

`memwatch.py` starts a command in a cgroup of its own and logs that cgroup's
memory while the command runs. The user-space detector and the XDP version
are measured the same way, by the kernel's own accounting, rather than by
each program reporting on itself.

Requirements: Linux with cgroup v2 and systemd (Ubuntu 24.04 is fine), Python
3, run as root. Standard library only.

### Running it

Everything after `--` is the command to measure.

Live capture (FABRIC or the Pi):

```bash
sudo python3 scripts/memwatch.py --out results/live1 -- \
    ./detector -iface eth0 -duration 5m -out results/live1
```

Trace replay (mode A):

```bash
sudo python3 scripts/memwatch.py --out results/run1 -- \
    ./detector -pcap PCAP-03-11/ -out results/run1
```

With the XDP version, attach the program first, then measure the detector
and record the BPF maps and programs too:

```bash
sudo ip link set dev ens7 xdpgeneric obj heavy_keeper.o sec xdp
sudo python3 scripts/memwatch.py --out results/xdp1 --bpftool -- \
    ./detector -iface ens7 -duration 5m -out results/xdp1
```

The maps are not in memwatch's `main` for this run; see
[BPF maps](#bpf-maps) for what to report.

Options: `--interval` (seconds between samples, default 0.5),
`--bpftool-after` (when the first bpftool snapshot is taken, default 5 s),
`--cpu` (also log the whole machine's CPU use, see below),
`--force` (overwrite memwatch's own files in `--out`).

Ctrl-C is forwarded to the command once, as SIGINT. The detector then stops
cleanly (`end_reason: interrupted` in its run.json) and writes its files;
memwatch records its last readings and exits with the command's exit code.
The command runs in its own session for this reason: the terminal's Ctrl-C
reaches only memwatch, and the detector does not get a second SIGINT, which
would kill it before it writes its results. memwatch's own errors (no root,
no cgroup v2, ...) exit with code 2 before the command is started.

### Output

| File | Contents |
|---|---|
| `memory.csv` | one row per sample: `ts_ns` (CLOCK_REALTIME), `current`, `anon`, `file`, `kernel`, `sock`, `percpu`, `slab`, `vmalloc`, `kernel_stack`, `pagetables`, `main` |
| `memory.stat.final` | the whole `memory.stat` at the end |
| `memory_summary.json` | unit and cgroup path, kernel version, interval, number of samples, max and median of `main`, max of `current`, `memory.peak`, exit code, forwarded signals, warnings |
| `bpf_maps.json`, `bpf_progs.json` | with `--bpftool`: `bpftool -j map show` / `prog show`, during the run and at the end |
| `cpu.csv` | with `--cpu`: one row per sample: `ts_ns`, `host_busy_ns`, `host_total_ns`, `host_softirq_ns`, `host_max_core_share` |

Memory values are bytes. A field missing from `memory.stat` gives an empty
cell, not 0. With `--cpu`, `memory_summary.json` also has a `cpu` section:
busy, total and softirq time over the run, `busy_share` and `softirq_share`
(of all cores), and the median and max of `host_max_core_share`.

### What to report: `main = anon + kernel + sock`

- `anon` — the program's own memory (heap, stacks).
- `kernel` — all kernel memory charged to the cgroup. According to
  `Documentation/admin-guide/cgroup-v2.rst` (Linux 6.8) it already includes
  `kernel_stack`, `pagetables`, `percpu`, `vmalloc` and `slab`. Those columns
  are logged for the breakdown and must not be added again.
- `sock` — network transmission buffers, not part of `kernel`.

`file` is the page cache, for instance the pcap files read in mode A. It
depends on what was read rather than on what the detector needs, so it is
logged but not part of `main`. `current` includes it.

`memory.peak` is the highest `current` since the cgroup was created, so it
includes page cache as well.

**The final readings.** systemd removes the cgroup once the command has
exited, sometimes before memwatch can read it. memwatch then uses the last
sample as the final state; `final_source` in the summary says which
(`after_exit` or `last_sample`). The last sample is at most one interval
before the end.

### BPF maps

BPF maps are charged to the cgroup of the process that creates them. The
kernel-space detector only opens maps that `ip link` created and pinned
when it attached `heavy_keeper.o`, so they are charged to the shell that ran
`ip link`, not to the detector's cgroup, and memwatch's `main` does not
include them. Pinned maps outlive their creator and stay charged to it.

The detector therefore records the maps' memory itself, in `bpf_memory` in
its run.json: per map and in total (`total_bytes`), as the kernel reports
it (memlock in the map's fdinfo, the same figure as `bytes_memlock` in
`bpftool map show`). The maps are preallocated, so the figure does not
depend on the traffic; it is read at the start and the end, and a warning
is recorded if the two differ. For the kernel-space detector report

    main (memory_summary.json) + bpf_memory.total_bytes (run.json)

Nothing is counted twice. The per-CPU maps (`slot_stats`, `blocked_stats`,
`blocklist_map`) grow with the number of possible CPUs, so the total
differs between the Pi and FABRIC. The program's own instructions and JIT
image are not included; `--bpftool` records them (`bytes_xlated`,
`bytes_jited`) if needed.

### Open question: is the AF_PACKET receive buffer in `sock`?

It is not confirmed that packets queued in the detector's AF_PACKET socket
are counted in `sock`. To test it:

1. Run live under high load (for example `tcpreplay --topspeed`) with a large
   buffer, `./detector -iface eth0 -rcvbuf 67108864 ...`, so the queue fills.
2. Check `live.socket.kernel_dropped` in run.json: drops mean the buffer was
   full.
3. If `sock` in `memory.csv` grows to the order of the buffer while drops
   occur, the buffer is counted. If it stays flat, report the granted buffer
   (`live.socket.recv_buffer_bytes` in run.json) separately alongside `main`.

### CPU use of the whole machine (`--cpu`) and baselines

Both detectors already write the machine's CPU use into every row of their
`windows.csv` (`host_*` columns, read from `/proc/stat`; see the
`HostCPUNote` in run.json). That includes the kernel's packet processing,
where XDP runs, but also everything that would happen without a detector.
`--cpu` measures the same columns without a detector, for the baseline:

```bash
# On the detector machine, while the sender replays the same traffic:
sudo python3 scripts/memwatch.py --cpu --out results/base1 -- sleep 300
```

The cost of a detector is its `host_busy_ns` minus the baseline's at the
same packet rate. An idle baseline (no traffic) shows the machine's
background load. The sender should run on another machine, or its own CPU
use ends up in every figure.

`host_total_ns` is all CPU time over the interval summed over the cores, so
`host_busy_ns / host_total_ns` is the share of the whole machine in use, and
`host_softirq_ns` the part of it in softirq. `host_max_core_share` is the
busy share of the busiest core; packets are processed on the cores that
receive them, so one core can saturate while the machine average is low.
`/proc/stat` counts in 10 ms ticks per core.

### Joining with the detector's output

In live mode, `ts_ns` in `memory.csv` and the time columns of the detector's
`windows.csv` (`start_ns`, `end_ns`, `closed_at_ns`, ...) are all
CLOCK_REALTIME, so the two can be joined on time. In mode A `windows.csv`
uses trace time, so only `closed_at_ns` and `eval_*_ns` line up with
`memory.csv`.

### Installing bpftool on Ubuntu 24.04

```bash
sudo apt install linux-tools-$(uname -r) linux-tools-common   # FABRIC (amd64)
sudo apt install linux-tools-raspi                            # Raspberry Pi
bpftool version
```

### Tests

```bash
python3 -m pytest scripts
```

The tests replace the cgroup root, `/proc/self/mounts`, `/proc/stat`, `systemd-run`,
`systemctl` and `bpftool` with fakes, so they run without root and on macOS.
They cover parsing of `memory.stat`, the `main` sum, empty fields, the
preconditions, exit codes (including death by signal), forwarding of Ctrl-C
exactly once, the fallback when the cgroup is gone, bpftool snapshots,
parsing of `/proc/stat` and the CPU columns, and the summary.

Only a real Linux system can show:

- that `systemd-run --scope` creates the cgroup and `systemctl show` finds it,
  and that memwatch itself is outside it;
- that `memory.stat` on the target kernel has the expected fields;
- whether the cgroup is still readable right after the command exits
  (`final_source`);
- whether the AF_PACKET buffer is counted in `sock` (above);
- that BPF maps from the XDP loader are charged to its cgroup.
