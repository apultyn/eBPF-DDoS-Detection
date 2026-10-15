# scripts

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

With the XDP version, record the BPF maps and programs too:

```bash
sudo python3 scripts/memwatch.py --out results/xdp1 --bpftool -- \
    ./xdp-loader ...
```

Options: `--interval` (seconds between samples, default 0.5),
`--bpftool-after` (when the first bpftool snapshot is taken, default 5 s),
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

All values are bytes. A field missing from `memory.stat` gives an empty cell,
not 0.

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

BPF maps are charged to the cgroup of the process that creates them. The XDP
loader must therefore be started through memwatch and stay alive for the
whole run; maps created by a loader that exits, or by another tool, are not
counted. Pinned maps outlive their creator and are still charged to the
cgroup that created them. Use `--bpftool` to see which maps existed and
their sizes.

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

The tests replace the cgroup root, `/proc/self/mounts`, `systemd-run`,
`systemctl` and `bpftool` with fakes, so they run without root and on macOS.
They cover parsing of `memory.stat`, the `main` sum, empty fields, the
preconditions, exit codes (including death by signal), forwarding of Ctrl-C
exactly once, the fallback when the cgroup is gone, bpftool snapshots and
the summary.

Only a real Linux system can show:

- that `systemd-run --scope` creates the cgroup and `systemctl show` finds it,
  and that memwatch itself is outside it;
- that `memory.stat` on the target kernel has the expected fields;
- whether the cgroup is still readable right after the command exits
  (`final_source`);
- whether the AF_PACKET buffer is counted in `sock` (above);
- that BPF maps from the XDP loader are charged to its cgroup.
