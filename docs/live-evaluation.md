# Live evaluation: user space and kernel, step by step

This guide evaluates both detector variants live, on an excerpt of
CIC-DDoS2019 replayed at its original rate, and scores them against the
dataset's labels. Every evaluation consists of three runs of the same
excerpt:

| Run | Variant | How | What it shows |
|---|---|---|---|
| (a) reference | user space | `detector -pcap` on the excerpt file | the algorithm without any replay effects |
| (b) | user space | live, AF_PACKET, replayed with tcpreplay | the cost of running live |
| (c) | kernel | live, XDP, replayed with tcpreplay | the kernel variant under the same conditions as (b) |

(a) vs (b) is the effect of the replay and live capture; (b) vs (c) is the
effect of the implementation. Run (a) also serves to align the live runs'
clocks with the trace (see [How the analysis aligns a live run](#how-the-analysis-aligns-a-live-run)).

**Blocking is never on in these runs.** `run-detector.sh` refuses `-block`,
and the analysis refuses any run whose run.json shows blocking.

---

## Setups

What every setup needs:

- a **sender** with tcpreplay, on the **same Ethernet segment** as the
  detector: a direct cable, or a switch between them. Not Wi-Fi, and not
  through a router, which would drop or alter the replayed frames;
- the replayed frames must **reach the detector's interface**. The excerpt
  keeps the dataset's MAC addresses, which belong to neither machine, so
  either:
  - **rewrite the MAC addresses** in the excerpt (`excerpt.py --rewrite-mac`)
    to the detector's (destination) and the sender's (source). This works
    with any cabling and is the safer choice; or
  - run the detector's interface in **promiscuous mode**
    (`run-detector.sh --promisc`), so it accepts frames addressed to other
    hosts. With a direct cable this is enough. Behind a switch it usually
    works too, since frames for unknown addresses are flooded to all
    ports, but a managed switch may filter them.

To check before a long run, replay a few seconds and watch the detector
side with `sudo ./capturecheck -iface <if>`: packets should be counted.

**Raspberry Pi.** Any sender on the Pi's Ethernet segment, as above. Choose
MAC rewriting or promiscuous mode depending on how the two are connected;
if unsure, rewrite the MAC addresses.

**FABRIC.** The `sender` and `detector` nodes on an L2Bridge. The VF only
accepts frames addressed to it and normally does not allow promiscuous
mode, so the MAC addresses must be rewritten. Native XDP
(`--xdp-mode drv`) is tried first.

## What to install

| Where | What |
|---|---|
| machine making the excerpt (any computer with the dataset) | Go, Python 3 with `pip install -r analysis/requirements.txt`, Wireshark tools 3.6 or later (`sudo apt install wireshark-common` or `brew install wireshark`), `tcpreplay` (for `tcprewrite`) |
| sender | `tcpreplay` |
| detector (Pi / FABRIC node) | Go, Python 3, `clang`, `libbpf-dev`, `linux-headers-$(uname -r)` (kernel variant), `ethtool`, `iproute2`, systemd; optionally `bpftool` |

The kernel variant needs Linux 6.1 or later for `bpf_ktime_get_tai_ns`;
Ubuntu 24.04 has 6.8.

---

## Step 1: labels (once per day)

```bash
python -m analysis.preprocess --dataset cicddos2019 \
    --input CSV-03-11/ --out labels/03-11.parquet --time-offset=+3h
```

See [analysis/GUIDE.md](../analysis/GUIDE.md) for choosing `--time-offset`.

## Step 2: make the excerpt

Pick a start where at least the first two minutes are normal traffic, so
the detector's warm-up learns from normal traffic. `labels/03-11.labels.csv`
lists when each attack starts.

```bash
# With MAC rewriting (FABRIC, and the Pi unless it runs in promiscuous mode):
# the detector's MAC as destination, the sender's as source
python3 scripts/excerpt.py --input PCAP-03-11/ --out excerpts/03-11-1300.pcap \
    --start 2018-11-03T13:00:00Z --duration 60m --labels labels/03-11.parquet \
    --rewrite-mac <detector MAC>,<sender MAC>

# Without (the Pi in promiscuous mode)
python3 scripts/excerpt.py --input PCAP-03-11/ --out excerpts/03-11-1300.pcap \
    --start 2018-11-03T13:00:00Z --duration 60m --labels labels/03-11.parquet
```

`ip link show <if>` prints an interface's MAC address (`link/ether`).

The merge, time cut, and optional MAC rewrite stream through pipes. Only one
temporary PCAP is written, in a hidden `.excerpt-*` directory beside `--out`,
and it is moved to the output path after validation. Allow disk space for the
finished excerpt (Ethernet conversion can increase its size). Older versions
kept merged, cut, and rewritten copies simultaneously, potentially using about
three times the selected data's size. Ordinary failures clean up the temporary
directory; a forced kill or machine crash can leave it behind. Inspect hidden
`.excerpt-*` directories for abandoned data before retrying a failed run.

The script refuses an excerpt when:

- **a gap between two files is longer than two windows**, or files overlap.
  tcpreplay waits through gaps, and a live detector learns the empty
  windows as zeros, which breaks its threshold. Choose another interval; if
  you must keep it, `--allow-gaps` records that you did.
- **an attack starts in the first two minutes** (`--min-benign`), with
  `--labels`. Override with `--allow-early-attack`.

Next to the excerpt it writes `<name>.excerpt.json`: the first and last
packet in trace time, the number of packets, the input files, every gap
between files, and the commands that made it. The analysis needs this file.

Copy the `.pcap` to the sender.

## Step 3: reference run (a)

On any machine, with the same detector settings as the live runs:

```bash
go run ./userspace/cmd/detector -pcap excerpts/03-11-1300.pcap -out results/03-11-1300/ref
```

## Step 4: live runs (b) and (c)

Run each variant separately, each into its own directory. For every run:

**On the detector**, start the script. It checks the machine, builds the
detector (and for the kernel variant compiles and attaches `heavy_keeper.o`),
then waits:

```bash
# Pi, user space (b); add --promisc if the excerpt's MAC addresses were not rewritten
sudo scripts/run-detector.sh --variant userspace --iface eth0 \
    --out results/03-11-1300/us-live --duration 62m

# Pi, kernel (c)
sudo scripts/run-detector.sh --variant kernel --iface eth0 --xdp-mode generic \
    --out results/03-11-1300/kernel-live --duration 62m

# FABRIC: no --promisc; native XDP for the kernel variant
sudo ethtool -K <if> gro off lro off      # once per boot; the script checks it
sudo scripts/run-detector.sh --variant kernel --iface <if> --xdp-mode drv \
    --out results/03-11-1300/kernel-live --duration 62m
```

`--duration` is the excerpt's length plus a margin of a couple of minutes.
If attaching in `drv` mode fails, the driver does not support native XDP;
rerun with `--xdp-mode generic` and note it, since it affects the kernel
variant's performance.

When the script says *ready*, **start the replay on the sender**:

```bash
sudo tcpreplay -i <if> excerpts/03-11-1300.pcap 2>&1 | tee tcpreplay.txt
```

- Use exactly this: **no `--pps`, no `--multiplier`, no `--topspeed`**, so the
  excerpt plays at its original rate.
- Then **press Enter on the detector** within a few seconds. The detector
  must start after the replay, so that its warm-up sees traffic.

When the detector stops (after `--duration`), copy the sender's output into
the run's directory:

```bash
scp sender:tcpreplay.txt results/03-11-1300/kernel-live/tcpreplay.txt
```

The script detaches XDP and restores promiscuous mode when it ends, also on
Ctrl-C. Everything it ran and the versions involved are in
`run-detector.json`.

## Step 5: check each run

| Check | Where | Expect |
|---|---|---|
| Blocking off | `run-detector.json` `blocking`, `run.json` `config.block` | `false` |
| Kernel timestamps (user space live) | `run.json` `live.socket.fallback_timestamps` | `0` |
| Out-of-order packets | `run.json` `stats.windows.late_packets` (user space) | `0` |
| XDP mode (kernel) | `run-detector.json` `xdp_mode_actual` | the mode you asked for |
| tcpreplay failures | `tcpreplay.txt` `Failed packets` | `0` |
| Replay rate | `tcpreplay.txt` "sent in … seconds" vs the excerpt's length | about equal; longer means tcpreplay could not keep up |
| Sent vs received | `tcpreplay.txt` `Successful packets`, `run.json` `live.nic_delta["dev.rx_packets"]`, `live.socket` (user space), `stats.packets` | close; the analysis reports the losses |
| End of run | `run.json` `end_reason` | `duration_reached` |

## Step 6: analysis

Evaluate each run on its own, then compare:

```bash
E=excerpts/03-11-1300.excerpt.json
R=results/03-11-1300

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/ref \
    --excerpt $E --out eval/03-11-1300/ref

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/us-live \
    --excerpt $E --reference $R/ref --out eval/03-11-1300/us-live

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/kernel-live \
    --excerpt $E --reference $R/ref --out eval/03-11-1300/kernel-live

python -m analysis.compare eval/03-11-1300/ref eval/03-11-1300/us-live eval/03-11-1300/kernel-live \
    --names "user space pcap,user space live,kernel live" --out eval/03-11-1300/compare
```

Each evaluation prints the variant, the offset and how good the alignment
was, how many windows were left out and why, the packet losses along the
way, and TP/FP/TN/FN, accuracy, precision, recall, F1 and FPR. The comparison
puts the runs side by side, with detection latency per attack.

**Read the warnings.** Losses above 1 %, a weak alignment (correlation below
0.9, or a peak not clearly above the next) and different window lengths
between runs are all reported, and all affect how the numbers may be used.

---

## How the analysis aligns a live run

The labels are in the trace's time (2018); a live run's windows are on the
wall clock. The analysis finds the offset between the two by matching the
live run's packets per window against the reference run (a): for each
candidate offset it computes how many packets each live window should have
received according to the reference, and picks the offset where that best
matches what was observed. This works across different window lengths and
boundaries. On synthetic traffic the offset is found to within a few tens of
milliseconds, small compared to a window. `--offset-ns` sets an offset by
hand instead.

Windows are then scored only if their whole evaluated span (the window and
the one before it) lies inside the excerpt; windows before and after the
replay are reported separately, since they would otherwise count as
correctly judged normal windows. The 75 warm-up windows count from the
excerpt's start.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `excerpt.py`: gap(s) longer than two windows | the interval spans a gap between recordings; choose another `--start` |
| `excerpt.py`: attacks start within the first 120 s | choose an earlier `--start` with normal traffic first |
| `excerpt.py`: link type is not Ethernet | give `--rewrite-mac`, which adds Ethernet headers |
| `run-detector.sh`: generic-receive-offload is on | `sudo ethtool -K <if> gro off lro off` |
| `run-detector.sh`: an XDP program is already attached | a previous run did not clean up: `sudo ip link set dev <if> xdp off` |
| `run-detector.sh`: attaching XDP in drv mode failed | the driver lacks native XDP; use `--xdp-mode generic` |
| The detector counts no packets | the frames do not reach it: rewrite the excerpt's MAC addresses to the detector's, or use `--promisc`; check that sender and detector are on the same Ethernet segment |
| The detector flags every window | it probably started before the replay and learned empty windows; restart it after starting tcpreplay |
| `evaluate`: correlation below 0.9 | the run and the reference may not be the same excerpt, or heavy losses changed the traffic; check the losses |
| `evaluate`: blocking was on | rerun without `-block` |
