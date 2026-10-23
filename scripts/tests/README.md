# Victim experiment scripts

Run these eight Bash scripts on the Linux victim from the project root.
Each requires exactly one argument: a positive integer identifying the test
run. Results go to `results/<script-name-without-.sh>-<test-number>`.
An existing result path is refused before building or attaching anything.

```bash
sudo bash scripts/tests/usr-acc-nat.sh 1
# Results: results/usr-acc-nat-1
```

The scripts use interface `enp7s0` and run the detector for `44m30s`.
`usr` / `ker` select the user-space / kernel-space detector; `acc` runs
without blocking, and `per` enables blocking and measures resources with
`memwatch.py`. `gen` uses generic XDP; `nat` uses native XDP (`xdpdrv`).
The native mode must be supported by the NIC driver.

After attaching, every script checks for its complete set of pinned maps
under `/sys/fs/bpf/xdp/globals`, `/sys/fs/bpf/tc/globals`, and `/sys/fs/bpf`,
then passes the detected directory as `-pin-dir`. The directory is printed
before capture starts. Missing maps or multiple distinct complete map sets
stop the run and trigger cleanup. Cleanup covers all three locations.
Keep `scripts/bpf-map-pins.sh` alongside the scripts when copying them to
the victim; it provides this shared pin-directory check.

| Script | Results for test number `N` |
|---|---|
| `usr-acc-gen.sh` | `results/usr-acc-gen-N` |
| `usr-acc-nat.sh` | `results/usr-acc-nat-N` |
| `usr-per-gen.sh` | `results/usr-per-gen-N` |
| `usr-per-nat.sh` | `results/usr-per-nat-N` |
| `ker-acc-gen.sh` | `results/ker-acc-gen-N` |
| `ker-acc-nat.sh` | `results/ker-acc-nat-N` |
| `ker-per-gen.sh` | `results/ker-per-gen-N` |
| `ker-per-nat.sh` | `results/ker-per-nat-N` |

Each script compiles its BPF object and builds its detector. XDP is detached
and the experiment's pinned maps are removed on exit, including failure or
Ctrl-C. A failed build, attach, detector run, or cleanup returns a failure,
so `&&` stops the sequence. Run the whole script with `sudo` as above to
avoid a password prompt during cleanup after a long run.

For example, the four native configurations can be chained:

```bash
sudo bash scripts/tests/usr-acc-nat.sh 1 &&
sudo bash scripts/tests/ker-acc-nat.sh 2 &&
sudo bash scripts/tests/usr-per-nat.sh 3 &&
sudo bash scripts/tests/ker-per-nat.sh 4
```

This only sequences the victim. It does **not** synchronize with a separate
chain of four replays on the attacker. Each detector captures for 44m30s,
but building, attaching, starting memwatch, writing results, and cleaning
up add variable time between captures. A back-to-back replay can therefore
start before the next detector is ready, and the offset can grow on each
run. Starting both chains together does not align them.

Coordinate each replay with its corresponding detector run, using traffic
during warm-up as described in [the live evaluation guide](../../docs/live-evaluation.md#step-4-live-runs-b-and-c).
These eight scripts start the detector immediately after setup; they do not
wait for Enter or exchange readiness signals with the attacker. A fixed
sleep between replays provides a gap, but does not guarantee alignment.
For unattended experiments, use a readiness handshake for every run.
