# Analysis

Scores the user-space detector's output against dataset ground truth:
accuracy, precision, recall and F1 per window, and detection latency per
attack. Ground truth follows Koshovyi & Wu (2026), section 4.1.3, so the
results are comparable with their IQR baseline.

For a step-by-step guide, from the dataset to accuracy, recall
and per-attack results, see [GUIDE.md](GUIDE.md).

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r analysis/requirements.txt
python -m pytest analysis
```

Works with pandas 2 and 3.

## 1. Labels to the common format

One run per day. `--time-offset` is what is added to the dataset's local
timestamps to get UTC; it has no default.

```
python -m analysis.preprocess --dataset cicddos2019 \
    --input CSV-03-11/ --out labels/03-11.parquet --time-offset=+3h
python -m analysis.preprocess --dataset cicddos2019 \
    --input CSV-01-12/ --out labels/01-12.parquet --time-offset=+3h
```

Next to each parquet file: `.meta.json` (skipped rows, duplicates, label
conflicts, the CSVs' timestamp range, warnings), `.labels.csv` (per label)
and `.files.csv` (per file).

To choose the offset, compare the earliest and latest CSV timestamps printed
here with the first packet time of the matching pcap files from
`capturecheck`.

## 2. Evaluate detector runs

The detector must have been run on the trace files (`detector -pcap`), not
live, since labels are in trace time.

```
python -m analysis.evaluate \
    --day 03-11 labels/03-11.parquet results/03-11/ \
    --day 01-12 labels/01-12.parquet results/01-12/ \
    --out eval/
```

Writes `windows.csv`, `latency.csv`, `metrics.csv` and `metrics.json` per day
under `eval/<day>/`, and `metrics.csv`/`metrics.json` with a total over all
days under `eval/`. The window length and mode are read from each run's
`run.json`. The first 75 evaluated windows per day are excluded as warm-up
(`--warmup`).

## 3. Live runs and comparing variants

Live runs (user space with `-iface`, and the kernel variant) are evaluated
one at a time against an excerpt made by `scripts/excerpt.py`, with a -pcap
run of the same excerpt as reference for aligning clocks:

```
python -m analysis.evaluate --labels labels/03-11.parquet --run results/kernel-live/ \
    --excerpt excerpts/03-11.excerpt.json --reference results/ref/ --out eval/kernel-live/
python -m analysis.compare eval/ref eval/us-live eval/kernel-live
```

A live evaluation also reports the offset and how well it matched, the
windows left out before and after the excerpt, and the packet losses from
tcpreplay to the detector; all metrics include FPR. Step 5 of
[GUIDE.md](GUIDE.md) explains the output. The full procedure, from making
the excerpt to the live runs on the Pi and FABRIC, is in
[docs/live-evaluation.md](../docs/live-evaluation.md).

## 4. Plot individual runs

```sh
python -m analysis.plot results/ --out results/plots --format png pdf
```

Creates traffic plots for each run, separate CPU and memory plots for
blocking performance runs, and actual/predicted label timelines from existing
accuracy evaluations. Supports a single directory or an entire results tree.
See [PLOTTING.md](PLOTTING.md) for options, output files and counter definitions.
Plots preserve missing measurements, scoring exclusions and evaluation warnings.

## 5. Compare performance as JSON

```sh
python -m analysis.compare_performance results/ --out results/comparison.json
```

Summarizes CPU, cgroup memory plus separately charged BPF maps, and window
evaluation/decision/block-update timing. Includes per-run percentiles,
descriptive implementation comparisons and source warnings. Use `--blocking on`
for the mitigation performance runs. No additional dependencies are needed.
See [PERFORMANCE.md](PERFORMANCE.md) for definitions, current findings and how
to measure attack-onset, application and per-packet latency.

## Layout

| Module | Depends on |
|---|---|
| `datasets/cicddos2019.py` | the dataset's CSV layout; produces the common format |
| `schema.py` | defines and validates the common label format |
| `groundtruth.py` | the common format only |
| `evaluate.py` | the common format and the detector's `windows.csv`/`run.json` |
| `alignment.py` | packets per window only; finds a live run's offset to trace time |
| `tcpreplay.py` | parses the sender's `tcpreplay.txt` |
| `compare.py` | the outputs of `evaluate.py` |
| `compare_performance.py` | raw run windows/resources; standard library JSON comparison |
| `plot.py` | raw run windows/resources and existing single-run evaluation outputs |

To add a dataset, add a loader under `datasets/` and register it in
`datasets/__init__.py`. Nothing after the loader needs to change.
