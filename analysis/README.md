# Analysis

Scores the user-space detector's output against dataset ground truth:
accuracy, precision, recall and F1 per window, and detection latency per
attack. Ground truth follows Koshovyi & Wu (2026), section 4.1.3, so the
results are comparable with their IQR baseline.

```
pip install -r analysis/requirements.txt
python -m pytest analysis
```

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

## Layout

| Module | Depends on |
|---|---|
| `datasets/cicddos2019.py` | the dataset's CSV layout; produces the common format |
| `schema.py` | defines and validates the common label format |
| `groundtruth.py` | the common format only |
| `evaluate.py` | the common format and the detector's `windows.csv`/`run.json` |

To add a dataset, add a loader under `datasets/` and register it in
`datasets/__init__.py`. Nothing after the loader needs to change.
