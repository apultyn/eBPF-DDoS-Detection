# Guide: getting accuracy, precision, recall and F1

This guide walks you from the CIC-DDoS2019 data to the detection-quality
numbers, step by step. No knowledge of the code is needed.

## What `analysis/` does

The detector does not know what an attack is; it only flags windows. To
compute accuracy we compare the detector's flags with the dataset's ground
truth:

```
CIC-DDoS2019 CSVs ──► preprocess ──► labels/03-11.parquet ──┐
 (truth per flow)      (step 2)       (truth, cleaned)       │
                                                              ├──► evaluate ──► accuracy, recall …
CIC-DDoS2019 pcap ──► detector -pcap ──► results/03-11/ ─────┘     (step 4)
 (the traffic)         (step 3)          (detector's flags)
```

Everything is done **per day**. CIC-DDoS2019 has two days: **03-11** (the
first day, the testing day) and **01-12** (the second day, the training day).

---

## Step 1: set up your machine (once)

From the root of the repository:

```bash
python3 -m venv .venv                          # a Python environment for the project
source .venv/bin/activate                      # activate it (in every new terminal)
pip install -r analysis/requirements.txt
python -m pytest analysis                      # should end with "34 passed"
```

If you get `ModuleNotFoundError: No module named 'numpy'`, you forgot to
activate the environment with `source .venv/bin/activate`.

You also need Go to run the detector (`go version` should work).

## Step 2: convert the ground truth to our format

CIC-DDoS2019 ships its ground truth as CSV files, one per attack type. Put
one day's CSV files in a directory, for example `CSV-03-11/`, and run:

```bash
python -m analysis.preprocess --dataset cicddos2019 \
    --input CSV-03-11/ --out labels/03-11.parquet --time-offset=+3h
```

- `--input`: the directory with the day's CSV files.
- `--out`: where the result goes. Name the file after the day.
- `--time-offset`: **required.** The CSV times are local time without a time
  zone; the offset is what is added to them to get UTC. See below for how to
  choose it. Always write it with `=`, especially when negative:
  `--time-offset=-3h`.

A full day takes a while. When it is done it prints a summary: how many flows
each attack type has, and when it starts and ends, in both local time and
UTC. Next to the parquet file you also get:

| File | Contents |
|---|---|
| `03-11.meta.json` | everything about the conversion: skipped rows, duplicates, label conflicts, warnings |
| `03-11.labels.csv` | per attack type: flows, packets, first start and last end |
| `03-11.files.csv` | the same per CSV file |

### Choosing `--time-offset`

The ground-truth times and the pcap times must be on the same clock,
otherwise windows are matched against the wrong part of the ground truth:

1. Run `preprocess` with a guess, for example `--time-offset=+0h`, and note
   the line `CSV timestamps: earliest … latest …`.
2. Run `capturecheck` on the day's first and last pcap file:
   `go run ./userspace/cmd/capturecheck -pcap PCAP-03-11/<file>`. Note the
   `time span`, which is in UTC.
3. The difference between the pcap time and the CSV time is the offset. Run
   `preprocess` again with the right value and `--force`.

Write the offset down per day and use the same one in every run.

## Step 3: run the detector on the same day's pcap files

```bash
go run ./userspace/cmd/detector -pcap PCAP-03-11/ -out results/03-11
```

The detector **must** be run on the pcap files (`-pcap`), not live on a
network interface. The ground truth uses the pcap files' own time, and a
live run has a different clock. `evaluate` refuses live runs.

To try other settings, for example a different threshold, add flags and use
a new `-out` directory per attempt:

```bash
go run ./userspace/cmd/detector -pcap PCAP-03-11/ -out results/03-11-bt400 -base-threshold 400
```

All settings are saved in `results/…/run.json`, so you can always see later
what was run.

## Step 4: compute the metrics

One day:

```bash
python -m analysis.evaluate --labels labels/03-11.parquet \
    --run results/03-11/ --out eval/03-11/
```

Both days, with a total over the two:

```bash
python -m analysis.evaluate \
    --day 03-11 labels/03-11.parquet results/03-11/ \
    --day 01-12 labels/01-12.parquet results/01-12/ \
    --out eval/
```

The result is printed right away:

```
day      prediction     scored  warmup not eval     TP     FP     TN     FN  accuracy precision   recall       F1  attacks
03-11    window          ...
03-11    window_or_ip    ...
all      window          ...
```

---

## Reading the results

### The main numbers: `metrics.csv`

In `eval/<day>/metrics.csv`, and with two days also a combined
`eval/metrics.csv` (the `all` rows).

| Column | Meaning |
|---|---|
| `prediction` | `window` = the window was flagged by the window threshold. **This is the main result.** `window_or_ip` = the window also counts as flagged if any IP address in it was flagged. |
| `windows_scored` | number of windows counted |
| `excluded_warmup` | windows left out as warm-up (the first 75 per day) |
| `excluded_not_evaluated` | windows the detector itself did not judge |
| `TP` | attack windows that were flagged (correct) |
| `FP` | normal windows that were flagged (false alarm) |
| `TN` | normal windows that were not flagged (correct) |
| `FN` | attack windows that were not flagged (missed) |
| `accuracy` | (TP + TN) / all: share of windows judged correctly |
| `precision` | TP / (TP + FP): how often an alarm was a real attack |
| `recall` | TP / (TP + FN): share of attack windows that were detected |
| `f1` | a combination of precision and recall |
| `attacks_detected` / `attacks_total` | attack types flagged at least once |

An empty value means the metric cannot be computed, for example precision
when no window was flagged. It is never a made-up number.

### How the ground truth works

The same method as Koshovyi & Wu (2026), section 4.1.3:

- All attack flows of the day are merged into attack periods.
- A window is an **attack** window if it overlaps an attack period, even
  partly. Otherwise it is **normal**.
- The detector judges each window together with the previous one, so one
  second at a time. The ground truth is compared against that same second.
- An attack therefore often counts in two windows in a row, because the
  windows overlap. That is expected.

### Per attack: `latency.csv`

One row per attack type and prediction:

| Column | Meaning |
|---|---|
| `status` | `detected` (flagged), `missed` (judged but never flagged) or `not_covered` (fell in the warm-up and was never judged) |
| `attack_start_utc` | when the attack started according to the ground truth |
| `latency_s` | seconds from the attack's start until the end of the first flagged window |

### Window by window: `windows.csv`

One row per window. Useful for understanding *why* something went wrong.

| Column | Meaning |
|---|---|
| `excluded` | `warmup` or `not_evaluated` if the window was not counted, otherwise empty |
| `truth` | `True` if the window overlaps an attack according to the ground truth |
| `malicious` | `True` if the detector flagged the window |
| `outcome_window` | `TP`, `FP`, `TN` or `FN` |
| `attack_labels` | which attack types the window overlaps |

Recall per attack type, in Python:

```python
import pandas as pd
w = pd.read_csv("eval/03-11/windows.csv")
scored = w[w.outcome_window.notna()]
per_attack = (scored.assign(attack=scored.attack_labels.str.split(";"))
                    .explode("attack").dropna(subset=["attack"])
                    .groupby("attack").outcome_window
                    .agg(windows="size", flagged=lambda o: (o == "TP").sum()))
per_attack["recall"] = per_attack.flagged / per_attack.windows
print(per_attack)
```

### Comparing several settings

Run `evaluate` once per result directory, each with its own `--out`, then
collect them:

```python
import pathlib, pandas as pd
rows = []
for d in sorted(pathlib.Path("eval").glob("*/metrics.csv")):
    m = pd.read_csv(d)
    m["run"] = d.parent.name
    rows.append(m[m.prediction == "window"])
print(pd.concat(rows)[["run", "accuracy", "precision", "recall", "f1"]])
```

Each run's settings are in `results/<run>/run.json` under `config`.

---

## Common problems

| Problem | Fix |
|---|---|
| `No module named 'numpy'` | activate the environment: `source .venv/bin/activate` |
| `--time-offset … needs an explicit sign` | write the sign: `+3h`, `-3h` or `0` |
| `expected one argument` after `--time-offset -3h` | write `--time-offset=-3h` |
| `WARNING: labels (...) do not overlap the scored windows` | wrong `--time-offset`, or ground truth and run from different days |
| `WARNING: no scored window overlaps an attack interval` | as above, or all attacks fall in the warm-up |
| `source is 'live'` | the detector ran live; run it again with `-pcap` |
| `already exists` / `is not empty` | choose a new `--out`, or add `--force` to overwrite |
| Almost all rows skipped as `bad_timestamp` | the CSVs use an unexpected time format; tell the group, the loader needs changing |
| `WARNING: ... 12-hour clock without AM/PM` | the CSVs seem to lack afternoon times; check the time format before going on |
| `pcapng is not supported` | convert: `editcap -F pcap in.pcapng out.pcap` |

More technical details are in [README.md](README.md).
