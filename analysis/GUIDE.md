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

There are two ways to get the detector's flags:

| | Way | Use it for |
|---|---|---|
| **A** | the user-space detector reads the pcap files directly (`-pcap`), steps 2–4 | the algorithm's accuracy over whole days, calibration |
| **B** | an excerpt is replayed with tcpreplay to a live detector, user space or kernel, step 5 | accuracy of both variants under live conditions, side by side |

Way B builds on way A: it needs the labels from step 2 and a `-pcap` run of
the excerpt as reference.

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

Here the detector reads the pcap files itself (way A). For live runs, see
step 5.

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

## Step 5: live runs, user space and kernel (way B)

How to make the excerpt and do the live runs on the Raspberry Pi or FABRIC
is described in [docs/live-evaluation.md](../docs/live-evaluation.md). This
step is about evaluating them. You need:

- the labels of the day, from step 2: `labels/03-11.parquet`;
- the excerpt's description, from `scripts/excerpt.py`: `excerpts/03-11-1300.excerpt.json`;
- a **reference run**: the user-space detector run with `-pcap` on the excerpt file;
- one or more **live runs** of the same excerpt, each in its own directory
  with the sender's `tcpreplay.txt` copied into it.

Why the extra pieces: a live run stamps its windows with the time the
packets arrived (2026), while the labels use the time in the trace (2018).
`evaluate` finds the offset between the two by matching the live run's
packets per window against the reference run, then moves the live windows
to trace time. The excerpt description tells it where the replay started
and ended, so that windows before and after it are left out instead of
counting as correctly judged normal windows.

Evaluate the reference and each live run on its own:

`--reference` is a results **directory** containing `run.json` and
`windows.csv`; `--excerpt` is the small `.excerpt.json`, not the PCAP.
The evaluator checks these before loading labels and prints its current
stage to stderr. Label Parquet files are read in batches of 65,536 rows,
projecting only required fields and merging overlapping attack intervals
per label as they are read. Per-flow IP addresses and other unused columns
are not loaded. Scoring and latency retain the same interval semantics.
Alignment caps its coarse grid and reports when a longer capture requires
a coarser grid; final offset refinement still uses the configured fine step.

```bash
E=excerpts/03-11-1300.excerpt.json
R=results/03-11-1300

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/ref \
    --excerpt $E --out eval/03-11-1300/ref

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/us-live \
    --excerpt $E --reference $R/ref --out eval/03-11-1300/us-live

python -m analysis.evaluate --labels labels/03-11.parquet --run $R/kernel-live \
    --excerpt $E --reference $R/ref --out eval/03-11-1300/kernel-live
```

Then put them side by side:

```bash
python -m analysis.compare eval/03-11-1300/ref eval/03-11-1300/us-live eval/03-11-1300/kernel-live \
    --names "user space pcap,user space live,kernel live" --out eval/03-11-1300/compare
```

### What a live evaluation prints

Before the usual table, each run gets a short description:

```
labels: kernel (xdp), window 536.871 ms, combined
  offset 252288123.458 s by cross-correlation, correlation 0.9951, peak ratio 1.72
  windows: 1166 total, 0 before and 57 after the excerpt, 1 not evaluated, 75 warm-up, 1033 scored (11.0% attack)
  packets: sent tcpreplay 2067442, tcpreplay failed 0, detector packets 1988917, ..., window loss 3.09%
```

| Line | What to check |
|---|---|
| first line | the **variant** (`userspace` or `kernel`), how it ran (`pcap`, `live` or `xdp`) and its window length |
| `offset` | the offset found and how good the match was. **Correlation** should be above 0.9, and the **peak ratio** (how far the best offset stands out from the next) above 1.2; otherwise a warning is printed and the results should not be used |
| `windows` | how many windows were left out and why: before or after the excerpt, not evaluated, warm-up. The rest are scored. `attack` is the share of scored windows that overlap an attack |
| `packets` | the losses along the way: sent by tcpreplay, received by the interface and socket, counted by the detector, and **window loss**, the share of the excerpt's packets that did not reach the detector in the scored part. Above 1 % gives a warning, since the detector then saw less than what was sent |

### What `compare` prints

One column per run, with the variant, window length, offset and its
correlation, the number of scored windows, TP/FP/TN/FN, accuracy, precision,
recall, F1, FPR, attacks detected, window loss and the number of warnings;
then detection latency per attack, one column per run. It warns if the runs
have different window lengths or excerpts, since their numbers are then not
like for like, and repeats each run's own warnings.

---

## Reading the results

### The main numbers: `metrics.csv`

In `eval/<day>/metrics.csv`, and with two days also a combined
`eval/metrics.csv` (the `all` rows).

| Column | Meaning |
|---|---|
| `prediction` | `window` = the window was flagged by the window threshold. **This is the main result.** `window_or_ip` = the window also counts as flagged if any IP address in it was flagged. |
| `variant`, `source` | (single runs) `userspace` or `kernel`, and `pcap`, `live` or `xdp` |
| `windows_scored` | number of windows counted |
| `excluded_before_excerpt`, `excluded_after_excerpt` | (with `--excerpt`) windows that lie partly or wholly outside the excerpt |
| `excluded_warmup` | windows left out as warm-up (the first 75 per day, or from the excerpt's start) |
| `excluded_not_evaluated` | windows the detector itself did not judge |
| `attack_window_share` | share of the scored windows that overlap an attack |
| `offset_ns` | (live runs) the offset used, wall clock minus trace time |
| `TP` | attack windows that were flagged (correct) |
| `FP` | normal windows that were flagged (false alarm) |
| `TN` | normal windows that were not flagged (correct) |
| `FN` | attack windows that were not flagged (missed) |
| `accuracy` | (TP + TN) / all: share of windows judged correctly |
| `precision` | TP / (TP + FP): how often an alarm was a real attack |
| `recall` | TP / (TP + FN): share of attack windows that were detected |
| `f1` | a combination of precision and recall |
| `fpr` | FP / (FP + TN): share of normal windows that raised a false alarm |
| `attacks_detected` / `attacks_total` | attack types flagged at least once |

An empty value means the metric cannot be computed, for example precision
when no window was flagged. It is never a made-up number.

For a single run, `metrics.json` also has a `run` section with the variant,
the offset and how it was found, the excerpt, the parsed `tcpreplay.txt` and
the packet losses.

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
| `start_ns`, `end_ns` | the window in trace time (for live runs, after the offset) |
| `wall_start_ns` | the window's start as the detector stamped it; differs from `start_ns` by the offset for live runs |
| `packets` | packets the detector counted in the window |
| `excluded` | `before_excerpt`, `after_excerpt`, `not_evaluated` or `warmup` if the window was not counted, otherwise empty |
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
| `source is 'live'` / `'xdp'`, a live run | it was given with `--day`; evaluate it on its own with `--run`, `--excerpt` and `--reference` (step 5) |
| `a live run needs --excerpt` / `needs --reference` | give the excerpt's `.excerpt.json` and the `-pcap` reference run of the same excerpt |
| `blocking was on` | the run had `-block`; evaluation runs must not block. Rerun without it |
| `WARNING: correlation … is below 0.9` / `the alignment is ambiguous` | the offset is unreliable: check that the run and the reference replayed the same excerpt, and the losses |
| `WARNING: … did not reach the detector` | more than 1 % of the packets were lost on the way; the detector saw less than was sent |
| `WARNING: the replay took … times the excerpt's duration` | tcpreplay could not keep up with the original rate |
| `already exists` / `is not empty` | choose a new `--out`, or add `--force` to overwrite |
| Almost all rows skipped as `bad_timestamp` | the CSVs use an unexpected time format; tell the group, the loader needs changing |
| `WARNING: ... 12-hour clock without AM/PM` | the CSVs seem to lack afternoon times; check the time format before going on |
| `pcapng is not supported` | convert: `editcap -F pcap in.pcapng out.pcap` |

More technical details are in [README.md](README.md).
