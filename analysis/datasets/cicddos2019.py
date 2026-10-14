"""Loader for the CIC-DDoS2019 flow CSVs.

The dataset ships one CSV per attack type and day, produced by
CICFlowMeter. Properties handled here:

- Column names carry stray leading spaces (" Source IP"); they are trimmed
  and columns are selected by name, never by position.
- Timestamp is local wall-clock time without a zone. The offset to UTC is a
  required parameter, defined as what is added to the CSV time to get UTC.
- Flow Duration is in microseconds.
- "BENIGN" is the only benign label.
- The same flow can appear in several CSVs of the same day. Rows already
  seen in an earlier file are dropped; duplicates within one file are
  counted but kept.

Files are read in chunks, so a day of several gigabytes never has to fit in
memory. Duplicate detection keeps one 64-bit hash and a one-byte label code
per flow, about 9 bytes per flow.
"""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from .. import schema
from ..timefmt import format_ns, format_offset

NAME = "cicddos2019"

DEFAULT_CHUNKSIZE = 500_000

BENIGN = frozenset({"BENIGN"})

# Columns read from the CSV, by trimmed name, and their short names here.
COLUMNS = {
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Flow Duration": "duration_us",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Label": "label",
}

NUMERIC = ["src_port", "dst_port", "protocol", "duration_us", "fwd_packets", "bwd_packets"]

# A flow's identity for duplicate detection. Label is deliberately left
# out, so that the same flow under two labels is caught as a conflict.
DEDUP_KEY = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol",
             "local_ns", "duration_us", "fwd_packets", "bwd_packets"]

# The attacks of both days run into the afternoon. If no timestamp has an
# hour of 13 or later, the CSV probably uses a 12-hour clock without AM/PM.
AFTERNOON_HOUR = 13


class ColumnError(ValueError):
    """A required column is missing from a CSV."""


def list_inputs(paths: Iterable[str | Path]) -> list[Path]:
    """Expand files and directories to CSV files. A directory contributes
    the .csv files directly inside it, in natural order."""
    files: list[Path] = []

    for p in map(Path, paths):
        if p.is_dir():
            found = [c for c in p.iterdir() if c.is_file() and c.suffix.lower() == ".csv"
                     and not c.name.startswith(".")]
            files.extend(sorted(found, key=_natural_key))
        elif p.is_file():
            files.append(p)
        else:
            raise FileNotFoundError(p)

    if not files:
        raise FileNotFoundError(f"no CSV files in {', '.join(map(str, paths))}")

    return files


def _natural_key(p: Path):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", p.name)]


def header_map(path: Path) -> dict[str, str]:
    """Map each raw header of the CSV that we need to its short name.

    Raises ColumnError naming the missing columns and the ones present.
    """
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        header = next(csv.reader(f), [])

    trimmed = {h.strip(): h for h in header}
    missing = [c for c in COLUMNS if c not in trimmed]

    if missing:
        raise ColumnError(
            f"{path}: missing columns {missing}; columns present: {[h.strip() for h in header]}"
        )

    return {trimmed[c]: short for c, short in COLUMNS.items()}


def _parse_chunk(raw: pd.DataFrame, offset_ns: int) -> tuple[pd.DataFrame, Counter]:
    """Parse one chunk of raw text columns. Returns the valid rows and a
    count of skipped rows by reason."""
    skipped: Counter = Counter()

    df = raw.apply(lambda c: c.str.strip())

    repeated_header = df["label"].eq("Label") | df["timestamp"].eq("Timestamp")
    skipped["repeated_header"] = int(repeated_header.sum())

    missing = (df[["src_ip", "dst_ip", "label", "timestamp"]] == "").any(axis=1) & ~repeated_header
    skipped["missing_field"] = int(missing.sum())

    ts = pd.to_datetime(df["timestamp"], format="ISO8601", errors="coerce")
    bad_ts = ts.isna() & ~repeated_header & ~missing
    skipped["bad_timestamp"] = int(bad_ts.sum())

    nums = df[NUMERIC].apply(pd.to_numeric, errors="coerce")
    bad_num = nums.isna().any(axis=1) & ~repeated_header & ~missing & ~bad_ts
    skipped["bad_number"] = int(bad_num.sum())

    negative = (nums["duration_us"] < 0) & ~repeated_header & ~missing & ~bad_ts & ~bad_num
    skipped["negative_duration"] = int(negative.sum())

    ok = ~(repeated_header | missing | bad_ts | bad_num | negative)

    out = pd.DataFrame({
        "src_ip": df.loc[ok, "src_ip"],
        "dst_ip": df.loc[ok, "dst_ip"],
        "label": df.loc[ok, "label"],
        "local_ns": ts[ok].astype("int64"),
    })

    for c in NUMERIC:
        out[c] = nums.loc[ok, c].astype("int64")

    out["start_ns"] = out["local_ns"] + offset_ns
    out["end_ns"] = out["start_ns"] + out["duration_us"] * 1000
    out["packets"] = out["fwd_packets"] + out["bwd_packets"]
    out["hour"] = ts[ok].dt.hour

    return out.reset_index(drop=True), skipped


class _Labels:
    """Assigns one-byte codes to label texts."""

    def __init__(self) -> None:
        self.codes: dict[str, int] = {}
        self.names: list[str] = []

    def encode(self, labels: pd.Series) -> np.ndarray:
        for name in labels.unique():
            if name not in self.codes:
                if len(self.names) == 256:
                    raise ValueError("more than 256 distinct labels")
                self.codes[name] = len(self.names)
                self.names.append(name)

        return labels.map(self.codes).to_numpy(dtype=np.uint8)


def _pair_counts(a: np.ndarray, b: np.ndarray, names: list[str]) -> Counter:
    """Count label pairs (a[i], b[i]) where the two differ."""
    differ = a != b
    pairs = Counter()

    if differ.any():
        keys = a[differ].astype(np.uint16) * 256 + b[differ]
        for key, n in zip(*np.unique(keys, return_counts=True)):
            pairs[f"{names[key // 256]}<->{names[key % 256]}"] += int(n)

    return pairs


def convert(
    inputs: Iterable[str | Path],
    out: str | Path,
    time_offset_ns: int,
    chunksize: int = DEFAULT_CHUNKSIZE,
    log: Callable[[str], None] = print,
) -> dict:
    """Convert the CSVs of one day to the common label format at out."""
    files = list_inputs(inputs)

    # Check every header before reading anything, so a wrong file fails fast.
    headers = {f: header_map(f) for f in files}

    labels = _Labels()

    seen_hash = np.empty(0, dtype=np.uint64)
    seen_code = np.empty(0, dtype=np.uint8)

    cross_conflicts: Counter = Counter()
    within_conflicts: Counter = Counter()

    per_label: dict[str, dict] = {}
    per_file: list[dict] = []

    local_min = local_max = None
    max_hour = -1

    writer = pq.ParquetWriter(out, schema.SCHEMA)

    try:
        for path in files:
            log(f"reading {path.name}")

            hmap = headers[path]
            file_hash: list[np.ndarray] = []
            file_code: list[np.ndarray] = []

            stats = {
                "file": path.name,
                "rows": 0,
                "kept": 0,
                "skipped": Counter(),
                "duplicates_of_earlier_files": 0,
                "duplicates_within_file": 0,
                "first_start_ns": None,
                "last_start_ns": None,
                "flows_per_label": Counter(),
            }

            reader = pd.read_csv(
                path,
                usecols=list(hmap),
                dtype=str,
                keep_default_na=False,
                chunksize=chunksize,
                encoding="utf-8",
                encoding_errors="replace",
            )

            for raw in reader:
                stats["rows"] += len(raw)

                df, skipped = _parse_chunk(raw.rename(columns=hmap), time_offset_ns)
                stats["skipped"].update(skipped)

                if df.empty:
                    continue

                local_min = _min(local_min, int(df["local_ns"].min()))
                local_max = _max(local_max, int(df["local_ns"].max()))
                max_hour = max(max_hour, int(df["hour"].max()))

                h = pd.util.hash_pandas_object(df[DEDUP_KEY], index=False).to_numpy(np.uint64)
                codes = labels.encode(df["label"])

                # Rows already seen in an earlier file are dropped; a
                # differing label there is a conflict.
                seen_before = np.zeros(len(df), dtype=bool)
                if seen_hash.size:
                    pos = np.searchsorted(seen_hash, h)
                    inside = pos < seen_hash.size
                    seen_before[inside] = seen_hash[pos[inside]] == h[inside]

                    cross_conflicts.update(
                        _pair_counts(seen_code[pos[seen_before]], codes[seen_before], labels.names)
                    )

                stats["duplicates_of_earlier_files"] += int(seen_before.sum())

                keep = ~seen_before
                kept = df[keep]

                file_hash.append(h[keep])
                file_code.append(codes[keep])

                if kept.empty:
                    continue

                kept = kept.assign(
                    is_attack=~kept["label"].isin(BENIGN),
                    source_file=path.name,
                )
                writer.write_table(schema.to_table(kept))

                stats["kept"] += len(kept)
                stats["first_start_ns"] = _min(stats["first_start_ns"], int(kept["start_ns"].min()))
                stats["last_start_ns"] = _max(stats["last_start_ns"], int(kept["start_ns"].max()))
                stats["flows_per_label"].update(kept["label"].value_counts().to_dict())

                for name, g in kept.groupby("label", sort=False):
                    s = per_label.setdefault(name, {
                        "label": name,
                        "is_attack": name not in BENIGN,
                        "flows": 0,
                        "packets": 0,
                        "first_start_ns": None,
                        "last_end_ns": None,
                    })
                    s["flows"] += len(g)
                    s["packets"] += int(g["packets"].sum())
                    s["first_start_ns"] = _min(s["first_start_ns"], int(g["start_ns"].min()))
                    s["last_end_ns"] = _max(s["last_end_ns"], int(g["end_ns"].max()))

            # Duplicates within this file are kept, but counted; then the
            # file's flows join the set later files are checked against.
            fh = np.concatenate(file_hash) if file_hash else np.empty(0, np.uint64)
            fc = np.concatenate(file_code) if file_code else np.empty(0, np.uint8)

            uniq, first = np.unique(fh, return_index=True)
            stats["duplicates_within_file"] = int(fh.size - uniq.size)

            if fh.size != uniq.size:
                order = np.argsort(fh, kind="stable")
                sh, sc = fh[order], fc[order]
                same = sh[1:] == sh[:-1]
                within_conflicts.update(_pair_counts(sc[:-1][same], sc[1:][same], labels.names))

            merged_hash = np.concatenate([seen_hash, uniq])
            merged_code = np.concatenate([seen_code, fc[first]])
            order = np.argsort(merged_hash, kind="stable")
            seen_hash, seen_code = merged_hash[order], merged_code[order]

            per_file.append(stats)
    finally:
        writer.close()

    warnings = []
    attacks = any(s["is_attack"] for s in per_label.values())
    if attacks and max_hour < AFTERNOON_HOUR:
        warnings.append(
            f"no timestamp has an hour >= {AFTERNOON_HOUR} although attacks are present; "
            "the CSVs may use a 12-hour clock without AM/PM"
        )

    for w in warnings:
        log("warning: " + w)

    return _meta(files, time_offset_ns, per_file, per_label, cross_conflicts,
                 within_conflicts, local_min, local_max, max_hour, warnings)


def _min(a, b):
    return b if a is None else min(a, b)


def _max(a, b):
    return b if a is None else max(a, b)


def _meta(files, offset_ns, per_file, per_label, cross, within, local_min, local_max,
          max_hour, warnings) -> dict:
    def times(utc_ns):
        if utc_ns is None:
            return {"ns": None, "utc": None, "local": None}
        return {
            "ns": utc_ns,
            "utc": format_ns(utc_ns),
            "local": format_ns(utc_ns - offset_ns, utc=False),
        }

    labels = []
    for s in sorted(per_label.values(), key=lambda s: (s["first_start_ns"] or 0)):
        labels.append({
            "label": s["label"],
            "is_attack": s["is_attack"],
            "flows": s["flows"],
            "packets": s["packets"],
            "first_start": times(s["first_start_ns"]),
            "last_end": times(s["last_end_ns"]),
        })

    files_out = []
    for st in per_file:
        files_out.append({
            "file": st["file"],
            "rows": st["rows"],
            "kept": st["kept"],
            "skipped": {k: v for k, v in st["skipped"].items() if v},
            "duplicates_of_earlier_files": st["duplicates_of_earlier_files"],
            "duplicates_within_file": st["duplicates_within_file"],
            "first_start": times(st["first_start_ns"]),
            "last_start": times(st["last_start_ns"]),
            "flows_per_label": dict(st["flows_per_label"]),
        })

    return {
        "dataset": NAME,
        "inputs": [str(f) for f in files],
        "time_offset": format_offset(offset_ns),
        "time_offset_ns": offset_ns,
        "time_offset_definition": "added to the CSV Timestamp (local time) to obtain UTC",
        "csv_timestamp_range": {
            "earliest": times(None if local_min is None else local_min + offset_ns),
            "latest": times(None if local_max is None else local_max + offset_ns),
        },
        "max_hour_seen": max_hour,
        "rows_read": sum(f["rows"] for f in per_file),
        "rows_kept": sum(f["kept"] for f in per_file),
        "rows_skipped": dict(sum((Counter(f["skipped"]) for f in files_out), Counter())),
        "duplicates_of_earlier_files": sum(f["duplicates_of_earlier_files"] for f in per_file),
        "duplicates_within_files": sum(f["duplicates_within_file"] for f in per_file),
        "label_conflicts_across_files": dict(cross),
        "label_conflicts_within_files": dict(within),
        "labels": labels,
        "files": files_out,
        "warnings": warnings,
    }
