"""Convert a dataset's label files for one day to the common label format.

    python -m analysis.preprocess --dataset cicddos2019 \\
        --input CSV-03-11/ --out labels/03-11.parquet --time-offset=+3h

Writes, next to the parquet file:

    <name>.meta.json      inputs, offset, skipped rows, duplicates, label
                          conflicts, the CSVs' timestamp range, warnings
    <name>.labels.csv     per label: flows, packets, first start, last end
    <name>.files.csv      per file: first and last start, flows per label

--time-offset is what is added to the dataset's local timestamps to obtain
UTC, and has no default. Write a negative offset as --time-offset=-3h so it
is not taken for an option.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from .datasets import LOADERS
from .timefmt import parse_offset


def outputs(out: Path) -> dict[str, Path]:
    stem = out.with_suffix("")

    return {
        "parquet": out,
        "meta": stem.with_name(stem.name + ".meta.json"),
        "labels": stem.with_name(stem.name + ".labels.csv"),
        "files": stem.with_name(stem.name + ".files.csv"),
    }


def write_summaries(meta: dict, paths: dict[str, Path]) -> None:
    paths["meta"].write_text(json.dumps(meta, indent=2) + "\n")

    with open(paths["labels"], "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "is_attack", "flows", "packets",
                    "first_start_ns", "first_start_utc", "first_start_local",
                    "last_end_ns", "last_end_utc", "last_end_local"])
        for s in meta["labels"]:
            w.writerow([s["label"], s["is_attack"], s["flows"], s["packets"],
                        s["first_start"]["ns"], s["first_start"]["utc"], s["first_start"]["local"],
                        s["last_end"]["ns"], s["last_end"]["utc"], s["last_end"]["local"]])

    with open(paths["files"], "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "rows", "kept", "duplicates_of_earlier_files", "duplicates_within_file",
                    "first_start_utc", "first_start_local", "last_start_utc", "last_start_local",
                    "flows_per_label", "skipped"])
        for s in meta["files"]:
            w.writerow([s["file"], s["rows"], s["kept"],
                        s["duplicates_of_earlier_files"], s["duplicates_within_file"],
                        s["first_start"]["utc"], s["first_start"]["local"],
                        s["last_start"]["utc"], s["last_start"]["local"],
                        json.dumps(s["flows_per_label"], sort_keys=True),
                        json.dumps(s["skipped"], sort_keys=True)])


def print_summary(meta: dict) -> None:
    r = meta["csv_timestamp_range"]
    print()
    print(f"time offset {meta['time_offset']} (added to CSV time to get UTC)")
    print(f"CSV timestamps: earliest {r['earliest']['local']} local = {r['earliest']['utc']}")
    print(f"                latest   {r['latest']['local']} local = {r['latest']['utc']}")
    print(f"rows: {meta['rows_read']} read, {meta['rows_kept']} kept, "
          f"{meta['duplicates_of_earlier_files']} duplicates of earlier files dropped, "
          f"{meta['duplicates_within_files']} duplicates within files kept")

    if meta["rows_skipped"]:
        print(f"skipped: {meta['rows_skipped']}")
    if meta["label_conflicts_across_files"]:
        print(f"label conflicts across files: {meta['label_conflicts_across_files']}")
    if meta["label_conflicts_within_files"]:
        print(f"label conflicts within files: {meta['label_conflicts_within_files']}")

    print()
    print(f"{'label':<16} {'attack':<6} {'flows':>11} {'packets':>13}  "
          f"{'first start (local / UTC)':<54}  last end (local / UTC)")
    for s in meta["labels"]:
        print(f"{s['label']:<16} {str(s['is_attack']):<6} {s['flows']:>11} {s['packets']:>13}  "
              f"{s['first_start']['local']} / {s['first_start']['utc']}  "
              f"{s['last_end']['local']} / {s['last_end']['utc']}")

    print()
    print(f"{'file':<28} {'kept':>10}  {'first start (local)':<26}  {'last start (local)':<26}  flows per label")
    for s in meta["files"]:
        print(f"{s['file']:<28} {s['kept']:>10}  {s['first_start']['local'] or '':<26}  "
              f"{s['last_start']['local'] or '':<26}  {s['flows_per_label']}")

    for w in meta["warnings"]:
        print(f"\nWARNING: {w}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dataset", required=True, choices=sorted(LOADERS))
    p.add_argument("--input", required=True, nargs="+", help="label files or directories for one day")
    p.add_argument("--out", required=True, type=Path, help="output parquet file, e.g. labels/03-11.parquet")
    p.add_argument("--time-offset", required=True,
                   help="added to the dataset's local time to get UTC, e.g. +3h; no default")
    p.add_argument("--chunksize", type=int, default=None, help="rows per chunk when reading")
    p.add_argument("--force", action="store_true", help="overwrite existing output files")
    args = p.parse_args(argv)

    try:
        offset = parse_offset(args.time_offset)
    except ValueError as e:
        p.error(str(e))

    paths = outputs(args.out)
    existing = [str(x) for x in paths.values() if x.exists()]
    if existing and not args.force:
        p.error(f"output exists, use --force to overwrite: {', '.join(existing)}")

    args.out.parent.mkdir(parents=True, exist_ok=True)

    loader = LOADERS[args.dataset]
    kwargs = {} if args.chunksize is None else {"chunksize": args.chunksize}

    meta = loader.convert(args.input, args.out, offset, **kwargs)
    meta["outputs"] = {k: str(v) for k, v in paths.items()}

    write_summaries(meta, paths)
    print_summary(meta)

    return 0


if __name__ == "__main__":
    sys.exit(main())
