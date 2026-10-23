"""Summarize raw detector runs as JSON (Python standard library only).

    python -m analysis.compare_performance results/ --out results/comparison.json

See PERFORMANCE.md for populations, units and comparison limitations.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
from pathlib import Path


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def number(row: dict, key: str) -> int | float | None:
    value = row.get(key)
    if value in (None, ""):
        return None
    try:
        # Never round absolute nanosecond timestamps through a float.
        result = int(value) if re.fullmatch(r"[+-]?\d+", str(value)) else float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid {key}: {value!r}") from exc
    if not math.isfinite(result):
        raise ValueError(f"non-finite {key}: {value!r}")
    if key.endswith("_ns") and not isinstance(result, int):
        raise ValueError(f"{key} must be an integer: {value!r}")
    return result


def percentile(values: list, fraction: float) -> float | None:
    if not values:
        return None
    position = (len(values) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def summary(values) -> dict:
    values = list(values)
    valid = sorted(v for v in values if v is not None and v >= 0)
    return {
        "n": len(valid), "missing": sum(v is None for v in values),
        "invalid_negative": sum(v is not None and v < 0 for v in values),
        "mean": statistics.fmean(valid) if valid else None,
        "min": valid[0] if valid else None, "p50": percentile(valid, 0.5),
        "p95": percentile(valid, 0.95), "p99": percentile(valid, 0.99),
        "max": valid[-1] if valid else None,
    }


def flag(row: dict, key: str) -> bool | None:
    value = str(row.get(key, "")).strip().lower()
    if value not in ("", "true", "false"):
        raise ValueError(f"invalid {key}: {value!r}")
    return {"true": True, "false": False}.get(value)


def difference_ms(row: dict, later: str, earlier: str) -> float | None:
    a, b = number(row, later), number(row, earlier)
    return (a - b) / 1e6 if a is not None and b is not None else None


def latency(rows: list[dict], live: bool) -> dict:
    pairs = {"evaluation": ("eval_end_ns", "eval_start_ns"),
             "queue": ("eval_start_ns", "closed_at_ns")}
    if live:
        pairs.update({"window_close": ("closed_at_ns", "end_ns"),
                      "decision": ("eval_end_ns", "end_ns"),
                      "block_update": ("blocked_at_ns", "end_ns"),
                      "verdict_to_block_update": ("blocked_at_ns", "eval_end_ns")})
    return {name: summary(difference_ms(row, *pair) for row in rows)
            for name, pair in pairs.items()}


def cpu_ratio(rows: list[dict], numerators: tuple[str, ...], denominator: str) -> dict:
    values, total_numerator, total_denominator = [], 0, 0
    for row in rows:
        nums = [number(row, key) for key in numerators]
        denom = number(row, denominator)
        if denom is None or any(n is None for n in nums):
            values.append(None)
        elif denom <= 0 or any(n < 0 for n in nums):
            values.append(-1)  # Disclose invalid intervals; never clip them to zero.
        else:
            numerator = sum(nums)
            values.append(100 * numerator / denom)
            total_numerator += numerator
            total_denominator += denom
    stats = summary(values)
    invalid = stats.pop("invalid_negative")
    return {**stats, "invalid_intervals": invalid,
            "weighted_mean": 100 * total_numerator / total_denominator if total_denominator else None,
            "numerator_ns": total_numerator, "denominator_ns": total_denominator}


def total_counter(rows: list[dict], key: str) -> int | None:
    values = [number(row, key) for row in rows]
    if any(v is not None and v < 0 for v in values):
        raise ValueError(f"negative {key}")
    return sum(values) if values and all(v is not None for v in values) else None


def describe_run(directory: Path) -> dict:
    info = read_json(directory / "run.json")
    rows = read_csv(directory / "windows.csv")
    if not rows:
        raise ValueError(f"{directory}: no windows")
    warnings = []
    previous_end = None
    for row in rows:
        start, end = number(row, "start_ns"), number(row, "end_ns")
        if start is None or end is None or end <= start:
            raise ValueError(f"{directory}: invalid window boundaries")
        if previous_end is not None and start < previous_end:
            raise ValueError(f"{directory}: unordered or overlapping windows")
        previous_end = end

    source = info.get("source")
    variant = {"xdp": "kernel", "live": "userspace", "pcap": "userspace"}.get(source, "unknown")
    live = source in ("xdp", "live")
    config = info.get("config", {})
    match = re.search(r"-(gen|nat)-\d+$", directory.name)
    attachment = {"gen": "generic", "nat": "native"}.get(match[1]) if match else None
    if live:
        warnings.append("XDP attachment mode is a directory label, not verified manifest metadata."
                        if attachment else "XDP attachment mode is unknown; this run has its own group.")

    evaluated = [row for row in rows if flag(row, "evaluated") is True]
    measured_latency = latency(evaluated, live)
    after_warmup = [row for row in evaluated if flag(row, "warm_up") is False]
    measured_after_warmup = latency(after_warmup, live)
    cpu_path = directory / "cpu.csv"
    host_rows = read_csv(cpu_path) if cpu_path.exists() else rows
    cpu = {
        "host_source": "cpu.csv" if cpu_path.exists() else "windows.csv",
        "host_busy_percent": cpu_ratio(host_rows, ("host_busy_ns",), "host_total_ns"),
        "host_softirq_percent": cpu_ratio(host_rows, ("host_softirq_ns",), "host_total_ns"),
        "busiest_core_percent": summary(
            None if (v := number(row, "host_max_core_share")) is None else 100 * v
            for row in host_rows),
        "process_percent_one_core": cpu_ratio(rows, ("user_cpu_ns", "sys_cpu_ns"), "cpu_interval_ns"),
    }

    mem_rows = read_csv(directory / "memory.csv")
    bpf = info.get("bpf_memory") or {}
    bpf_bytes, initial_bpf = bpf.get("total_bytes"), bpf.get("start_total_bytes")
    stable_bpf = bpf_bytes is not None and initial_bpf == bpf_bytes
    if not stable_bpf:
        warnings.append("Fixed separately charged BPF map memory is unconfirmed; combined memory is null.")
    memory = {
        "samples": len(mem_rows), "bpf_maps_bytes": bpf_bytes,
        "bpf_maps_start_bytes": initial_bpf, "bpf_maps_stable": stable_bpf,
        "main_mib": summary(None if (v := number(row, "main")) is None else v / 2**20 for row in mem_rows),
        "main_plus_bpf_maps_mib": summary(
            (v + bpf_bytes) / 2**20 if stable_bpf and (v := number(row, "main")) is not None else None
            for row in mem_rows),
        "current_mib": summary(None if (v := number(row, "current")) is None else v / 2**20 for row in mem_rows),
        "go_heap_mib": summary(None if (v := number(row, "heap_alloc_bytes")) is None else v / 2**20 for row in rows),
    }
    if not mem_rows:
        warnings.append("No memory.csv; cgroup memory was not measured.")
    mem_summary_path = directory / "memory_summary.json"
    if mem_summary_path.exists():
        mem_summary = read_json(mem_summary_path)
        warnings.extend(f"memwatch: {w}" for w in mem_summary.get("warnings", []))
        if mem_summary.get("exit_code") not in (None, 0):
            warnings.append(f"memwatch command exit code: {mem_summary['exit_code']}")

    evaluation_path = directory.parent / f"eval-{directory.name}" / "metrics.json"
    evaluation = None
    if evaluation_path.exists():
        metrics = read_json(evaluation_path)
        evaluation = {"path": evaluation_path.as_posix(), "warnings": metrics.get("warnings", [])}
        warnings.extend(f"evaluation: {w}" for w in evaluation["warnings"])
    if (info.get("version") or {}).get("modified"):
        warnings.append("Run used a modified source tree; commit alone does not identify the build.")
    for population in (measured_latency, measured_after_warmup):
        if any(s["invalid_negative"] for s in population.values()):
            warnings.append("Negative timestamp differences were excluded and counted as invalid.")
    for stat in cpu.values():
        if isinstance(stat, dict) and (stat.get("invalid_intervals") or stat.get("invalid_negative")):
            warnings.append("Invalid CPU intervals were excluded and counted as invalid.")

    packets = total_counter(rows, "packets")
    blocked = total_counter(rows, "blocked_packets")
    counted_plus_blocked = packets + blocked if packets is not None and blocked is not None else None
    socket = (info.get("live") or {}).get("socket") or {}
    window_lengths = sorted({number(row, "end_ns") - number(row, "start_ns") for row in rows})
    return {
        "name": directory.name, "path": directory.as_posix(), "variant": variant, "source": source,
        "blocking": config.get("block"), "attachment_label": attachment,
        "window_length_ns": window_lengths[0] if len(window_lengths) == 1 else None,
        "observed_window_lengths_ns": window_lengths, "config": config,
        "version": info.get("version"), "end_reason": info.get("end_reason"),
        "started_at": info.get("started_at"), "finished_at": info.get("finished_at"),
        "coverage": {"windows": len(rows), "evaluated_windows": len(evaluated),
                     "after_warmup_windows": len(after_warmup),
                     "warmup_unknown_windows": sum(flag(row, "warm_up") is None for row in evaluated),
                     "window_span_seconds": (number(rows[-1], "end_ns") - number(rows[0], "start_ns")) / 1e9,
                     "window_duration_seconds": sum(number(row, "end_ns") - number(row, "start_ns") for row in rows) / 1e9},
        "traffic": {"counted_packets": packets, "blocked_packets": blocked,
                    "counted_plus_blocked_packets": counted_plus_blocked,
                    "blocked_share_of_counted_plus_blocked": blocked / counted_plus_blocked if counted_plus_blocked else None,
                    "socket_dropped_run_total": socket.get("kernel_dropped"),
                    "manifest_packets_run_total": (info.get("stats") or {}).get("packets")},
        "cpu": cpu, "memory": memory, "latency_ms": measured_latency,
        "latency_after_warmup_ms": measured_after_warmup,
        "saved_evaluation": evaluation, "warnings": list(dict.fromkeys(warnings)),
    }


def metric_values(run: dict) -> dict:
    return {
        "host_busy_percent": run["cpu"]["host_busy_percent"]["weighted_mean"],
        "host_busy_p99_percent": run["cpu"]["host_busy_percent"]["p99"],
        "process_percent_one_core": run["cpu"]["process_percent_one_core"]["weighted_mean"],
        "main_plus_bpf_maps_p50_mib": run["memory"]["main_plus_bpf_maps_mib"]["p50"],
        "main_plus_bpf_maps_max_mib": run["memory"]["main_plus_bpf_maps_mib"]["max"],
        **{f"{name}_{p}_ms": stat[p] for name, stat in run["latency_ms"].items()
           for p in ("p50", "p95", "p99", "max")},
    }


def group_runs(runs: list[dict]) -> list[dict]:
    buckets = {}
    for run in runs:
        identity = {key: run[key] for key in ("variant", "source", "blocking", "attachment_label", "window_length_ns")}
        identity["detector_mode"] = run["config"].get("mode")
        # Unknown attachment and variable window lengths cannot be pooled safely.
        if run["attachment_label"] is None or run["window_length_ns"] is None:
            identity["unresolved_run"] = run["path"]
        key = json.dumps(identity, sort_keys=True)
        buckets.setdefault(key, (identity, []))[1].append(run)
    groups = []
    for key, (identity, members) in sorted(buckets.items()):
        values = [metric_values(member) for member in members]
        metrics = sorted(set().union(*(value.keys() for value in values)))
        groups.append({**identity, "n_runs": len(members), "runs": [r["path"] for r in members],
                       "metrics": {name: summary(value.get(name) for value in values) for name in metrics}})
    return groups


def compare_groups(groups: list[dict]) -> list[dict]:
    comparisons = []
    for user in groups:
        if user["variant"] != "userspace" or user["source"] != "live" or not user["attachment_label"]:
            continue
        for kernel in groups:
            if kernel["variant"] != "kernel" or any(user[key] != kernel[key] for key in
                    ("attachment_label", "blocking", "window_length_ns", "detector_mode")):
                continue
            if user["window_length_ns"] is None:
                continue
            metrics = {}
            for name in sorted(user["metrics"].keys() & kernel["metrics"].keys()):
                a, b = user["metrics"][name]["p50"], kernel["metrics"][name]["p50"]
                metrics[name] = {"userspace_run_median": a, "kernel_run_median": b,
                                 "kernel_minus_userspace": b - a if a is not None and b is not None else None,
                                 "kernel_reduction_percent": 100 * (a - b) / a if a and b is not None else None}
            comparisons.append({"attachment_label": user["attachment_label"], "blocking": user["blocking"],
                                "window_length_ns": user["window_length_ns"], "detector_mode": user["detector_mode"],
                                "userspace_runs": user["runs"], "kernel_runs": kernel["runs"],
                                "status": "descriptive_unpaired_unvalidated", "metrics": metrics})
    return comparisons


def build_report(directories: list[Path], blocking: str = "all", include_offline: bool = False) -> dict:
    paths = set()
    for directory in directories:
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        manifests = [directory / "run.json"] if (directory / "run.json").exists() else directory.rglob("run.json")
        paths.update(path.parent.resolve() for path in manifests)
    runs = []
    for path in sorted(paths):
        info = read_json(path / "run.json")
        if info.get("source") == "pcap" and not include_offline:
            continue
        if blocking != "all" and info.get("config", {}).get("block") is not (blocking == "on"):
            continue
        runs.append(describe_run(path))
    if not runs:
        raise ValueError("no matching raw detector runs (run.json and windows.csv)")
    groups = group_runs(runs)
    return {
        "schema_version": 1,
        "definitions": {
            "latency_ms": "Evaluated windows, including warmup. Nanosecond integers subtracted before conversion to ms.",
            "latency_after_warmup_ms": "Evaluated windows with warm_up explicitly false; unknown flags excluded.",
            "evaluation": "eval_end_ns - eval_start_ns; includes kernel map reads, excludes per-packet XDP/capture work.",
            "queue": "eval_start_ns - closed_at_ns.",
            "window_close": "closed_at_ns - end_ns; includes grace, scheduling and aggregation/map snapshot work.",
            "decision": "eval_end_ns - end_ns; live sources only, includes window-close delay.",
            "block_update": "blocked_at_ns - end_ns; only rows with an update timestamp, not proof of a successful drop.",
            "verdict_to_block_update": "blocked_at_ns - eval_end_ns; only update rows.",
            "cpu": "Percent; process 100 = one core, host 100 = all cores. Weighted means use sums of valid counter pairs.",
            "memory": "Sample quantiles in MiB, not time weighted. main = anon + kernel + sock; add stable separately charged BPF maps.",
            "quantiles": "Linear interpolation at (n-1)*q; missing/invalid values excluded with counts; unavailable values are null.",
            "groups": "Descriptive directory-label cohorts; statistics across per-run summaries, never pooled windows.",
            "comparisons": "Difference between cohort medians; positive kernel_reduction_percent means a smaller kernel value.",
        },
        "warnings": [
            "Whole recordings include setup, idle tails and different traffic. No common validated replay interval or no-detector baseline is selected.",
            "Cohorts do not establish identical hardware, traffic, configuration or builds; comparisons are descriptive, unpaired and not significance tests.",
            "Process CPU excludes XDP work; use whole-host CPU for offload comparisons.",
            "BPF map addition assumes the repository's separate loader cgroup arrangement. Program/JIT memory is excluded.",
            "Attack-onset latency and per-packet/wire latency are not computed. Saved evaluations require valid alignment and onset coverage.",
        ],
        "runs": runs, "groups": groups, "comparisons": compare_groups(groups),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directories", nargs="+", type=Path, help="raw run directories or result trees")
    parser.add_argument("--blocking", choices=("all", "on", "off"), default="all")
    parser.add_argument("--include-offline", action="store_true", help="include pcap replay in separate groups")
    parser.add_argument("--out", required=True, type=Path, help="output JSON file")
    args = parser.parse_args(argv)
    try:
        report = build_report(args.directories, args.blocking, args.include_offline)
        # Do not allow the output to replace a source measurement.
        output = args.out.resolve()
        if output.suffix.lower() != ".json":
            raise ValueError("--out must be a JSON file")
        if output.name.lower() in {"run.json", "metrics.json", "memory_summary.json", "bpf_maps.json", "bpf_progs.json"}:
            raise ValueError("choose a comparison filename to preserve measurements")
        if any(output.parent == Path(run["path"]) for run in report["runs"]):
            raise ValueError("place --out outside raw run directories to preserve measurements")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(f"Wrote {args.out}: {len(report['runs'])} runs, {len(report['groups'])} groups, "
          f"{len(report['comparisons'])} descriptive comparisons")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
