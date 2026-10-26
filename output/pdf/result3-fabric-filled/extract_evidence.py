"""Extract reproducible FABRIC evidence for the filled result3.tex fragment."""

import csv
import hashlib
import json
from pathlib import Path
import sys

import numpy as np
import pandas as pd

OUT = Path(__file__).resolve().parent
REPO = OUT.parents[2]
sys.path.insert(0, str(REPO))
from analysis.compare_performance import describe_run


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def flood(rows, blocked=False):
    counts = np.array([int(r["packets"]) for r in rows], dtype=np.int64)
    if blocked:
        counts += np.array([int(r["blocked_packets"]) + int(r.get("kernel_drops") or 0) for r in rows], dtype=np.int64)
    median = pd.Series(counts).rolling(9, center=True, min_periods=9).median().to_numpy()
    high = np.flatnonzero(median > 10000)
    first, stop = int(high[0]), int(high[-1])
    assert stop > first
    origin = int(rows[0]["start_ns"])
    start, end = int(rows[first]["start_ns"]), int(rows[stop]["start_ns"])
    return {"first_index": first, "stop_index_exclusive": stop,
            "start_ns": start, "end_ns": end,
            "start_elapsed_s": (start - origin) / 1e9, "end_elapsed_s": (end - origin) / 1e9,
            "duration_s": (end - start) / 1e9}


def cpu_stats(rows):
    busy = sum(int(r["host_busy_ns"]) for r in rows)
    total = sum(int(r["host_total_ns"]) for r in rows)
    interval = sum(int(r["cpu_interval_ns"]) for r in rows)
    process = sum(int(r["user_cpu_ns"]) + int(r["sys_cpu_ns"]) for r in rows)
    counted = sum(int(r["packets"]) for r in rows)
    duration = sum(int(r["end_ns"]) - int(r["start_ns"]) for r in rows)
    return {"samples": len(rows), "host_percent_all_cores": 100 * busy / total,
            "process_percent_one_core": 100 * process / interval,
            "process_cores": process / interval, "host_cores": busy / interval,
            "rest_cores": (busy - process) / interval,
            "counted_mean_kpps": counted * 1e6 / duration,
            "counted_max_window_kpps": max(int(r["packets"]) * 1e6 / (int(r["end_ns"]) - int(r["start_ns"])) for r in rows),
            "host_us_per_counted_packet": busy / 1000 / counted,
            "summed_wall_interval_s": interval / 1e9}


def main():
    all_runs = {}
    hashes = {}
    for condition in ("acc", "per"):
        for prefix in ("usr", "ker"):
            name = f"{prefix}-{condition}-gen-1"
            directory = REPO / "results/data-fabric" / name
            info = json.loads((directory / "run.json").read_text(encoding="utf-8-sig"))
            rows = read_csv(directory / "windows.csv")
            assert info["config"]["block"] == (condition == "per")
            phase = flood(rows, condition == "per")
            a, b = phase["first_index"], phase["stop_index_exclusive"]
            run = {"name": name, "manifest": info, "phase": phase,
                   "cpu_whole": cpu_stats(rows), "cpu_flood": cpu_stats(rows[a:b])}
            nic, stats = info["live"]["nic_delta"], info["stats"]
            denominator = nic["dev.rx_packets"] + nic["dev.rx_drop"]
            counts = {"counted": sum(int(r["packets"]) for r in rows),
                      "interface": nic["dev.rx_drop"],
                      "socket": info["live"].get("socket", {}).get("kernel_dropped", 0),
                      "late": stats["windows"].get("late_packets", 0)}
            counts["unaccounted"] = denominator - sum(counts.values()) - stats["blocked_packets"]
            assert counts["unaccounted"] >= 0
            assert nic["dev.rx_drop"] == nic["ethtool.rx_out_of_buffer"]
            run["accounting"] = {"denominator": denominator, "counts": counts,
                                 "percent": {key: 100 * value / denominator for key, value in counts.items()}}
            described = describe_run(directory)
            run["latency_after_detector_warmup_ms"] = described["latency_after_warmup_ms"]
            if condition == "acc":
                evaluation_dir = directory.parent / f"eval-{name}-adjusted"
                metrics = json.loads((evaluation_dir / "metrics.json").read_text())
                evaluated = read_csv(evaluation_dir / "windows.csv")
                assert len(evaluated) == len(rows)
                run["evaluation"] = metrics
                latency = read_csv(evaluation_dir / "latency.csv")
                label_start = int(next(r["attack_start_ns"] for r in latency if r["label"] == "DrDoS_DNS"))
                run["flood_onset_vs_label_s"] = (phase["start_ns"] - metrics["counts"]["offset_ns"] - label_start) / 1e9
                parts = {}
                for key, select in (("before", lambda i: i < a), ("flood", lambda i: a <= i < b), ("tail", lambda i: i >= b)):
                    used = [(i, r) for i, r in enumerate(evaluated) if r["excluded"] == "" and select(i)]
                    flagged = sum(r["malicious"] == "True" for i, r in used)
                    missed = [(i, r) for i, r in used if r["malicious"] == "False"]
                    parts[key] = {"windows": len(used), "flagged": flagged,
                                  "flagged_percent": 100 * flagged / len(used), "not_flagged": len(missed),
                                  "not_flagged_empty_combined_span": sum(int(rows[i]["evaluated_packets"]) == 0 for i, r in missed)}
                assert sum(part["windows"] for part in parts.values()) == metrics["counts"]["windows_scored"]
                run["phases"] = parts
                run["first_flood_window_flagged"] = rows[a]["malicious"] == "true"
                for p in (evaluation_dir / "metrics.json", evaluation_dir / "windows.csv", evaluation_dir / "latency.csv"):
                    hashes[p.relative_to(REPO).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
            else:
                ips = read_csv(directory / "ips.csv")
                updates = [r for r in ips if r["blocked"] == "true"]
                blocklist = stats["blocklist"]
                assert len(updates) == blocklist["blocked"] + blocklist["refreshed"]
                assert info["config"]["block_ttl"] == "1m0s"
                run["blocking"] = {"blocked_percent": 100 * stats["blocked_packets"] / denominator,
                                   "passed_percent": 100 * (nic["dev.rx_packets"] - stats["blocked_packets"]) / denominator,
                                   "interface_drop_percent": 100 * nic["dev.rx_drop"] / denominator,
                                   "new_events": blocklist["blocked"], "refreshes": blocklist["refreshed"],
                                   "successful_updates": len(updates), "expirations": blocklist["expired"],
                                   "unique_blocked_sources": sorted(set(r["ip"] for r in updates)),
                                   "verified_attack_source_count": None}
                run["memory"] = described["memory"]
                for p in (directory / "ips.csv", directory / "memory.csv", directory / "memory_summary.json"):
                    hashes[p.relative_to(REPO).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (directory / "run.json", directory / "windows.csv"):
                hashes[p.relative_to(REPO).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
            all_runs[name] = run
    ref_path = REPO / "results/data-fabric/ref-pcap/windows.csv"
    reference_phase = flood(read_csv(ref_path))
    source = Path("C:/Users/jedre/Downloads/result3.tex")
    result = {"runs": all_runs, "reference_flood": reference_phase,
              "input_tex": str(source), "input_tex_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "source_sha256": hashes,
              "methods": {"flood": "Centered median of nine consecutive counted windows >10,000 packets; cutpoints are starts of first and last qualifying windows; half-open interval. For blocking runs, use counted + blocked + socket drops to locate the flood.",
                          "phase_origin": "First recorded window start_ns, not process launch; matches the Pi source's reported phase times.",
                          "cpu": "Ratios of summed contemporaneous windows.csv counters. Host percentages use host_total_ns; process uses cpu_interval_ns. CPU per counted packet includes all host busy time.",
                          "latency": "evaluated=true and detector warm_up=false, using integer timestamp differences; distinct from evaluator's 75-window exclusion.",
                          "memory": "Sample median main plus stable, separately charged BPF maps; no program/JIT memory.",
                          "blocking": "Block events are new admissions from stats.blocklist.blocked, excluding refreshes; unique sources from successful ips.csv updates."}}
    (OUT / "fabric-evidence.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for name, r in all_runs.items():
        summary = {"name": name, "flood": r["phase"], "cpu_whole_pct": r["cpu_whole"]["host_percent_all_cores"], "cpu_flood": r["cpu_flood"]}
        if "phases" in r:
            summary.update(phases=r["phases"], onset_vs_label=r["flood_onset_vs_label_s"], loss=r["evaluation"]["run"]["losses"]["window_loss"],first_flagged=r["first_flood_window_flagged"])
        else:
            summary.update(blocking=r["blocking"])
        print(json.dumps(summary))
    print("Reference flood duration:", reference_phase["duration_s"])


if __name__ == "__main__":
    main()
