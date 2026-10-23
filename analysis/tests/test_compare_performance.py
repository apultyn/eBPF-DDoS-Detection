"""Check timing precision, resource accounting and repetition boundaries."""

import csv
import json

import pytest

from analysis import compare_performance as compare


T0 = 1_792_699_292_926_869_504
S = 1_000_000_000


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(dict.fromkeys(k for row in rows for k in row)))
        writer.writeheader()
        writer.writerows(rows)


def write_run(path, *, source="live", block=True, rows=None, maps=True):
    path.mkdir(parents=True)
    info = {"source": source, "config": {"block": block, "mode": "combined"},
            "version": {"commit": "abc", "modified": True}, "end_reason": "duration_reached"}
    if maps:
        info["bpf_memory"] = {"start_total_bytes": 2**20, "total_bytes": 2**20}
    (path / "run.json").write_text(json.dumps(info), encoding="utf-8")
    if rows is None:
        rows = []
        for index in range(2):
            end = T0 + (index + 1) * S
            rows.append({"start_ns": end - S, "end_ns": end, "evaluated": "true",
                         "warm_up": "true" if index == 0 else "false", "packets": 10,
                         "blocked_packets": 90, "closed_at_ns": end + 10_000_001,
                         "eval_start_ns": end + 10_001_001, "eval_end_ns": end + 10_021_002,
                         "blocked_at_ns": end + 10_041_003,
                         "user_cpu_ns": 10 if index == 0 else 180, "sys_cpu_ns": 0,
                         "cpu_interval_ns": 100 if index == 0 else 200,
                         "host_busy_ns": 10 if index == 0 else 180,
                         "host_total_ns": 100 if index == 0 else 200, "host_softirq_ns": 0})
    write_csv(path / "windows.csv", rows)
    return path


def test_integer_nanoseconds_latency_populations_and_block_accounting(tmp_path):
    path = write_run(tmp_path / "usr-per-nat-1")
    run = compare.describe_run(path)

    assert compare.number({"end_ns": str(T0)}, "end_ns") == T0
    assert run["latency_ms"]["evaluation"]["p50"] == pytest.approx(0.020001)
    assert run["latency_ms"]["decision"]["p95"] == pytest.approx(10.021002)
    assert run["latency_ms"]["block_update"]["p50"] == pytest.approx(10.041003)
    assert run["latency_ms"]["verdict_to_block_update"]["p50"] == pytest.approx(0.020001)
    assert run["latency_ms"]["decision"]["n"] == 2
    assert run["latency_after_warmup_ms"]["decision"]["n"] == 1
    assert run["traffic"]["counted_packets"] == 20  # Already after XDP blocks.
    assert run["traffic"]["counted_plus_blocked_packets"] == 200
    assert run["traffic"]["blocked_share_of_counted_plus_blocked"] == 0.9


def test_weighted_cpu_uses_complete_counter_pairs_and_prefers_memwatch(tmp_path):
    path = write_run(tmp_path / "usr-per-gen-1")
    write_csv(path / "cpu.csv", [
        {"host_busy_ns": 50, "host_total_ns": 100, "host_softirq_ns": 0},
        {"host_busy_ns": 0, "host_total_ns": 900, "host_softirq_ns": 0},
        {"host_busy_ns": "", "host_total_ns": 2000, "host_softirq_ns": ""},
    ])
    run = compare.describe_run(path)
    assert run["cpu"]["host_source"] == "cpu.csv"
    assert run["cpu"]["host_busy_percent"]["weighted_mean"] == 5
    assert run["cpu"]["host_busy_percent"]["mean"] == 25
    assert run["cpu"]["host_busy_percent"]["missing"] == 1
    assert run["cpu"]["process_percent_one_core"]["weighted_mean"] == pytest.approx(100 * 190 / 300)


def test_memory_adds_maps_once_and_does_not_add_kernel_subcomponents(tmp_path):
    path = write_run(tmp_path / "ker-per-nat-1", source="xdp")
    write_csv(path / "memory.csv", [{"main": 2**20, "kernel": 100, "slab": 100},
                                     {"main": 3 * 2**20, "kernel": 100, "slab": 100}])
    run = compare.describe_run(path)
    assert run["memory"]["main_mib"]["p50"] == 2
    assert run["memory"]["main_plus_bpf_maps_mib"]["p50"] == 3
    assert run["memory"]["current_mib"]["n"] == 0

    info = compare.read_json(path / "run.json")
    info["bpf_memory"]["start_total_bytes"] = 0
    (path / "run.json").write_text(json.dumps(info), encoding="utf-8")
    assert compare.describe_run(path)["memory"]["main_plus_bpf_maps_mib"]["p50"] is None


def test_invalid_cpu_intervals_are_not_zero_utilization():
    stat = compare.cpu_ratio([
        {"host_busy_ns": 2, "host_total_ns": 10},
        {"host_busy_ns": 0, "host_total_ns": 0},
        {"host_busy_ns": -5, "host_total_ns": 100},
        {"host_busy_ns": "", "host_total_ns": 100},
    ], ("host_busy_ns",), "host_total_ns")
    assert stat["weighted_mean"] == 20
    assert stat["n"] == 1
    assert stat["invalid_intervals"] == 2
    assert stat["missing"] == 1


def test_missing_timing_and_negative_differences_are_disclosed(tmp_path):
    path = write_run(tmp_path / "usr-per-nat-1")
    rows = compare.read_csv(path / "windows.csv")
    rows[0]["eval_end_ns"] = int(rows[0]["eval_start_ns"]) - 1
    rows[1]["eval_end_ns"] = ""
    rows[1]["blocked_at_ns"] = ""
    write_csv(path / "windows.csv", rows)
    run = compare.describe_run(path)
    assert run["latency_ms"]["evaluation"]["n"] == 0
    assert run["latency_ms"]["evaluation"]["invalid_negative"] == 1
    assert run["latency_ms"]["evaluation"]["missing"] == 1
    assert run["latency_ms"]["evaluation"]["p50"] is None
    assert run["latency_ms"]["block_update"]["missing"] == 1
    assert any("Negative timestamp" in w for w in run["warnings"])
    json.dumps(run, allow_nan=False)


def test_offline_clocks_are_not_subtracted_and_are_excluded_by_default(tmp_path):
    write_run(tmp_path / "ref-pcap", source="pcap", block=False)
    write_run(tmp_path / "usr-per-nat-1")
    report = compare.build_report([tmp_path])
    assert len(report["runs"]) == 1
    offline = compare.describe_run(tmp_path / "ref-pcap")
    assert set(offline["latency_ms"]) == {"evaluation", "queue"}
    assert len(compare.build_report([tmp_path], include_offline=True)["runs"]) == 2


def test_unknown_mode_is_not_silently_assigned_to_generic_and_inputs_deduplicate(tmp_path):
    write_run(tmp_path / "ker-acc-per-1", source="xdp")
    write_run(tmp_path / "ker-per-gen-2", source="xdp")
    write_run(tmp_path / "usr-per-gen-1")
    report = compare.build_report([tmp_path, tmp_path / "ker-per-gen-2"])
    assert len(report["runs"]) == 3
    assert len(report["groups"]) == 3
    assert len(report["comparisons"]) == 1
    assert len(report["comparisons"][0]["kernel_runs"]) == 1
    unknown = next(r for r in report["runs"] if r["name"] == "ker-acc-per-1")
    assert unknown["attachment_label"] is None
    assert unknown["blocking"] is True


def test_repetitions_are_summarized_as_runs_not_pooled_windows(tmp_path):
    first = write_run(tmp_path / "usr-per-nat-1")
    second = write_run(tmp_path / "usr-per-nat-2")
    a, b = compare.describe_run(first), compare.describe_run(second)
    a["latency_ms"]["decision"] = compare.summary([1])
    b["latency_ms"]["decision"] = compare.summary([9] * 100)
    group = compare.group_runs([a, b])[0]
    assert group["n_runs"] == 2
    assert group["metrics"]["decision_p50_ms"]["p50"] == 5
    assert group["metrics"]["decision_p50_ms"]["n"] == 2


def test_blocking_filter_and_saved_warnings(tmp_path):
    path = write_run(tmp_path / "usr-acc-nat-1", block=False)
    write_run(tmp_path / "usr-per-nat-1", block=True)
    evaluation = tmp_path / "eval-usr-acc-nat-1"
    evaluation.mkdir()
    (evaluation / "metrics.json").write_text(json.dumps({"warnings": ["alignment ambiguous"]}))
    report = compare.build_report([tmp_path], blocking="off")
    assert len(report["runs"]) == 1
    assert "evaluation: alignment ambiguous" in report["runs"][0]["warnings"]
    assert compare.describe_run(path)["memory"]["main_mib"]["p50"] is None


@pytest.mark.parametrize("value", ["nan", "inf", "1.792699e18", "bad"])
def test_bad_timestamps_fail_instead_of_being_rounded(value):
    with pytest.raises(ValueError):
        compare.number({"end_ns": value}, "end_ns")


def test_cli_emits_strict_json_and_preserves_source_files(tmp_path, capsys):
    path = write_run(tmp_path / "usr-per-nat-1")
    out = tmp_path / "comparison.json"
    assert compare.main([str(tmp_path), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["schema_version"] == 1
    original = (path / "run.json").read_text()
    with pytest.raises(SystemExit) as exc:
        compare.main([str(tmp_path), "--out", str(path / "run.json")])
    assert exc.value.code == 2
    assert (path / "run.json").read_text() == original
    assert "preserve measurements" in capsys.readouterr().err
