"""Regression checks for plots that must preserve measurement semantics."""

import json
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from analysis import plot


S = 1_000_000_000
T0 = 1_792_678_145_581_645_824


def write_run(directory, *, source="live", block=False, rows=None):
    """A small raw detector run; names deliberately do not encode scenario."""
    directory.mkdir(parents=True)
    if rows is None:
        rows = [
            {"start_ns": T0, "end_ns": T0 + S, "packets": 100,
             "bytes": 2_000_000, "kernel_drops": 10,
             "blocked_packets": 20, "evaluated": "true", "malicious": "true"},
            {"start_ns": T0 + S, "end_ns": T0 + 3 * S, "packets": 300,
             "bytes": 1_000_000, "kernel_drops": "",
             "blocked_packets": 40, "evaluated": "false", "malicious": ""},
            # There is a real two-second gap before the last window.
            {"start_ns": T0 + 5 * S, "end_ns": T0 + 6 * S,
             "packets": 50, "bytes": "", "kernel_drops": 0,
             "blocked_packets": "", "evaluated": "true", "malicious": "false"},
        ]
    for i, row in enumerate(rows):
        row.setdefault("epoch", T0 // S + i)
    pd.DataFrame(rows).to_csv(directory / "windows.csv", index=False)
    (directory / "run.json").write_text(json.dumps({
        "source": source,
        "config": {"block": block, "window_length": "1s", "mode": "combined"},
    }), encoding="utf-8")
    return directory


def write_evaluation(run, directory, saved_path=None):
    """Copy every raw window while retaining its original wall-clock start."""
    directory.mkdir()
    frame = pd.read_csv(run / "windows.csv", dtype=str, keep_default_na=False)
    frame["wall_start_ns"] = frame["start_ns"]
    for column in ("start_ns", "end_ns"):
        frame[column] = frame[column].map(lambda value: int(value) - 100 * S)
    frame["truth"] = "true"
    frame["excluded"] = ""
    frame.iloc[::-1].to_csv(directory / "windows.csv", index=False)
    (directory / "metrics.json").write_text(json.dumps({
        "run": {"run_dir": saved_path or f"/test/results/{run.name}"},
    }), encoding="utf-8")
    return directory


def test_raw_csv_preserves_integer_time_and_unmeasured_values(tmp_path):
    run = write_run(tmp_path / "run")

    windows = plot.read_windows(run / "windows.csv")

    assert windows.start_ns.tolist() == [T0, T0 + S, T0 + 5 * S]
    assert windows.end_ns.tolist() == [T0 + S, T0 + 3 * S, T0 + 6 * S]
    assert pd.api.types.is_integer_dtype(windows.start_ns.dtype)
    assert windows.evaluated.tolist() == [True, False, True]
    assert windows.malicious.iloc[0] == True
    assert pd.isna(windows.malicious.iloc[1])
    assert windows.malicious.iloc[2] == False
    assert str(windows.malicious.dtype) == "boolean"
    assert pd.isna(windows.kernel_drops.iloc[1])
    assert pd.isna(windows.blocked_packets.iloc[2])


def test_rates_use_each_window_duration_and_do_not_subtract_blocked_twice(tmp_path):
    run = write_run(tmp_path / "run")
    windows = plot.read_windows(run / "windows.csv")

    rates = plot.traffic_series(windows)

    # packets already excludes packets blocked at XDP. Dividing by the
    # observed duration, rather than the configured 1s, also matters here.
    assert rates["processed_pps"].tolist() == pytest.approx([100, 150, 50])
    assert rates["blocked_pps"].iloc[:2].tolist() == pytest.approx([20, 20])
    assert pd.isna(rates["blocked_pps"].iloc[2])
    assert rates["processed_MBps"].iloc[:2].tolist() == pytest.approx([2, 0.5])
    assert pd.isna(rates["processed_MBps"].iloc[2])
    assert rates["accounted_pps"].iloc[0] == pytest.approx(130)
    assert pd.isna(rates["accounted_pps"].iloc[1])
    assert pd.isna(rates["accounted_pps"].iloc[2])


def test_xdp_accounting_does_not_require_a_capture_socket_counter(tmp_path):
    run = write_run(tmp_path / "run", source="xdp")
    windows = plot.read_windows(run / "windows.csv")

    rates = plot.traffic_series(windows, source="xdp")

    # XDP has no capture socket: its blank socket-loss field does not make
    # the measured post-blocking + blocked count unknown.
    assert rates["accounted_pps"].iloc[:2].tolist() == pytest.approx([120, 170])
    assert pd.isna(rates["accounted_pps"].iloc[2])


def test_plot_coordinates_keep_observed_gaps_and_window_extents(tmp_path):
    run = write_run(tmp_path / "run")
    windows = plot.read_windows(run / "windows.csv")
    rates = plot.traffic_series(windows)

    x, y = plot.step_coordinates(windows, rates["processed_pps"], T0)

    np.testing.assert_allclose(x, [0, 1, 1, 3, np.nan, 5, 6], equal_nan=True)
    np.testing.assert_allclose(y, [100, 100, 150, 150, np.nan, 50, 50], equal_nan=True)


def test_discovery_uses_raw_artifacts_and_ignores_evaluation_tables(tmp_path):
    first = write_run(tmp_path / "first")
    nested = write_run(tmp_path / "nested" / "second")
    evaluation = tmp_path / "eval-first"
    evaluation.mkdir()
    (evaluation / "metrics.json").write_text("{}", encoding="utf-8")
    pd.DataFrame({"start_ns": [T0], "end_ns": [T0 + S], "truth": [True]}).to_csv(
        evaluation / "windows.csv", index=False)
    incomplete = tmp_path / "incomplete"
    incomplete.mkdir()
    (incomplete / "run.json").write_text("{}", encoding="utf-8")

    assert set(plot.discover_runs(tmp_path)) == {first, nested}
    assert plot.discover_runs(first) == [first]


@pytest.mark.parametrize("saved_path", ["/home/test/results/odd-name/", "C:\\test\\results\\odd-name\\"])
def test_evaluation_mapping_uses_saved_run_metadata(tmp_path, saved_path):
    run = write_run(tmp_path / "odd-name")
    evaluation = write_evaluation(run, tmp_path / "unrelated-evaluation-name", saved_path)

    assert plot.evaluation_for(run) == evaluation


def test_explicit_evaluation_rejects_a_different_run(tmp_path):
    run = write_run(tmp_path / "run")
    evaluation = write_evaluation(run, tmp_path / "evaluation", "/test/results/another-run")

    with pytest.raises(ValueError, match="different run"):
        plot.evaluation_for(run, evaluation)


@pytest.mark.parametrize("column", ["packets", "wall_start_ns"])
@pytest.mark.parametrize("explicit", [False, True])
def test_evaluation_rejects_stale_windows_even_if_name_matches(tmp_path, column, explicit):
    run = write_run(tmp_path / "run")
    evaluation = write_evaluation(run, tmp_path / "evaluation")
    frame = pd.read_csv(evaluation / "windows.csv", dtype=str, keep_default_na=False)
    # Corrupt a later raw window, not just the first window or aggregate total.
    frame.loc[0, column] = str(int(frame.loc[0, column]) + 1)
    frame.to_csv(evaluation / "windows.csv", index=False)

    with pytest.raises(ValueError, match="does not match raw run"):
        plot.evaluation_for(run, evaluation if explicit else None)


def test_cli_rejects_repeated_run_basenames_before_overwriting_plots(tmp_path, capsys):
    write_run(tmp_path / "cohort-a" / "same-name")
    write_run(tmp_path / "cohort-b" / "same-name")

    assert plot.main([str(tmp_path), "--kind", "traffic", "--out", str(tmp_path / "out")]) == 1

    assert "duplicate run directory names" in capsys.readouterr().err
    assert not list((tmp_path / "out").rglob("*.png"))


def test_accuracy_excludes_warmup_and_unknown_truth_or_verdict(tmp_path):
    rows = []
    for i, (truth, pred, evaluated, excluded) in enumerate([
        ("true", "false", "true", ""),
        ("true", "true", "true", "warmup"),
        ("", "true", "true", ""),
        ("false", "false", "false", ""),
        ("false", "", "true", ""),
    ]):
        rows.append({"start_ns": T0 + i * S, "end_ns": T0 + (i + 1) * S,
                     "truth": truth, "malicious": pred,
                     "evaluated": evaluated, "excluded": excluded})
    run = write_run(tmp_path / "evaluation", rows=rows)

    truth, predicted, scored = plot.accuracy_values(plot.read_windows(run / "windows.csv"))

    assert scored.tolist() == [True, False, False, False, False]
    assert truth.iloc[0] == True and predicted.iloc[0] == False
    assert truth.iloc[1:].isna().all() and predicted.iloc[1:].isna().all()


def test_combined_prediction_preserves_unknown_ip_verdict(tmp_path):
    rows = [{"start_ns": T0 + i * S, "end_ns": T0 + (i + 1) * S,
             "truth": "true", "evaluated": "true", "excluded": "",
             "malicious": malicious, "flagged_ips": flagged}
            for i, (malicious, flagged) in enumerate([
                ("false", ""), ("true", ""), ("", "1"), ("", "0"),
            ])]
    run = write_run(tmp_path / "evaluation", rows=rows)

    truth, predicted, scored = plot.accuracy_values(
        plot.read_windows(run / "windows.csv"), "window_or_ip")

    assert scored.tolist() == [False, True, True, False]
    assert predicted.iloc[1:3].tolist() == [True, True]
    assert predicted.iloc[[0, 3]].isna().all()
    assert truth.iloc[[0, 3]].isna().all()


def test_resource_plot_includes_samples_outside_verdict_window_extent(tmp_path, monkeypatch):
    run = write_run(tmp_path / "run", block=True)
    pd.DataFrame({"ts_ns": [T0 - S, T0 + 10 * S], "main": [1024, 2048],
                  "current": [4096, 8192]}).to_csv(run / "memory.csv", index=False)
    extents = {}

    def capture_save(figure, directory, name, formats):
        extents[name] = figure.axes[0].get_xlim()
        plot.plt.close(figure)
        return []

    monkeypatch.setattr(plot, "save", capture_save)
    plot.plot_resources(run, tmp_path / "out", ["png"])

    assert extents["memory"] == pytest.approx((-1, 10))


def test_headless_cli_discovers_resources_by_metadata_and_exports_formats(tmp_path):
    # This looks like an accuracy name, but metadata says blocking/performance.
    run = write_run(tmp_path / "misleading-accuracy-name", source="xdp", block=True)
    pd.DataFrame({"ts_ns": [T0, T0 + S], "host_busy_ns": [200, 600],
                  "host_total_ns": [1000, 1000], "host_softirq_ns": [100, 400],
                  "host_max_core_share": [0.3, 0.8]}).to_csv(run / "cpu.csv", index=False)
    pd.DataFrame({"ts_ns": [T0, T0 + S], "main": [1024, 2048],
                  "current": [4096, 8192]}).to_csv(run / "memory.csv", index=False)
    info = json.loads((run / "run.json").read_text(encoding="utf-8"))
    info["bpf_memory"] = {"total_bytes": 256, "start_total_bytes": 256}
    (run / "run.json").write_text(json.dumps(info), encoding="utf-8")
    out = tmp_path / "plots"

    command = [sys.executable, "-m", "analysis.plot", str(run), "--out", str(out),
               "--format", "png", "pdf", "--xlim", "0", "6", "--symlog"]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[2],
                            capture_output=True, text=True, timeout=60)

    assert result.returncode == 0, result.stderr
    manifest = json.loads((out / "plot_manifest.json").read_text(encoding="utf-8"))
    assert manifest["errors"] == []
    record, = manifest["plots"]
    assert record["blocking"] is True
    outputs = {Path(path).name: Path(path) for path in record["outputs"]}
    for name in ("traffic", "memory", "host_cpu", "host_softirq", "busiest_core"):
        assert outputs[f"{name}.png"].read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert outputs[f"{name}.pdf"].read_bytes().startswith(b"%PDF-")
    assert not any("accuracy" in name for name in outputs)


def test_missing_evaluation_reports_unavailable_truth_in_manifest(tmp_path):
    run = write_run(tmp_path / "run", block=False)
    out = tmp_path / "plots"

    assert plot.main([str(run), "--out", str(out)]) == 0

    manifest = json.loads((out / "plot_manifest.json").read_text(encoding="utf-8"))
    record, = manifest["plots"]
    assert any("truth cannot be inferred" in warning for warning in record["warnings"])
    assert not any("accuracy_" in Path(path).name for path in record["outputs"])


def test_accuracy_figure_keeps_alignment_warning_visible(tmp_path, monkeypatch):
    evaluation = write_run(tmp_path / "evaluation", rows=[{
        "start_ns": T0, "end_ns": T0 + S, "truth": "true",
        "evaluated": "true", "excluded": "", "malicious": "true",
    }])
    warning = "the alignment is ambiguous"
    (evaluation / "metrics.json").write_text(json.dumps({"warnings": [warning]}), encoding="utf-8")
    captured = []

    def capture_save(figure, *args):
        captured.extend(text.get_text() for text in figure.texts)
        plot.plt.close(figure)
        return []

    monkeypatch.setattr(plot, "save", capture_save)
    plot.plot_accuracy(evaluation, tmp_path / "out", ["png"])

    assert any("PROVISIONAL" in text for text in captured)
    assert any(warning in text for text in captured)
