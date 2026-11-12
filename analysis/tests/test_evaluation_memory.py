"""Memory regressions and equivalence to full per-flow label evaluation."""

import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import pytest

from analysis import alignment, evaluate, groundtruth, schema
from analysis.tests.test_evaluate import LEN, T0, write_run


@pytest.mark.parametrize("batch_size", [1, 7, 128, 4096])
def test_batch_compaction_preserves_scores_latency_and_warnings(tmp_path, batch_size):
    rng = np.random.default_rng(19)
    n = 1000
    starts = T0 + rng.integers(-10 * LEN, 100 * LEN, n)
    labels = pd.DataFrame({
        "start_ns": starts,
        "end_ns": starts + rng.integers(0, 4 * LEN, n),
        "label": rng.choice(["Syn", "UDP", "BENIGN"], n),
        "source_file": "capture.csv",
        "src_ip": [f"192.0.2.{i % 255}" for i in range(n)],
    })
    labels["is_attack"] = labels["label"] != "BENIGN"
    path = tmp_path / "labels.parquet"
    schema.write(schema.to_table(labels), path)
    full = schema.read(path)
    compact = groundtruth.read_labels(path, batch_size=batch_size)
    assert len(compact) < len(full)
    assert compact.start_ns.min() == full.start_ns.min()
    assert compact.end_ns.max() == full.end_ns.max()

    run = evaluate.load_run(write_run(tmp_path / "run", [i % 3 == 0 for i in range(100)]))
    for excerpt in (None, {"trace_start_ns": T0 + 5 * LEN, "trace_end_ns": T0 + 90 * LEN}):
        old = evaluate.evaluate_day("test", full, run, warmup=2, excerpt=excerpt)
        new = evaluate.evaluate_day("test", compact, run, warmup=2, excerpt=excerpt)
        assert new["scores"] == old["scores"]
        assert new["counts"] == old["counts"]
        assert new["warnings"] == old["warnings"]
        pd.testing.assert_frame_equal(new["windows"], old["windows"])
        pd.testing.assert_frame_equal(new["latency"], old["latency"])


def test_batch_reader_does_not_use_whole_table_read(tmp_path, monkeypatch):
    n = 100_000
    frame = pd.DataFrame({"start_ns": np.zeros(n, dtype="int64"),
                          "end_ns": np.full(n, 100, dtype="int64"),
                          "label": "Syn", "is_attack": True, "source_file": "x.csv",
                          "src_ip": "a large unused per-flow field" * 20})
    path = tmp_path / "labels.parquet"
    schema.write(schema.to_table(frame), path)

    def refuse(*args, **kwargs):
        pytest.fail("evaluation must not read the whole label table")

    monkeypatch.setattr(pq, "read_table", refuse)
    compact = groundtruth.read_labels(path, batch_size=1024)
    assert compact[compact.is_attack][["start_ns", "end_ns"]].values.tolist() == [[0, 100]]
    assert len(compact) == 2  # merged attack plus coverage bounds
    for batch in schema.iter_intervals(path, batch_size=1024):
        assert batch.num_rows <= 1024
        assert batch.schema.names == list(schema.REQUIRED)


@pytest.mark.parametrize("rows", [0, 4])
def test_empty_or_benign_only_labels(tmp_path, rows):
    frame = pd.DataFrame({"start_ns": np.arange(rows, dtype="int64"),
                          "end_ns": np.arange(rows, dtype="int64") + 1,
                          "label": ["BENIGN"] * rows, "is_attack": [False] * rows,
                          "source_file": ["x.csv"] * rows})
    path = tmp_path / "labels.parquet"
    schema.write(schema.to_table(frame), path)
    compact = groundtruth.read_labels(path, batch_size=1)
    assert not compact.is_attack.any()
    assert len(compact) == (1 if rows else 0)


@pytest.mark.parametrize("column,value", [("start_ns", None), ("source_file", None), ("end_ns", -1)])
def test_projected_batches_still_validate_required_values(tmp_path, column, value):
    frame = pd.DataFrame({"start_ns": [0], "end_ns": [1], "label": ["Syn"],
                          "is_attack": [True], "source_file": ["x.csv"]})
    frame[column] = value
    path = tmp_path / "labels.parquet"
    pq.write_table(schema.to_table(frame), path)
    with pytest.raises(schema.SchemaError):
        groundtruth.read_labels(path)


def test_reference_is_checked_before_labels_are_loaded(tmp_path, monkeypatch, capsys):
    run = write_run(tmp_path / "live", [False] * 4, source="live")
    excerpt = tmp_path / "excerpt.json"
    excerpt.write_text(json.dumps({"trace_start_ns": T0, "trace_end_ns": T0 + 4 * LEN}))
    pcap = tmp_path / "traffic.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1")

    def refuse(*args, **kwargs):
        pytest.fail("labels loaded before reference validation")

    monkeypatch.setattr(groundtruth, "read_labels", refuse)
    with pytest.raises(SystemExit):
        evaluate.main(["--labels", "unused.parquet", "--run", str(run),
                       "--excerpt", str(excerpt), "--reference", str(pcap), "--out", str(tmp_path / "out")])
    assert "results directory" in capsys.readouterr().err


def test_pcap_cannot_be_loaded_as_large_json_metadata(tmp_path):
    pcap = tmp_path / "traffic.pcap"
    with pcap.open("wb") as target:
        target.write(b"\xd4\xc3\xb2\xa1")
        target.truncate(evaluate.MAX_METADATA_BYTES + 1)
    with pytest.raises(evaluate.RunError, match="too large"):
        evaluate.read_excerpt(pcap)


def test_adaptive_alignment_caps_fft_and_recovers_offset(monkeypatch):
    n = 1000
    length = 500_000_000
    offset = 100_123_000_000
    starts = T0 + np.arange(n, dtype="int64") * length
    counts = np.random.default_rng(29).integers(0, 10000, n)
    ref = alignment.Series.of(starts, starts + length, counts)
    live = alignment.Series.of(starts + offset, starts + length + offset, counts)
    monkeypatch.setattr(alignment, "MAX_GRID_BINS", 4096)
    real_fft = np.fft.rfft
    sizes = []

    def bounded_fft(a, size):
        sizes.append(size)
        assert size <= alignment.MAX_GRID_BINS
        return real_fft(a, size)

    monkeypatch.setattr(np.fft, "rfft", bounded_fft)
    result = alignment.estimate_offset(ref, live)
    assert sizes
    assert result.coarse_step_ns > alignment.COARSE_STEP_NS
    assert abs(result.offset_ns - offset) <= 2 * alignment.FINE_STEP_NS
    assert result.correlation > 0.99


def test_alignment_refuses_empty_series():
    empty = alignment.Series.of([], [], [])
    with pytest.raises(ValueError, match="empty"):
        alignment.estimate_offset(empty, empty)
