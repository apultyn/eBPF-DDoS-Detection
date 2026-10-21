"""End-to-end tests of evaluating live runs, on synthetic runs.

A packet trace is generated, a -pcap reference run of it is written in
500 ms windows on trace time, and a live run of the kernel variant in
2^29 ns windows on the wall clock, eight years and a fraction of a second
later. The detector's verdicts are set from the true attack interval, so a
correct offset gives perfect scores.
"""

import json

import numpy as np
import pandas as pd
import pytest

from analysis import compare, evaluate, schema
from analysis.tests.test_alignment import MS, OFFSET, S, TRACE_T0, packet_times

ATTACK = (TRACE_T0 + 300 * S, TRACE_T0 + 360 * S)

TCPREPLAY = """\
Actual: {n} packets ({b} bytes) sent in {s:.2f} seconds
Rated: 1.0 Bps, 0.001 Mbps, 100.00 pps
Statistics for network device: eth0
\tSuccessful packets:        {n}
\tFailed packets:            0
"""


def write_run(dir_, times, length, source, offset=0, first=None, last=None, block=False):
    """windows.csv and run.json for a run seeing `times` (trace time),
    stamped on a clock `offset` ahead, in windows of `length` ns."""
    dir_.mkdir(parents=True)
    stamped = times + offset
    first = stamped[0] if first is None else first
    last = stamped[-1] if last is None else last
    edges = np.arange((first // length) * length, last + length, length, dtype=np.int64)
    counts, _ = np.histogram(stamped, bins=edges)

    trace_start, trace_end = edges[:-1] - offset, edges[1:] - offset
    # The detector flags exactly the windows whose combined span overlaps
    # the attack, so a correct alignment scores perfectly.
    span_start = trace_start - length
    malicious = (span_start <= ATTACK[1]) & (trace_end > ATTACK[0])

    evaluated = np.ones(len(counts), dtype=bool)
    evaluated[0] = False

    pd.DataFrame({
        "epoch": edges[:-1] // length,
        "start_ns": edges[:-1],
        "end_ns": edges[1:],
        "packets": counts,
        "evaluated": np.where(evaluated, "true", "false"),
        "malicious": np.where(evaluated, np.where(malicious, "true", "false"), ""),
        "flagged_ips": np.where(evaluated, "0", ""),
    }).to_csv(dir_ / "windows.csv", index=False)

    length_text = "500ms" if length == 500 * MS else "536.870912ms"
    info = {
        "source": source,
        "config": {"window_length": length_text, "mode": "combined", "block": block},
        "stats": {"packets": int(counts.sum()), "blocked_packets": 0},
    }
    if source == "live":
        info["live"] = {"socket": {"kernel_total": int(counts.sum()), "kernel_dropped": 0},
                        "nic_delta": {"dev.rx_packets": int(counts.sum()), "dev.rx_drop": 0}}
    (dir_ / "run.json").write_text(json.dumps(info))
    return dir_


@pytest.fixture
def setup(tmp_path):
    times = packet_times(seconds=600, seed=4)

    labels = pd.DataFrame({
        "start_ns": [times[0], ATTACK[0]],
        "end_ns": [times[-1], ATTACK[1]],
        "label": ["BENIGN", "Syn"],
        "is_attack": [False, True],
        "source_file": ["x.csv", "x.csv"],
    })
    schema.write(schema.to_table(labels), tmp_path / "labels.parquet")

    excerpt = {"file": "ex.pcap", "trace_start_ns": int(times[0]), "trace_end_ns": int(times[-1]),
               "trace_start": "start", "trace_end": "end", "packets_ip": int(times.size), "max_gap_s": 0.0}
    (tmp_path / "ex.excerpt.json").write_text(json.dumps(excerpt))

    ref = write_run(tmp_path / "ref", times, 500 * MS, "pcap")

    return {"tmp": tmp_path, "times": times, "ref": ref, "labels": tmp_path / "labels.parquet",
            "excerpt": tmp_path / "ex.excerpt.json"}


def live_run(setup, name="live", drop=0.0, block=False, source="xdp"):
    """The kernel variant, started 5 s into the replay and left running 30 s after it."""
    times = setup["times"]
    seen = times[times > times[0] + 5 * S]
    if drop:
        keep = np.random.default_rng(9).random(seen.size) >= drop
        seen = seen[keep]
    d = write_run(setup["tmp"] / name, seen, 1 << 29, source, offset=OFFSET,
                  last=times[-1] + OFFSET + 30 * S, block=block)
    span = (times[-1] - times[0]) / 1e9
    (d / "tcpreplay.txt").write_text(TCPREPLAY.format(n=times.size, b=times.size * 60, s=span))
    return d


def evaluate_live(setup, run_dir, out, *extra):
    return evaluate.main(["--labels", str(setup["labels"]), "--run", str(run_dir),
                          "--excerpt", str(setup["excerpt"]), "--reference", str(setup["ref"]),
                          "--out", str(out), *extra])


def test_live_kernel_run_is_aligned_and_scored(setup, capsys):
    out = setup["tmp"] / "eval"
    assert evaluate_live(setup, live_run(setup), out) == 0

    m = json.loads((out / "metrics.json").read_text())
    run = m["run"]

    assert run["variant"] == "kernel" and run["source"] == "xdp" and run["live"]
    assert abs(run["offset"]["offset_ns"] - OFFSET) < 30 * MS
    assert run["offset"]["correlation"] > 0.95

    s = m["scores"]["window"]
    assert s["accuracy"] > 0.99 and s["recall"] > 0.95 and s["TP"] > 50

    c = m["counts"]
    # Idle windows after the replay are left out, not counted as normal.
    assert c["excluded_after_excerpt"] >= 50
    assert c["excluded_warmup"] == 75
    assert 0 < c["attack_window_share"] < 0.2

    assert run["tcpreplay"]["successful"] == setup["times"].size
    assert run["losses"]["window_loss"] == pytest.approx(0, abs=0.01)
    assert not [w for w in m["warnings"] if "did not reach" in w]

    assert "offset" in capsys.readouterr().out


def test_warmup_counts_from_excerpt_start(setup):
    out = setup["tmp"] / "eval"
    evaluate_live(setup, live_run(setup), out, "--warmup", "10")

    w = pd.read_csv(out / "windows.csv", keep_default_na=False)
    warm = w[w.excluded == "warmup"]
    after = w[w.excluded == "after_excerpt"]

    assert len(warm) == 10
    # The warm-up windows are the first evaluated ones inside the excerpt.
    inside = w[(w.excluded == "") | (w.excluded == "warmup")]
    assert list(inside.epoch[:10]) == list(warm.epoch)
    assert after.epoch.min() > inside.epoch.max()


def test_packet_loss_is_reported(setup):
    out = setup["tmp"] / "eval"
    evaluate_live(setup, live_run(setup, drop=0.05), out)

    m = json.loads((out / "metrics.json").read_text())
    assert m["run"]["losses"]["window_loss"] == pytest.approx(0.05, abs=0.01)
    assert any("did not reach the detector" in w for w in m["warnings"])


def test_manual_offset(setup):
    out = setup["tmp"] / "eval"
    rc = evaluate.main(["--labels", str(setup["labels"]), "--run", str(live_run(setup)),
                        "--excerpt", str(setup["excerpt"]), "--offset-ns", str(OFFSET), "--out", str(out)])
    assert rc == 0

    m = json.loads((out / "metrics.json").read_text())
    assert m["run"]["offset"] == {"offset_ns": OFFSET, "method": "manual"}
    assert m["scores"]["window"]["accuracy"] > 0.99


def test_live_run_needs_excerpt_and_offset(setup):
    run = live_run(setup)

    with pytest.raises(SystemExit):
        evaluate.main(["--labels", str(setup["labels"]), "--run", str(run),
                       "--reference", str(setup["ref"]), "--out", str(setup["tmp"] / "a")])
    with pytest.raises(SystemExit):
        evaluate.main(["--labels", str(setup["labels"]), "--run", str(run),
                       "--excerpt", str(setup["excerpt"]), "--out", str(setup["tmp"] / "b")])


def test_blocking_is_refused(setup):
    with pytest.raises(SystemExit):
        evaluate_live(setup, live_run(setup, block=True), setup["tmp"] / "eval")


def test_compare_side_by_side(setup, capsys):
    tmp = setup["tmp"]

    assert evaluate.main(["--labels", str(setup["labels"]), "--run", str(setup["ref"]),
                          "--excerpt", str(setup["excerpt"]), "--out", str(tmp / "e-ref")]) == 0
    assert evaluate_live(setup, live_run(setup, "us", source="live"), tmp / "e-us") == 0
    assert evaluate_live(setup, live_run(setup, "k"), tmp / "e-k") == 0

    rc = compare.main([str(tmp / "e-ref"), str(tmp / "e-us"), str(tmp / "e-k"),
                       "--names", "pcap,us-live,kernel-live", "--out", str(tmp / "cmp")])
    assert rc == 0

    table = pd.read_csv(tmp / "cmp" / "compare.csv")
    assert list(table.run) == ["pcap", "us-live", "kernel-live"]
    assert list(table.variant) == ["userspace", "userspace", "kernel"]
    assert (table.accuracy > 0.99).all()

    lat = pd.read_csv(tmp / "cmp" / "compare_latency.csv", index_col=0)
    assert list(lat.columns) == ["pcap", "us-live", "kernel-live"] and "Syn" in lat.index

    printed = capsys.readouterr().out
    assert "different window lengths" in printed and "fpr" in printed
