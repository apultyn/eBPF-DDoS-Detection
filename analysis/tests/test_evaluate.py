"""Tests for evaluation against synthetic detector runs."""

import json

import pandas as pd
import pytest

from analysis import evaluate, schema

MS = 1_000_000
LEN = 500 * MS
T0 = 1_541_260_800 * 10**9  # on a window boundary


def write_run(dir_, malicious, evaluated=None, flagged_ips=None, mode="combined",
              source="pcap", length="500ms"):
    """Write windows.csv and run.json for consecutive windows from T0."""
    dir_.mkdir(parents=True, exist_ok=True)
    n = len(malicious)
    evaluated = evaluated or [True] * n
    flagged_ips = flagged_ips or [0] * n

    rows = []
    for i in range(n):
        ev = evaluated[i]
        rows.append({
            "epoch": T0 // LEN + i,
            "start_ns": T0 + i * LEN,
            "end_ns": T0 + (i + 1) * LEN,
            "evaluated": "true" if ev else "false",
            "malicious": ("true" if malicious[i] else "false") if ev else "",
            "flagged_ips": flagged_ips[i] if ev else "",
            "packets": 100,
        })

    pd.DataFrame(rows).to_csv(dir_ / "windows.csv", index=False)
    (dir_ / "run.json").write_text(json.dumps({
        "source": source,
        "config": {"window_length": length, "mode": mode},
    }))

    return dir_


def labels_frame(intervals, benign=()):
    """Labels from (start_ns, end_ns, label) attack intervals, plus benign
    intervals."""
    rows = [{"start_ns": s, "end_ns": e, "label": l, "is_attack": True} for s, e, l in intervals]
    rows += [{"start_ns": s, "end_ns": e, "label": "BENIGN", "is_attack": False} for s, e in benign]

    df = pd.DataFrame(rows)
    df["source_file"] = "test.csv"
    # Round-trip through the common format, as the real pipeline does.
    return schema.to_table(df).to_pandas()


def window(i):
    return T0 + i * LEN


def test_metrics_after_warmup_and_unevaluated_exclusions(tmp_path):
    # 10 windows: 0 is not evaluated, 1-2 are warm-up, 3-9 are scored.
    # Attack covers windows 5-6; in combined mode the span of window 7
    # reaches back into window 6, so 5, 6 and 7 are attack windows.
    run = evaluate.load_run(write_run(
        tmp_path / "r",
        malicious=[False, True, True, False, True, True, False, False, True, False],
        evaluated=[False] + [True] * 9,
    ))
    labels = labels_frame([(window(5) + 1, window(7) - 1, "Syn")], benign=[(window(0), window(10))])

    d = evaluate.evaluate_day("day", labels, run, warmup=2)

    c = d["counts"]
    assert (c["windows_total"], c["excluded_not_evaluated"], c["excluded_warmup"], c["windows_scored"]) == (10, 1, 2, 7)

    w = d["windows"]
    assert w["excluded"].tolist()[:3] == ["not_evaluated", "warmup", "warmup"]
    assert w["truth"].tolist() == [False, False, False, False, False, True, True, True, False, False]

    # Scored windows 3-9: truth F F T T T F F, predicted F T T F F T F,
    # so TP at 5, FP at 4 and 8, TN at 3 and 9, FN at 6 and 7.
    s = d["scores"]["window"]
    assert (s["TP"], s["FP"], s["TN"], s["FN"]) == (1, 2, 2, 2)
    assert s["accuracy"] == pytest.approx(3 / 7)
    assert s["precision"] == pytest.approx(1 / 3)
    assert s["recall"] == pytest.approx(1 / 3)
    assert s["f1"] == pytest.approx(1 / 3)
    assert s["fpr"] == pytest.approx(2 / 4)


def test_current_mode_span_is_one_window(tmp_path):
    run = evaluate.load_run(write_run(tmp_path / "r", [False] * 4, mode="current"))
    labels = labels_frame([(window(1) + 1, window(2) - 1, "Syn")])

    d = evaluate.evaluate_day("day", labels, run, warmup=0)

    assert d["windows"]["truth"].tolist() == [False, True, False, False]
    assert d["counts"]["span_ns"] == LEN


def test_window_or_ip_prediction(tmp_path):
    run = evaluate.load_run(write_run(tmp_path / "r", [False, False, False], flagged_ips=[0, 2, 0]))
    labels = labels_frame([(window(1), window(1) + 10, "Syn")])

    d = evaluate.evaluate_day("day", labels, run, warmup=0)

    assert d["scores"]["window"]["TP"] == 0
    assert d["scores"]["window_or_ip"]["TP"] == 1


def test_zero_denominators_are_not_numbers(tmp_path):
    run = evaluate.load_run(write_run(tmp_path / "r", [False, False]))
    labels = labels_frame([], benign=[(window(0), window(2))])

    s = evaluate.evaluate_day("day", labels, run, warmup=0)["scores"]["window"]

    assert s["precision"] is None and s["recall"] is None and s["f1"] is None
    assert s["accuracy"] == 1.0


def test_latency_detected_missed_and_not_covered(tmp_path):
    # Syn starts in window 2 and is first flagged in window 4.
    # UDP overlaps windows 7-8, never flagged. LDAP lies in window 0; with
    # two warm-up windows no scored span reaches it (window 2's combined
    # span starts at window 1).
    malicious = [False] * 10
    malicious[4] = True
    run = evaluate.load_run(write_run(tmp_path / "r", malicious))

    labels = labels_frame([
        (window(2) + 100 * MS, window(5), "Syn"),
        (window(7) + 1, window(8) + 1, "UDP"),
        (window(0) + 1, window(0) + 2, "LDAP"),
    ])

    d = evaluate.evaluate_day("day", labels, run, warmup=2)
    lat = d["latency"].set_index(["label", "prediction"])

    syn = lat.loc[("Syn", "window")]
    assert syn.status == "detected"
    assert syn.latency_s == pytest.approx((window(5) - (window(2) + 100 * MS)) / 1e9)

    assert lat.loc[("UDP", "window"), "status"] == "missed"
    assert lat.loc[("LDAP", "window"), "status"] == "not_covered"

    s = d["scores"]["window"]
    assert (s["attacks_total"], s["attacks_detected"], s["attacks_not_covered"]) == (3, 1, 1)


def test_live_runs_need_the_single_run_path(tmp_path):
    with pytest.raises(evaluate.RunError, match="wall clock"):
        evaluate.load_run(write_run(tmp_path / "r", [False], source="live"))

    # Allowed when evaluated on its own, with an offset.
    assert evaluate.load_run(tmp_path / "r", allow_live=True).variant == "userspace"


def test_window_length_must_match_run_json(tmp_path):
    with pytest.raises(evaluate.RunError, match="window_length"):
        evaluate.load_run(write_run(tmp_path / "r", [False], length="1s"))


def test_warns_when_labels_do_not_overlap_windows(tmp_path):
    run = evaluate.load_run(write_run(tmp_path / "r", [False] * 4))
    far = window(0) + 3 * 3600 * 10**9  # three hours off, like a wrong offset
    labels = labels_frame([(far, far + LEN, "Syn")])

    d = evaluate.evaluate_day("day", labels, run, warmup=0)

    assert any("--time-offset" in w for w in d["warnings"])


def test_command_line_two_days_and_total(tmp_path, capsys):
    for day, mal in [("03-11", [False, True, False]), ("01-12", [True, False, False])]:
        write_run(tmp_path / "results" / day, mal)
        schema.write(schema.to_table(labels_frame([(window(1), window(1) + 10, "Syn")])),
                     tmp_path / f"{day}.parquet")

    out = tmp_path / "eval"
    rc = evaluate.main([
        "--day", "03-11", str(tmp_path / "03-11.parquet"), str(tmp_path / "results" / "03-11"),
        "--day", "01-12", str(tmp_path / "01-12.parquet"), str(tmp_path / "results" / "01-12"),
        "--out", str(out), "--warmup", "0",
    ])
    assert rc == 0

    m = pd.read_csv(out / "metrics.csv")
    total = m[(m.day == "all") & (m.prediction == "window")].iloc[0]

    # 03-11: TP in window 1. 01-12: FP in window 0, FN in window 1.
    # Window 2's combined span reaches into window 1 on both days.
    assert (total.TP, total.FP, total.FN) == (1, 1, 3)
    assert (out / "03-11" / "windows.csv").exists() and (out / "01-12" / "latency.csv").exists()
    assert "all" in capsys.readouterr().out
