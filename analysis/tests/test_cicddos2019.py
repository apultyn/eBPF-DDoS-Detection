"""Tests for the CIC-DDoS2019 loader, on small synthetic CSVs."""

from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import pytest

from analysis import schema
from analysis.datasets import cicddos2019 as cic
from analysis.timefmt import parse_offset

# The real files have a leading index column, Flow ID, stray spaces in the
# names and many feature columns we do not read.
HEADER = ["Unnamed: 0", "Flow ID", " Source IP", " Source Port", " Destination IP",
          " Destination Port", " Protocol", " Timestamp", " Flow Duration",
          " Total Fwd Packets", " Total Backward Packets", "Total Length of Fwd Packets",
          " Label"]

HOUR_NS = 3600 * 10**9


def row(src="172.16.0.5", sport=1000, dst="192.168.50.1", dport=53, proto=17,
        ts="2018-11-03 13:00:00.000000", dur=1_000_000, fwd=3, bwd=1, label="DrDoS_DNS",
        flow_id="x"):
    return {"Unnamed: 0": 0, "Flow ID": flow_id, " Source IP": src, " Source Port": sport,
            " Destination IP": dst, " Destination Port": dport, " Protocol": proto,
            " Timestamp": ts, " Flow Duration": dur, " Total Fwd Packets": fwd,
            " Total Backward Packets": bwd, "Total Length of Fwd Packets": 100, " Label": label}


def write_csv(path: Path, rows, header=HEADER):
    pd.DataFrame(rows).reindex(columns=header).to_csv(path, index=False)
    return path


def convert(tmp_path, inputs, offset="+3h", chunksize=cic.DEFAULT_CHUNKSIZE):
    out = tmp_path / "out.parquet"
    meta = cic.convert(inputs, out, parse_offset(offset), chunksize=chunksize, log=lambda _: None)
    return schema.read(out), meta


def test_output_follows_common_schema(tmp_path):
    f = write_csv(tmp_path / "a.csv", [row(), row(label="BENIGN", sport=2000)])

    out = tmp_path / "out.parquet"
    cic.convert([f], out, 0, log=lambda _: None)

    # The written file must validate as-is, without any conversion.
    schema.validate(pq.read_table(out))


def test_trimmed_names_and_any_column_order(tmp_path):
    reordered = list(reversed(HEADER))
    f = write_csv(tmp_path / "a.csv", [row()], header=reordered)

    df, _ = convert(tmp_path, [f])

    r = df.iloc[0]
    assert (r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.protocol) == ("172.16.0.5", 1000, "192.168.50.1", 53, 17)
    assert r.label == "DrDoS_DNS" and r.packets == 4 and r.source_file == "a.csv"


def test_missing_column_is_reported(tmp_path):
    header = [h for h in HEADER if h.strip() != "Flow Duration"]
    f = write_csv(tmp_path / "a.csv", [row()], header=header)

    with pytest.raises(cic.ColumnError, match="Flow Duration"):
        convert(tmp_path, [f])


def test_offset_and_flow_duration(tmp_path):
    f = write_csv(tmp_path / "a.csv", [row(ts="2018-11-03 13:00:00.250000", dur=1_500_000)])

    df, meta = convert(tmp_path, [f], offset="+3h")

    local = pd.Timestamp("2018-11-03 13:00:00.25").value
    assert df.start_ns[0] == local + 3 * HOUR_NS
    assert df.end_ns[0] == df.start_ns[0] + 1_500_000 * 1000

    first = meta["labels"][0]["first_start"]
    assert first["local"] == "2018-11-03T13:00:00.250000"
    assert first["utc"] == "2018-11-03T16:00:00.250000Z"


def test_negative_offset_and_timestamp_without_fraction(tmp_path):
    f = write_csv(tmp_path / "a.csv", [row(ts="2018-11-03 13:00:00")])

    df, _ = convert(tmp_path, [f], offset="-2h")

    assert df.start_ns[0] == pd.Timestamp("2018-11-03 11:00:00").value


def test_duplicates_across_files_dropped_within_file_kept(tmp_path):
    a = write_csv(tmp_path / "a.csv", [row(sport=1), row(sport=1), row(sport=2)])
    b = write_csv(tmp_path / "b.csv", [row(sport=2, flow_id="other"), row(sport=3)])

    df, meta = convert(tmp_path, [a, b])

    # a keeps its internal duplicate; b loses the flow already in a.
    assert sorted(df.src_port) == [1, 1, 2, 3]
    assert meta["duplicates_within_files"] == 1
    assert meta["duplicates_of_earlier_files"] == 1
    assert meta["files"][1]["duplicates_of_earlier_files"] == 1


def test_label_conflicts_are_counted(tmp_path):
    a = write_csv(tmp_path / "a.csv", [row(sport=1, label="BENIGN"), row(sport=2, label="Syn")])
    b = write_csv(tmp_path / "b.csv", [row(sport=1, label="Syn"), row(sport=2, label="Syn")])

    df, meta = convert(tmp_path, [a, b])

    # The first occurrence wins.
    assert df.set_index("src_port").label[1] == "BENIGN"
    assert meta["label_conflicts_across_files"] == {"BENIGN<->Syn": 1}


def test_broken_rows_are_counted_not_fatal(tmp_path):
    rows = [
        row(sport=1),
        row(sport=2, ts="not a time"),
        row(sport=3, dur="abc"),
        row(sport=4, dur=-5),
        row(sport=5, src=""),
        {h: h for h in HEADER},  # a header line repeated mid-file
    ]
    f = write_csv(tmp_path / "a.csv", rows)

    df, meta = convert(tmp_path, [f])

    assert list(df.src_port) == [1]
    assert meta["rows_skipped"] == {
        "bad_timestamp": 1,
        "bad_number": 1,
        "negative_duration": 1,
        "missing_field": 1,
        "repeated_header": 1,
    }


def test_chunked_reading_matches_single_pass(tmp_path):
    rows = [row(sport=i % 7, ts=f"2018-11-03 13:00:{i % 60:02d}", label=["BENIGN", "Syn"][i % 2])
            for i in range(50)]
    a = write_csv(tmp_path / "a.csv", rows[:30])
    b = write_csv(tmp_path / "b.csv", rows[20:])

    whole, meta_whole = convert(tmp_path, [a, b], chunksize=10_000)
    (tmp_path / "out.parquet").unlink()
    chunked, meta_chunked = convert(tmp_path, [a, b], chunksize=3)

    pd.testing.assert_frame_equal(whole.reset_index(drop=True), chunked.reset_index(drop=True))
    assert meta_whole["labels"] == meta_chunked["labels"]
    assert meta_whole["duplicates_of_earlier_files"] == meta_chunked["duplicates_of_earlier_files"]
    assert meta_whole["duplicates_within_files"] == meta_chunked["duplicates_within_files"]


def test_summary_per_label_and_file(tmp_path):
    a = write_csv(tmp_path / "a.csv", [
        row(sport=1, label="BENIGN", ts="2018-11-03 10:00:00", dur=2_000_000, fwd=1, bwd=1),
        row(sport=2, label="Syn", ts="2018-11-03 13:30:00", dur=1_000_000, fwd=10, bwd=0),
        row(sport=3, label="Syn", ts="2018-11-03 14:00:00", dur=5_000_000, fwd=5, bwd=5),
    ])

    _, meta = convert(tmp_path, [a], offset="+0h")

    syn = next(s for s in meta["labels"] if s["label"] == "Syn")
    assert syn["flows"] == 2 and syn["packets"] == 20 and syn["is_attack"]
    assert syn["first_start"]["local"] == "2018-11-03T13:30:00.000000"
    assert syn["last_end"]["local"] == "2018-11-03T14:00:05.000000"

    benign = next(s for s in meta["labels"] if s["label"] == "BENIGN")
    assert not benign["is_attack"]

    assert meta["files"][0]["flows_per_label"] == {"BENIGN": 1, "Syn": 2}
    assert meta["csv_timestamp_range"]["earliest"]["local"] == "2018-11-03T10:00:00.000000"
    assert meta["csv_timestamp_range"]["latest"]["local"] == "2018-11-03T14:00:00.000000"
    assert meta["warnings"] == []


def test_warns_when_no_afternoon_timestamps(tmp_path):
    f = write_csv(tmp_path / "a.csv", [row(ts="2018-11-03 01:30:00"), row(ts="2018-11-03 12:59:59", sport=9)])

    _, meta = convert(tmp_path, [f])

    assert any("12-hour" in w for w in meta["warnings"])


def test_directory_input_in_natural_order(tmp_path):
    d = tmp_path / "day"
    d.mkdir()
    for name in ["UDP_10.csv", "UDP_2.csv", "Syn.csv"]:
        write_csv(d / name, [row()])
    (d / "notes.txt").write_text("not a csv")

    assert [p.name for p in cic.list_inputs([d])] == ["Syn.csv", "UDP_2.csv", "UDP_10.csv"]
