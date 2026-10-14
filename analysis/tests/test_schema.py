"""Tests for the common label format."""

import pandas as pd
import pyarrow as pa
import pytest

from analysis import schema


def frame(**overrides):
    df = pd.DataFrame({
        "start_ns": [0, 10],
        "end_ns": [5, 20],
        "label": ["BENIGN", "Syn"],
        "is_attack": [False, True],
        "source_file": ["a.csv", "a.csv"],
    })
    for k, v in overrides.items():
        df[k] = v
    return df


def test_optional_columns_may_be_missing():
    t = schema.to_table(frame())

    schema.validate(t)
    assert t.column("src_ip").null_count == 2


def test_round_trip(tmp_path):
    path = tmp_path / "l.parquet"
    schema.write(schema.to_table(frame(src_port=[80, None])), path)

    df = schema.read(path)

    assert df.columns.tolist() == schema.COLUMNS
    assert df.src_port.isna().tolist() == [False, True]


def test_rejects_interval_ending_before_start():
    with pytest.raises(schema.SchemaError, match="end before"):
        schema.validate(schema.to_table(frame(end_ns=[5, 9])))


def test_rejects_missing_required_value():
    with pytest.raises(schema.SchemaError, match="label"):
        schema.validate(schema.to_table(frame(label=["BENIGN", None])))


def test_rejects_wrong_columns():
    t = schema.to_table(frame()).drop(["packets"])

    with pytest.raises(schema.SchemaError, match="columns"):
        schema.validate(t)


def test_rejects_wrong_type():
    t = schema.to_table(frame())
    t = t.set_column(0, "start_ns", pa.array([0.0, 10.0]))

    with pytest.raises(schema.SchemaError, match="start_ns"):
        schema.validate(t)
