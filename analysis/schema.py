"""The common label format every dataset loader produces.

Each row is a time interval with a label, usually one labelled flow:

    start_ns, end_ns   interval in ns since the Unix epoch, UTC, end >= start
    label              the dataset's own label text, e.g. "BENIGN", "Syn"
    is_attack          whether the label denotes malicious traffic
    src_ip, dst_ip     addresses as text                     (may be null)
    src_port, dst_port ports                                 (may be null)
    protocol           IP protocol number                    (may be null)
    packets            packets in the interval, both ways    (may be null)
    source_file        file the row came from, for tracing

Only start_ns, end_ns, label, is_attack and source_file are required. The
rest may be null for datasets that do not provide them. Code after the
loaders must depend on nothing but this format.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

_DICT = pa.dictionary(pa.int32(), pa.string())

SCHEMA = pa.schema(
    [
        ("start_ns", pa.int64()),
        ("end_ns", pa.int64()),
        ("label", _DICT),
        ("is_attack", pa.bool_()),
        ("src_ip", pa.string()),
        ("dst_ip", pa.string()),
        ("src_port", pa.int32()),
        ("dst_port", pa.int32()),
        ("protocol", pa.int16()),
        ("packets", pa.int64()),
        ("source_file", _DICT),
    ]
)

COLUMNS = SCHEMA.names

REQUIRED = ("start_ns", "end_ns", "label", "is_attack", "source_file")


class SchemaError(ValueError):
    """Raised when data does not follow the common label format."""


def to_table(df: pd.DataFrame) -> pa.Table:
    """Convert a DataFrame to a table in the common format.

    Columns from SCHEMA that are missing in df are filled with nulls;
    columns not in SCHEMA are ignored.
    """
    n = len(df)
    arrays = []

    for field in SCHEMA:
        if field.name in df.columns:
            col = df[field.name]
        else:
            col = pd.Series([None] * n, dtype=object)

        if pa.types.is_dictionary(field.type):
            arr = pa.array(col.astype(object), type=pa.string(), from_pandas=True).dictionary_encode()
        else:
            arr = pa.array(col, type=field.type, from_pandas=True)

        arrays.append(arr)

    return pa.Table.from_arrays(arrays, schema=SCHEMA)


def validate(table: pa.Table) -> None:
    """Raise SchemaError unless table follows the common label format."""
    if table.schema.names != COLUMNS:
        raise SchemaError(f"columns are {table.schema.names}, want {COLUMNS}")

    for field in SCHEMA:
        got = table.schema.field(field.name).type
        if not got.equals(field.type):
            raise SchemaError(f"column {field.name} has type {got}, want {field.type}")

    for name in REQUIRED:
        nulls = table.column(name).null_count
        if nulls:
            raise SchemaError(f"column {name} has {nulls} null values")

    if table.num_rows and pc.any(pc.less(table.column("end_ns"), table.column("start_ns"))).as_py():
        raise SchemaError("some rows end before they start")


def write(table: pa.Table, path: str | Path) -> None:
    validate(table)
    pq.write_table(table, path)


def read(path: str | Path) -> pd.DataFrame:
    """Read and validate a label file. label and source_file come back as
    categoricals; nullable integer columns as pandas nullable dtypes."""
    table = pq.read_table(path)
    validate(table)

    return table.to_pandas(
        types_mapper={
            pa.int32(): pd.Int32Dtype(),
            pa.int16(): pd.Int16Dtype(),
        }.get
    )
