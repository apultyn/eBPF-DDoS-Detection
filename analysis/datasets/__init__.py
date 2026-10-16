"""Dataset loaders.

A loader turns one dataset's label files into the common label format of
analysis.schema. Everything specific to the dataset belongs in its loader:
column names, timestamp format and time zone, the unit of durations, which
labels are benign, and how duplicates are handled.

A loader module provides:

    NAME: str
    convert(inputs, out, time_offset_ns, chunksize=..., log=print) -> dict

convert reads the files in inputs (files or directories), writes a parquet
file in the common format to out, and returns a JSON-serialisable dict of
metadata and summaries for the caller to save and print.
"""

from . import cicddos2019

LOADERS = {
    cicddos2019.NAME: cicddos2019,
}
