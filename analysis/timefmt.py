"""Parsing and printing of durations and timestamps.

All times inside the analysis are integer nanoseconds since the Unix epoch,
the same unit as start_ns and end_ns in the detector's windows.csv.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_UNITS_NS = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60 * 1_000_000_000,
    "h": 3600 * 1_000_000_000,
}

_PART = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")


def parse_duration(text: str) -> int:
    """Parse a Go-style duration such as "500ms", "1h30m" or "-3h" into ns.

    This is the format the detector writes into run.json, so window lengths
    can be read back exactly. A bare "0" is accepted.
    """
    s = text.strip()
    if s in ("0", "+0", "-0"):
        return 0

    sign = 1
    if s[:1] in "+-":
        sign = -1 if s[0] == "-" else 1
        s = s[1:]

    if not s:
        raise ValueError(f"invalid duration {text!r}")

    total = 0.0
    pos = 0
    for m in _PART.finditer(s):
        if m.start() != pos:
            raise ValueError(f"invalid duration {text!r}")
        total += float(m.group(1)) * _UNITS_NS[m.group(2)]
        pos = m.end()

    if pos != len(s):
        raise ValueError(f"invalid duration {text!r}")

    return sign * round(total)


def parse_offset(text: str) -> int:
    """Parse a time offset, the amount added to a dataset's local time to
    get UTC. A sign is required unless the offset is zero, so that the
    direction is always stated explicitly: "+3h", "-4h", "+0h", "0".
    """
    s = text.strip()
    if s not in ("0",) and s[:1] not in "+-":
        raise ValueError(f"time offset {text!r} needs an explicit sign, e.g. +3h or -3h")

    return parse_duration(s)


def format_ns(ns: int, utc: bool = True) -> str:
    """Format ns since the epoch as ISO 8601 with microseconds.

    With utc=True the result ends in "Z". With utc=False the value is taken
    to already be local wall-clock time and is printed without a zone.
    """
    if ns is None:
        return ""

    sec, rem = divmod(int(ns), 1_000_000_000)
    dt = datetime.fromtimestamp(sec, tz=timezone.utc).replace(microsecond=rem // 1000)
    text = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

    return text + "Z" if utc else text


def format_offset(ns: int) -> str:
    """Format an offset in ns as a signed duration, e.g. +3h or -2h30m."""
    sign = "-" if ns < 0 else "+"
    ns = abs(ns)

    h, ns = divmod(ns, _UNITS_NS["h"])
    m, ns = divmod(ns, _UNITS_NS["m"])
    s = ns / _UNITS_NS["s"]

    parts = []
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    if s or not parts:
        parts.append(f"{s:g}s")

    return sign + "".join(parts)
