"""Parse the summary tcpreplay prints when it finishes.

    Actual: 1000 packets (60000 bytes) sent in 10.00 seconds
    Rated: 6000.0 Bps, 0.048 Mbps, 100.00 pps
    Statistics for network device: eth0
        Successful packets:        1000
        Failed packets:            0
        Truncated packets:         0
        Retried packets (ENOBUFS): 0
        Retried packets (EAGAIN):  0

Fields that are missing come back as None.
"""

from __future__ import annotations

import re
from pathlib import Path

_FIELDS = {
    "actual_packets": r"Actual:\s+(\d+)\s+packets",
    "actual_bytes": r"Actual:\s+\d+\s+packets\s+\((\d+)\s+bytes\)",
    "actual_seconds": r"sent in\s+([\d.]+)\s+seconds",
    "rated_pps": r"Rated:.*?([\d.]+)\s+pps",
    "successful": r"Successful packets:\s+(\d+)",
    "failed": r"Failed packets:\s+(\d+)",
    "truncated": r"Truncated packets:\s+(\d+)",
    "retried_enobufs": r"Retried packets \(ENOBUFS\):\s+(\d+)",
    "retried_eagain": r"Retried packets \(EAGAIN\):\s+(\d+)",
}


def parse(text: str) -> dict:
    out = {}
    for key, pattern in _FIELDS.items():
        m = re.search(pattern, text)
        if m is None:
            out[key] = None
        elif "." in m.group(1):
            out[key] = float(m.group(1))
        else:
            out[key] = int(m.group(1))
    return out


def read(run_dir: Path) -> dict | None:
    """Parse <run_dir>/tcpreplay.txt, or None if there is none."""
    path = run_dir / "tcpreplay.txt"
    if not path.exists():
        return None
    d = parse(path.read_text(errors="replace"))
    d["file"] = str(path)
    return d
