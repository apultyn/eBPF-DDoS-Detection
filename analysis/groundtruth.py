"""Window-level ground truth from interval labels.

Follows Koshovyi & Wu (2026), section 4.1.3: the labelled attack flows of a
day are merged into attack intervals, and a detector window is an attack
window if it overlaps any attack interval, normal only if it lies entirely
outside them.

Intervals are closed, [start_ns, end_ns], since a flow occupies both its
first and its last instant. Window spans are half-open, [start_ns, end_ns),
since a window ends where the next begins. So an interval ending exactly at
a window's start overlaps it, and one starting exactly at a window's end
does not.

Depends only on the common label format.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def merge_intervals(starts, ends) -> tuple[np.ndarray, np.ndarray]:
    """Merge closed intervals that overlap or touch into disjoint ones,
    sorted by start."""
    s = np.asarray(starts, dtype=np.int64)
    e = np.asarray(ends, dtype=np.int64)

    if s.size == 0:
        return s, e

    order = np.argsort(s, kind="stable")
    s, e = s[order], e[order]

    # An interval starts a new merged interval when it begins after
    # everything before it has ended.
    running_end = np.maximum.accumulate(e)
    new = np.empty(s.size, dtype=bool)
    new[0] = True
    new[1:] = s[1:] > running_end[:-1]

    merged_s = s[new]
    merged_e = np.maximum.reduceat(e, np.flatnonzero(new))

    return merged_s, merged_e


def attack_intervals(labels: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Merged intervals covered by any attack flow."""
    a = labels[labels["is_attack"]]
    return merge_intervals(a["start_ns"], a["end_ns"])


def intervals_by_label(labels: pd.DataFrame) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Merged intervals per attack label, for tracing which attacks a
    window overlaps."""
    a = labels[labels["is_attack"]]
    return {
        str(name): merge_intervals(g["start_ns"], g["end_ns"])
        for name, g in a.groupby("label", observed=True, sort=True)
    }


def overlaps(span_start, span_end, starts: np.ndarray, ends: np.ndarray) -> np.ndarray:
    """For each half-open span [span_start, span_end), whether it overlaps
    any of the disjoint, sorted closed intervals [starts, ends]."""
    ws = np.asarray(span_start, dtype=np.int64)
    we = np.asarray(span_end, dtype=np.int64)

    if starts.size == 0:
        return np.zeros(ws.size, dtype=bool)

    # Intervals 0..idx-1 start before the span ends. They are disjoint and
    # sorted, so the last of them reaches furthest.
    idx = np.searchsorted(starts, we, side="left")
    has = idx > 0

    out = np.zeros(ws.size, dtype=bool)
    out[has] = ends[idx[has] - 1] >= ws[has]

    return out


def overlapping_labels(span_start, span_end, by_label: dict) -> list[str]:
    """For each span, the attack labels it overlaps, joined with ';'."""
    n = len(np.asarray(span_start))
    hits = [[] for _ in range(n)]

    for name, (s, e) in by_label.items():
        for i in np.flatnonzero(overlaps(span_start, span_end, s, e)):
            hits[i].append(name)

    return [";".join(h) for h in hits]
