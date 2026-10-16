"""Tests for interval merging and window overlap."""

import numpy as np
import pandas as pd

from analysis import groundtruth as gt


def test_merge_overlapping_touching_and_unsorted():
    s, e = gt.merge_intervals([50, 0, 10, 30, 31], [60, 10, 20, 31, 40])

    # [0,10] and [10,20] touch and merge; [30,31] and [31,40] likewise.
    assert s.tolist() == [0, 30, 50]
    assert e.tolist() == [20, 40, 60]


def test_merge_contained_interval_keeps_outer_end():
    s, e = gt.merge_intervals([0, 5], [100, 10])

    assert s.tolist() == [0] and e.tolist() == [100]


def test_merge_empty():
    s, e = gt.merge_intervals([], [])

    assert s.size == 0 and e.size == 0


def test_overlap_at_edges():
    starts, ends = np.array([100]), np.array([200])

    spans = [
        (50, 100, False),   # ends exactly where the interval starts: half-open, no overlap
        (50, 101, True),    # one ns into the interval
        (200, 300, True),   # starts exactly at the interval's last instant
        (201, 300, False),  # starts just after it
        (120, 150, True),   # inside
        (0, 1000, True),    # contains it
    ]

    got = gt.overlaps([s for s, _, _ in spans], [e for _, e, _ in spans], starts, ends)

    assert got.tolist() == [want for _, _, want in spans]


def test_overlap_with_several_intervals():
    starts, ends = gt.merge_intervals([10, 50], [20, 60])

    got = gt.overlaps([0, 20, 21, 40, 60, 61], [10, 21, 50, 51, 70, 70], starts, ends)

    assert got.tolist() == [False, True, False, True, True, False]


def test_no_intervals_means_all_normal():
    got = gt.overlaps([0, 10], [10, 20], np.empty(0, np.int64), np.empty(0, np.int64))

    assert got.tolist() == [False, False]


def test_attack_intervals_and_labels():
    labels = pd.DataFrame({
        "start_ns": [0, 5, 100, 300],
        "end_ns": [10, 20, 110, 310],
        "label": pd.Categorical(["Syn", "BENIGN", "Syn", "UDP"]),
        "is_attack": [True, False, True, True],
    })

    s, e = gt.attack_intervals(labels)
    assert s.tolist() == [0, 100, 300] and e.tolist() == [10, 110, 310]

    by_label = gt.intervals_by_label(labels)
    assert set(by_label) == {"Syn", "UDP"}

    names = gt.overlapping_labels([0, 105, 200, 0], [5, 305, 250, 400], by_label)
    assert names == ["Syn", "Syn;UDP", "", "Syn;UDP"]
