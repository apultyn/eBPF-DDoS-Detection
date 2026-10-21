"""Tests for finding the live-to-trace offset, and for parsing tcpreplay."""

import numpy as np
import pytest

from analysis import alignment, tcpreplay

S = 10**9
MS = 10**6
TRACE_T0 = 1_541_250_000 * S  # 2018-11-03T13:00:00Z
# A live run eight years later, at an offset that is no round number.
OFFSET = 8 * 365 * 86400 * S + 123_456_789_123


def packet_times(seconds=600, seed=1, bursts=True):
    """Packet arrival times in trace time: a fluctuating background and,
    optionally, a few short bursts, as in real traffic."""
    rng = np.random.default_rng(seed)
    t = np.arange(0, seconds * 1000)  # 1 ms bins
    rate = 2 + np.sin(t / 7000) + rng.random(t.size) * 2  # packets per ms, varying
    if bursts:
        for start in rng.integers(0, t.size - 3000, 6):
            rate[start:start + int(rng.integers(500, 3000))] += 20
    counts = rng.poisson(rate)
    times = np.repeat(t, counts) * MS + rng.integers(0, MS, counts.sum())
    return TRACE_T0 + np.sort(times)


def windows(times, length, phase=0, first=None, last=None):
    """Windows of `length` on a grid shifted by `phase`, counting `times`."""
    first = times[0] if first is None else first
    last = times[-1] if last is None else last
    start = ((first - phase) // length) * length + phase
    edges = np.arange(start, last + length, length, dtype=np.int64)
    counts, _ = np.histogram(times, bins=edges)
    return alignment.Series.of(edges[:-1], edges[1:], counts)


def test_recovers_known_offset_same_window_length():
    times = packet_times()
    ref = windows(times, 500 * MS)
    live = windows(times + OFFSET, 500 * MS, phase=137 * MS)

    a = alignment.estimate_offset(ref, live)

    assert abs(a.offset_ns - OFFSET) < 30 * MS
    assert a.correlation > 0.95 and not a.warnings


def test_recovers_known_offset_different_window_lengths():
    # Reference in user-space windows of 500 ms, live in the kernel's 2^29 ns.
    times = packet_times(seed=2)
    ref = windows(times, 500 * MS)
    live = windows(times + OFFSET, 1 << 29)

    a = alignment.estimate_offset(ref, live)

    assert abs(a.offset_ns - OFFSET) < 30 * MS
    assert a.correlation > 0.95 and a.peak_ratio > alignment.MIN_PEAK_RATIO


def test_live_run_with_idle_time_and_missing_start():
    # The live detector starts a few seconds into the replay and runs on
    # for a while after it, with idle windows at the end.
    times = packet_times(seed=3)
    ref = windows(times, 500 * MS)
    live_times = times[times > TRACE_T0 + 5 * S] + OFFSET
    live = windows(live_times, 1 << 29, last=live_times[-1] + 30 * S)

    a = alignment.estimate_offset(ref, live)

    assert abs(a.offset_ns - OFFSET) < 30 * MS


def test_even_traffic_gives_a_warning():
    # Constant traffic has no features to align on.
    times = TRACE_T0 + np.arange(0, 300 * S, MS)
    ref = windows(times, 500 * MS)
    live = windows(times + OFFSET, 1 << 29)

    a = alignment.estimate_offset(ref, live)

    assert a.warnings


def test_predicted_counts_follow_the_reference():
    ref = alignment.Series.of([0, 10], [10, 20], [10, 30])

    # A live window covering the second half of the first reference window
    # and the first half of the second gets 5 + 15 packets.
    live = alignment.Series.of([1005], [1015], [0])
    assert alignment.predicted(ref, live, 1000)[0] == pytest.approx(20)


TCPREPLAY_OUTPUT = """\
Actual: 1000 packets (60000 bytes) sent in 10.02 seconds
Rated: 5988.0 Bps, 0.047 Mbps, 99.80 pps
Flows: 10 flows, 0.99 fps, 1000 flow packets, 0 non-flow
Statistics for network device: eth0
\tSuccessful packets:        998
\tFailed packets:            2
\tTruncated packets:         0
\tRetried packets (ENOBUFS): 5
\tRetried packets (EAGAIN):  0
"""


def test_parse_tcpreplay():
    d = tcpreplay.parse(TCPREPLAY_OUTPUT)

    assert d["actual_packets"] == 1000 and d["actual_bytes"] == 60000
    assert d["actual_seconds"] == pytest.approx(10.02) and d["rated_pps"] == pytest.approx(99.8)
    assert (d["successful"], d["failed"], d["truncated"], d["retried_enobufs"]) == (998, 2, 0, 5)


def test_parse_tcpreplay_missing_fields():
    d = tcpreplay.parse("something else entirely")

    assert all(v is None for v in d.values())
