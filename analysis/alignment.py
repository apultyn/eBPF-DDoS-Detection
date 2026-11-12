"""Find the offset between a live run's clock and the trace's clock.

A live run stamps windows with the time packets arrived (wall clock); the
labels and a -pcap reference run use the time recorded in the trace. The
offset is

    offset_ns = wall time - trace time

for the same packet, so a live window [s, e) covers trace time
[s - offset, e - offset).

It is found by matching the live run's packets per window against a
reference run of the same excerpt in -pcap mode. The reference is treated
as a packet rate that is constant within each of its windows; for a
candidate offset, the packets each live window should have received are
the reference's cumulative count over that window's span in trace time.
This works for any combination of window lengths and boundaries.

The search is in two steps: a cross-correlation over all offsets on a
coarse common grid (FFT), then a fine search around the best peak scoring
the exact model by Pearson correlation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

COARSE_STEP_NS = 10_000_000  # 10 ms
FINE_STEP_NS = 1_000_000  # 1 ms

MIN_CORRELATION = 0.9
MIN_PEAK_RATIO = 1.2

# Cap the FFT and interpolation arrays even when a reference spans a whole
# day (or contains a large timestamp gap). Refine the offset at the requested
# fine resolution after adapting the coarse grid.
MAX_GRID_BINS = 1 << 19


@dataclass
class Series:
    """Packets per window: windows [start_ns, end_ns) with a count each."""

    start_ns: np.ndarray
    end_ns: np.ndarray
    packets: np.ndarray

    @classmethod
    def of(cls, start_ns, end_ns, packets) -> "Series":
        order = np.argsort(np.asarray(start_ns, dtype=np.int64), kind="stable")
        return cls(np.asarray(start_ns, dtype=np.int64)[order],
                   np.asarray(end_ns, dtype=np.int64)[order],
                   np.asarray(packets, dtype=np.float64)[order])

    def cumulative(self, t_ns) -> np.ndarray:
        """Packets before each time in t_ns, spreading every window's
        packets evenly over the window. Flat across gaps between windows."""
        xs = np.empty(2 * self.start_ns.size, dtype=np.float64)
        xs[0::2], xs[1::2] = self.start_ns, self.end_ns
        before = np.concatenate([[0.0], np.cumsum(self.packets)[:-1]])
        ys = np.empty_like(xs)
        ys[0::2], ys[1::2] = before, before + self.packets

        # Times relative to the first window keep float precision at ns.
        origin = float(self.start_ns[0])
        return np.interp(np.asarray(t_ns, dtype=np.float64) - origin, xs - origin, ys)

    def on_grid(self, t0: int, step: int, n: int) -> np.ndarray:
        edges = t0 + step * np.arange(n + 1, dtype=np.int64)
        return np.diff(self.cumulative(edges))


@dataclass
class Alignment:
    offset_ns: int
    correlation: float
    peak_ratio: float
    method: str = "cross-correlation"
    coarse_step_ns: int = COARSE_STEP_NS
    fine_step_ns: int = FINE_STEP_NS
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "offset_ns": self.offset_ns,
            "method": self.method,
            "correlation": None if math.isnan(self.correlation) else self.correlation,
            "peak_ratio": None if math.isinf(self.peak_ratio) or math.isnan(self.peak_ratio) else self.peak_ratio,
            "coarse_step_ns": self.coarse_step_ns,
            "fine_step_ns": self.fine_step_ns,
            "warnings": self.warnings,
        }


def predicted(ref: Series, live: Series, offset_ns: int) -> np.ndarray:
    """Packets each live window should have, given the reference and an offset."""
    return ref.cumulative(live.end_ns - offset_ns) - ref.cumulative(live.start_ns - offset_ns)


def pearson(a: np.ndarray, b: np.ndarray) -> float:
    a, b = a - a.mean(), b - b.mean()
    d = math.sqrt(float(np.dot(a, a)) * float(np.dot(b, b)))
    return float(np.dot(a, b)) / d if d else float("nan")


def estimate_offset(ref: Series, live: Series,
                    coarse_step_ns: int = COARSE_STEP_NS,
                    fine_step_ns: int = FINE_STEP_NS) -> Alignment:
    """Offset (wall - trace) that best matches live packets per window to the reference."""
    if coarse_step_ns <= 0 or fine_step_ns <= 0:
        raise ValueError("alignment steps must be positive")
    if not ref.start_ns.size or not live.start_ns.size:
        raise ValueError("cannot align an empty reference or live run")

    r0, r1 = int(ref.start_ns[0]), int(ref.end_ns.max())
    l0, l1 = int(live.start_ns[0]), int(live.end_ns.max())
    if r1 <= r0 or l1 <= l0:
        raise ValueError("alignment runs must have positive time spans")
    span = (r1 - r0) + (l1 - l0)
    # Integer ceiling avoids overflow/rounding when timestamps are far apart.
    step = max(coarse_step_ns, (span + MAX_GRID_BINS - 3) // (MAX_GRID_BINS - 2))
    nr, nl = math.ceil((r1 - r0) / step), math.ceil((l1 - l0) / step)

    r = ref.on_grid(r0, step, nr)
    l = live.on_grid(l0, step, nl)
    r, l = r - r.mean(), l - l.mean()

    # Linear cross-correlation via FFT: c[k] = sum_i r[i] * l[i + k], for
    # lags k in -(nr-1) .. nl-1, stored with negative lags wrapped.
    size = 1 << (nr + nl - 1).bit_length()
    c = np.fft.irfft(np.fft.rfft(l, size) * np.conj(np.fft.rfft(r, size)), size)
    lags = np.concatenate([np.arange(0, nl), np.arange(-(nr - 1), 0)])
    c = np.concatenate([c[:nl], c[size - (nr - 1):]]) if nr > 1 else c[:nl]

    norm = math.sqrt(float(np.dot(r, r)) * float(np.dot(l, l)))
    if norm:
        c = c / norm

    best = int(np.argmax(c))
    coarse_offset = l0 - r0 + int(lags[best]) * step

    # The second-best peak, at least two of the longer windows away, shows
    # whether the best one stands out.
    window = int(max(np.median(ref.end_ns - ref.start_ns), np.median(live.end_ns - live.start_ns)))
    away = np.abs(lags - lags[best]) * step > 2 * window
    second = float(c[away].max()) if away.any() else float("-inf")
    ratio = float(c[best]) / second if second > 0 else float("inf")

    # Refine with the exact model. On the coarse grid every window's packets
    # are smeared over the whole window, so the coarse peak is broad and can
    # be off by a good part of a window; search a full window either side,
    # then narrow down to the fine step.
    def best_of(centre: int, half_width: int, step_ns: int) -> tuple[int, float]:
        candidates = centre + np.arange(-half_width, half_width + 1, step_ns, dtype=np.int64)
        scores = np.array([pearson(predicted(ref, live, int(o)), live.packets) for o in candidates])
        scores[np.isnan(scores)] = -2.0
        i = int(np.argmax(scores))
        return int(candidates[i]), float(scores[i])

    mid_step = max(5 * fine_step_ns, step // 5)
    offset, _ = best_of(coarse_offset, max(window, step), mid_step)
    while mid_step > 5 * fine_step_ns:
        next_step = max(5 * fine_step_ns, mid_step // 5)
        offset, _ = best_of(offset, mid_step, next_step)
        mid_step = next_step
    offset, corr = best_of(offset, mid_step, fine_step_ns)

    a = Alignment(offset_ns=offset, correlation=corr if corr > -2 else float("nan"),
                  peak_ratio=ratio, coarse_step_ns=step, fine_step_ns=fine_step_ns)

    if step > coarse_step_ns:
        a.warnings.append(
            f"coarse alignment grid increased to {step / 1e6:g} ms to limit memory; "
            "fine refinement is unchanged. Check that the reference covers the same excerpt"
        )

    if math.isnan(a.correlation) or a.correlation < MIN_CORRELATION:
        a.warnings.append(
            f"correlation {a.correlation:.3f} at the best offset is below {MIN_CORRELATION}; "
            "the live run and the reference may not show the same traffic"
        )
    if a.peak_ratio < MIN_PEAK_RATIO:
        a.warnings.append(
            f"the best offset is only {a.peak_ratio:.2f} times the next candidate (want >= {MIN_PEAK_RATIO}); "
            "the alignment is ambiguous, for example with very even traffic"
        )

    return a
