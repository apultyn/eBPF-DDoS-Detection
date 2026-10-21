#!/usr/bin/env python3
"""Cut an excerpt out of one day of CIC-DDoS2019 pcap files for live replay.

    python3 scripts/excerpt.py --input PCAP-03-11/ --out excerpts/03-11.pcap \\
        --duration 60m [--start 2018-11-03T14:00:00Z] [--rewrite-mac DST,SRC] \\
        [--labels labels/03-11.parquet]

The day's files are taken in natural order, the order the detector reads
them in, and only those overlapping the requested interval are used. They
are concatenated in that order (mergecap -a), the interval is cut out
(editcap -A/-B), and the MAC addresses are optionally rewritten for FABRIC
(tcprewrite). The result is checked with capturecheck and described in
<out>.excerpt.json, which the analysis reads with --excerpt.

Gaps between files are kept in the excerpt, and tcpreplay waits through
them. A live detector closes empty windows during such a gap, and they
enter its threshold history as zeros. The excerpt is therefore refused if
any gap between consecutive files is longer than two windows, or if files
overlap in time; --allow-gaps overrides this.

With --labels, the excerpt is also refused if an attack starts within its
first --min-benign (default 2 minutes), since the detector's warm-up must
see normal traffic; --allow-early-attack overrides this.

Requires mergecap and editcap (Wireshark 3.6 or later), tcprewrite for
--rewrite-mac, and Go to build capturecheck unless --capturecheck is given.
Standard library only, except pyarrow for --labels.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]

# The kernel variant's window, 2^29 ns. The user-space variant is to use the
# same length; the gap rule is in windows of this length unless --window.
DEFAULT_WINDOW_NS = 1 << 29

DEFAULT_MIN_BENIGN_NS = 120 * 10**9

LINKTYPE_ETHERNET = 1


class ExcerptError(Exception):
    """A check failed; the message is shown to the user."""


@dataclass
class Tools:
    """External commands, replaceable in tests."""

    capturecheck: list[str] | None = None  # built on demand when None
    mergecap: str = "mergecap"
    editcap: str = "editcap"
    tcprewrite: str = "tcprewrite"
    log: Callable[[str], None] = field(default=lambda m: print(f"excerpt: {m}", file=sys.stderr, flush=True))
    commands: list[list[str]] = field(default_factory=list)

    def run(self, cmd: list[str], capture: bool = False) -> str:
        self.commands.append(cmd)
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            raise ExcerptError(f"{' '.join(cmd)} failed ({out.returncode}): {out.stderr.strip() or out.stdout.strip()}")
        return out.stdout if capture else ""


# ---------------------------------------------------------------- time


_UNITS = {"ns": 1, "us": 10**3, "µs": 10**3, "ms": 10**6, "s": 10**9, "m": 60 * 10**9, "h": 3600 * 10**9}


def parse_duration(text: str) -> int:
    """Go-style duration ("60m", "1h30m", "536.870912ms") in ns."""
    parts = re.findall(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)", text)
    if not parts or "".join(n + u for n, u in parts) != text.strip():
        raise ValueError(f"invalid duration {text!r}")
    return round(sum(float(n) * _UNITS[u] for n, u in parts))


def parse_time(text: str) -> int:
    """UTC time as ISO 8601 ("2018-11-03T14:00:00Z") or epoch seconds, in ns."""
    t = text.strip()
    if re.fullmatch(r"\d+(\.\d+)?", t):
        whole, _, frac = t.partition(".")
        return int(whole) * 10**9 + int((frac + "000000000")[:9])

    m = re.fullmatch(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]00:00)?", t)
    if not m:
        raise ValueError(f"invalid time {text!r}; use e.g. 2018-11-03T14:00:00Z")
    dt = datetime.strptime(f"{m.group(1)}T{m.group(2)}", "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 10**9 + int(((m.group(3) or "") + "000000000")[:9])


def format_ns(ns: int) -> str:
    sec, rem = divmod(ns, 10**9)
    return datetime.fromtimestamp(sec, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{rem:09d}Z"


# ---------------------------------------------------------------- files


def _chunks(s: str) -> list[str]:
    return re.findall(r"\d+|\D+", s)


def natural_compare(a: str, b: str) -> int:
    """The detector's ordering (capture.naturalCompare): runs of digits
    compare by value, other text bytewise."""
    ca, cb = _chunks(a), _chunks(b)
    for x, y in zip(ca, cb):
        if x[0].isdigit() and y[0].isdigit():
            tx, ty = x.lstrip("0"), y.lstrip("0")
            if len(tx) != len(ty):
                return len(tx) - len(ty)
            if tx != ty:
                return -1 if tx < ty else 1
            if len(x) != len(y):
                return len(x) - len(y)
        elif x != y:
            bx, by = x.encode(), y.encode()
            return -1 if bx < by else 1
    return len("".join(ca)) - len("".join(cb))


def list_inputs(paths: list[str]) -> list[Path]:
    """Files as given; a directory contributes its regular, non-hidden
    files, in natural order. Mirrors capture.ExpandPaths."""
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            names = [c.name for c in p.iterdir() if c.is_file() and not c.name.startswith(".")]
            out.extend(p / n for n in sorted(names, key=functools.cmp_to_key(natural_compare)))
        elif p.is_file():
            out.append(p)
        else:
            raise ExcerptError(f"{p}: no such file or directory")
    if not out:
        raise ExcerptError("no input files")
    return out


def link_type(path: Path) -> int:
    """Link type from a classic pcap header."""
    with open(path, "rb") as f:
        hdr = f.read(24)
    if len(hdr) < 24:
        raise ExcerptError(f"{path}: too short for a pcap header")
    magic = hdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        order = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        order = ">"
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise ExcerptError(f"{path}: pcapng; convert with editcap -F pcap first")
    else:
        raise ExcerptError(f"{path}: not a pcap file")
    return struct.unpack(order + "I", hdr[20:24])[0] & 0xFFFF


@dataclass
class FileSpan:
    path: Path
    packets: int
    skipped: int
    first_ns: int | None
    last_ns: int | None


_PACKETS = re.compile(r"^packets:\s+(\d+)", re.M)
_SKIPPED = re.compile(r"^skipped:\s+(\d+)", re.M)
_SPAN = re.compile(r"^time span:.*\((\S+) to (\S+)\)", re.M)


def parse_capturecheck(path: Path, text: str) -> FileSpan:
    """Parse capturecheck's summary."""
    p, s, span = _PACKETS.search(text), _SKIPPED.search(text), _SPAN.search(text)
    if not (p and s and span):
        raise ExcerptError(f"{path}: unexpected capturecheck output:\n{text}")

    packets = int(p.group(1))
    if packets == 0:
        return FileSpan(path, 0, int(s.group(1)), None, None)

    return FileSpan(path, packets, int(s.group(1)), parse_time(span.group(1)), parse_time(span.group(2)))


def capturecheck(tools: Tools, path: Path, tmp: Path) -> FileSpan:
    if tools.capturecheck is None:
        binary = tmp / "capturecheck"
        tools.log("building capturecheck")
        tools.run(["go", "-C", str(REPO), "build", "-o", str(binary), "./userspace/cmd/capturecheck"])
        tools.capturecheck = [str(binary)]

    return parse_capturecheck(path, tools.run(tools.capturecheck + ["-pcap", str(path)], capture=True))


# ---------------------------------------------------------------- selection


def select(spans: list[FileSpan], start: int, end: int) -> list[FileSpan]:
    """Files with packets in [start, end), in reading order."""
    return [s for s in spans if s.first_ns is not None and s.last_ns >= start and s.first_ns < end]


def discontinuities(selected: list[FileSpan]) -> list[dict]:
    """Gaps (and overlaps) between consecutive files inside the interval.

    The gap after file i is the time from its last packet to the first
    packet of file i+1. A negative gap means the files overlap in time,
    which a concatenation turns into out-of-order packets.
    """
    out = []
    for a, b in zip(selected, selected[1:]):
        out.append({
            "after": a.path.name,
            "before": b.path.name,
            "from": format_ns(a.last_ns),
            "to": format_ns(b.first_ns),
            "gap_s": (b.first_ns - a.last_ns) / 1e9,
        })
    return out


def early_attacks(labels: Path, start: int, min_benign: int) -> list[dict]:
    """Attack flows starting before start + min_benign that are still
    running at or after start."""
    try:
        import pyarrow.parquet as pq
    except ImportError as e:
        raise ExcerptError("--labels needs pyarrow (pip install -r analysis/requirements.txt)") from e

    t = pq.read_table(labels, columns=["start_ns", "end_ns", "label", "is_attack"]).to_pydict()
    hits: dict[str, int] = {}
    for s, e, label, attack in zip(t["start_ns"], t["end_ns"], t["label"], t["is_attack"]):
        if attack and s < start + min_benign and e >= start:
            hits[label] = min(hits.get(label, s), s)
    return [{"label": k, "first_start": format_ns(v)} for k, v in sorted(hits.items(), key=lambda kv: kv[1])]


# ---------------------------------------------------------------- main


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def tool_version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True)
    except OSError:
        return "unavailable"
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0] if text else "unknown"


def git_commit() -> str:
    out = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def run(args: argparse.Namespace, tools: Tools) -> dict:
    out: Path = args.out
    meta_path = out.with_name(out.name.removesuffix(".pcap") + ".excerpt.json")

    if not args.force and (out.exists() or meta_path.exists()):
        raise ExcerptError(f"{out} or {meta_path} exists; use --force to overwrite")

    if args.rewrite_mac:
        macs = args.rewrite_mac.split(",")
        if len(macs) != 2 or not all(re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", m) for m in macs):
            raise ExcerptError("--rewrite-mac takes DST,SRC, e.g. 02:00:00:00:00:02,02:00:00:00:00:01")

    files = list_inputs(args.input)
    out.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(dir=out.parent, prefix=".excerpt-") as tmpdir:
        tmp = Path(tmpdir)

        tools.log(f"reading the time span of {len(files)} files")
        spans = [capturecheck(tools, f, tmp) for f in files]

        with_packets = [s for s in spans if s.first_ns is not None]
        if not with_packets:
            raise ExcerptError("no IP packets in the input")

        day_start = min(s.first_ns for s in with_packets)
        start = parse_time(args.start) if args.start else day_start
        end = start + parse_duration(args.duration)

        selected = select(spans, start, end)
        if not selected:
            raise ExcerptError(f"no file has packets between {format_ns(start)} and {format_ns(end)}")

        types = {link_type(s.path) for s in selected}
        if len(types) != 1:
            raise ExcerptError(f"the selected files have different link types: {sorted(types)}")
        lt = types.pop()
        if lt != LINKTYPE_ETHERNET and not args.rewrite_mac:
            raise ExcerptError(
                f"link type {lt} is not Ethernet; tcpreplay needs Ethernet frames, so give "
                "--rewrite-mac DST,SRC to add Ethernet headers"
            )

        gaps = discontinuities(selected)
        limit_s = 2 * args.window / 1e9
        bad = [g for g in gaps if g["gap_s"] > limit_s or g["gap_s"] < 0]

        for g in gaps:
            kind = "overlap" if g["gap_s"] < 0 else "gap"
            tools.log(f"{kind} {g['gap_s']:+.6f} s between {g['after']} and {g['before']}")

        if bad and not args.allow_gaps:
            raise ExcerptError(
                f"{len(bad)} gap(s) longer than two windows ({limit_s:.3f} s) or overlaps between files; "
                "a live detector would learn the empty windows as zeros. Choose another interval, "
                "or pass --allow-gaps"
            )

        early = None
        if args.labels:
            early = early_attacks(args.labels, start, args.min_benign)
            if early and not args.allow_early_attack:
                raise ExcerptError(
                    f"attacks start within the first {args.min_benign / 1e9:.0f} s, where the detector "
                    f"warms up: {early}. Choose a later --start, or pass --allow-early-attack"
                )
        else:
            tools.log("warning: no --labels given, so the excerpt's first minutes were not checked for attacks")

        merged = tmp / "merged.pcap"
        cut = tmp / "cut.pcap"
        tools.run([tools.mergecap, "-F", "pcap", "-a", "-w", str(merged)] + [str(s.path) for s in selected])
        tools.run([tools.editcap, "-F", "pcap", "-A", format_ns(start), "-B", format_ns(end), str(merged), str(cut)])

        final = cut
        if args.rewrite_mac:
            dst, src = args.rewrite_mac.split(",")
            final = tmp / "rewritten.pcap"
            cmd = [tools.tcprewrite, f"--enet-dmac={dst}", f"--enet-smac={src}",
                   f"--infile={cut}", f"--outfile={final}"]
            if lt != LINKTYPE_ETHERNET:
                cmd.insert(1, "--dlt=enet")
            tools.run(cmd)

        result = capturecheck(tools, final, tmp)
        if result.first_ns is None:
            raise ExcerptError("the excerpt has no IP packets")

        shutil.move(str(final), out)

    meta = {
        "file": str(out),
        "sha256": sha256(out),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_commit(),
        "requested": {"start_ns": start, "start": format_ns(start), "end_ns": end, "end": format_ns(end),
                      "duration_s": (end - start) / 1e9},
        # The first and last packet actually in the excerpt; the analysis
        # scores only windows inside this span.
        "trace_start_ns": result.first_ns,
        "trace_end_ns": result.last_ns,
        "trace_start": format_ns(result.first_ns),
        "trace_end": format_ns(result.last_ns),
        "packets_ip": result.packets,
        "frames_non_ip": result.skipped,
        "link_type_input": lt,
        "rewrite_mac": args.rewrite_mac,
        "inputs": [{"file": str(s.path), "packets_ip": s.packets,
                    "first": format_ns(s.first_ns), "last": format_ns(s.last_ns)} for s in selected],
        "gap_rule": {"window_ns": args.window, "max_gap_s": limit_s, "allowed": bool(args.allow_gaps)},
        "discontinuities": gaps,
        "max_gap_s": max((g["gap_s"] for g in gaps), default=0.0),
        "early_attack_check": None if early is None else {
            "labels": str(args.labels), "min_benign_s": args.min_benign / 1e9,
            "attacks": early, "allowed": bool(args.allow_early_attack)},
        "commands": tools.commands,
        "tools": {
            "mergecap": tool_version([tools.mergecap, "-v"]),
            "editcap": tool_version([tools.editcap, "-v"]),
            "tcprewrite": tool_version([tools.tcprewrite, "-V"]) if args.rewrite_mac else None,
        },
    }
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")

    tools.log(f"wrote {out}: {result.packets} IP packets, {format_ns(result.first_ns)} to "
              f"{format_ns(result.last_ns)}, {len(selected)} files, largest gap {meta['max_gap_s']:.3f} s")
    tools.log(f"wrote {meta_path}")

    return meta


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="excerpt.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--input", required=True, nargs="+", help="the day's pcap files or directory")
    p.add_argument("--out", required=True, type=Path, help="output pcap, e.g. excerpts/03-11.pcap")
    p.add_argument("--start", help="trace time (UTC) to start at; default the day's first packet")
    p.add_argument("--duration", required=True, help="length of the excerpt, e.g. 60m")
    p.add_argument("--window", type=parse_duration, default=DEFAULT_WINDOW_NS,
                   help="detector window length for the gap rule (default 536.870912ms = 2^29 ns)")
    p.add_argument("--allow-gaps", action="store_true", help="accept gaps longer than two windows")
    p.add_argument("--rewrite-mac", help="DST,SRC MAC addresses to write into every frame (FABRIC)")
    p.add_argument("--labels", type=Path, help="label parquet of the day, to check the start is benign")
    p.add_argument("--min-benign", type=parse_duration, default=DEFAULT_MIN_BENIGN_NS,
                   help="normal traffic required at the start (default 2m)")
    p.add_argument("--allow-early-attack", action="store_true", help="accept an attack in the first minutes")
    p.add_argument("--capturecheck", help="path to a built capturecheck; default: build it with go")
    p.add_argument("--force", action="store_true", help="overwrite the output")
    args = p.parse_args(argv)
    try:
        parse_duration(args.duration)
        if args.start:
            parse_time(args.start)
    except ValueError as e:
        p.error(str(e))
    return args


def main(argv: list[str] | None = None, tools: Tools | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    tools = tools or Tools()
    if args.capturecheck:
        tools.capturecheck = [args.capturecheck]
    try:
        run(args, tools)
        return 0
    except ExcerptError as e:
        tools.log(f"error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
