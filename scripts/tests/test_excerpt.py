"""Tests for excerpt.py.

The real capturecheck is built and used, so that parsing its output is
tested against the real thing. mergecap, editcap and tcprewrite are
replaced by small Python fakes that do the same to classic pcap files.
"""

import functools
import json
import shutil
import struct
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import excerpt  # noqa: E402

T0 = 1_541_250_000  # seconds, 2018-11-03T13:00:00Z
S = 10**9


# ------------------------------------------------------------ pcap helpers


def frame(src: str) -> bytes:
    """An Ethernet frame carrying a minimal IPv4 header from src."""
    ip = bytearray(20)
    ip[0] = 0x45
    ip[12:16] = bytes(int(x) for x in src.split("."))
    return bytes(12) + b"\x08\x00" + bytes(ip)


def write_pcap(path: Path, stamps_ns, linktype=1, src="192.0.2.1"):
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for ns in stamps_ns:
        data = frame(src) if linktype == 1 else frame(src)[14:]
        sec, rem = divmod(ns, S)
        out += struct.pack("<IIII", sec, rem // 1000, len(data), len(data)) + data
    path.write_bytes(bytes(out))
    return path


PCAP_LIB = '''
import struct, sys
from datetime import datetime, timezone
def read(path):
    b = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    hdr, pos, recs = b[:24], 24, []
    while pos < len(b):
        sec, usec, cap, wire = struct.unpack("<IIII", b[pos:pos+16])
        recs.append((sec * 10**9 + usec * 1000, b[pos:pos+16+cap]))
        pos += 16 + cap
    return hdr, recs

def write(path, data):
    if path == "-":
        sys.stdout.buffer.write(data)
    else:
        open(path, "wb").write(data)
def iso(t):
    d, f = t.rstrip("Z").split(".")
    dt = datetime.strptime(d, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 10**9 + int((f + "000000000")[:9])
'''


def make_exe(path: Path, body: str) -> str:
    path.write_text(f"#!{sys.executable}\n" + PCAP_LIB + textwrap.dedent(body))
    path.chmod(0o755)
    return str(path)


@pytest.fixture(scope="session")
def capturecheck_bin(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("go is needed to build capturecheck")
    out = tmp_path_factory.mktemp("bin") / "capturecheck"
    subprocess.run(["go", "-C", str(excerpt.REPO), "build", "-o", str(out), "./userspace/cmd/capturecheck"],
                   check=True)
    return str(out)


@pytest.fixture
def tools(tmp_path, capturecheck_bin):
    b = tmp_path / "bin"
    b.mkdir()

    mergecap = make_exe(b / "mergecap", """
        args = sys.argv[1:]
        out = args[args.index("-w") + 1]
        files = [a for a in args[args.index("-w") + 2:]]
        hdr, data = None, b""
        for f in files:
            h, recs = read(f)
            hdr = hdr or h
            data += b"".join(r for _, r in recs)
        write(out, hdr + data)
    """)
    editcap = make_exe(b / "editcap", """
        args = sys.argv[1:]
        if args == ["-v"]:
            print("Editcap (Wireshark) 4.2.2"); sys.exit(0)
        a, z = iso(args[args.index("-A") + 1]), iso(args[args.index("-B") + 1])
        src, dst = args[-2], args[-1]
        hdr, recs = read(src)
        write(dst, hdr + b"".join(r for t, r in recs if a <= t < z))
    """)
    tcprewrite = make_exe(b / "tcprewrite", """
        args = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a)
        hdr, recs = read(args["--infile"])
        write(args["--outfile"], hdr + b"".join(r for _, r in recs))
    """)

    return excerpt.Tools(capturecheck=[capturecheck_bin], mergecap=mergecap, editcap=editcap,
                         tcprewrite=tcprewrite, log=lambda m: None)


def day(tmp_path, gap_s=0.5, overlap=False):
    """Three files in natural order: _0 and _1 are close together, _10 is
    an hour later, as between CIC recordings."""
    d = tmp_path / "PCAP-03-11"
    d.mkdir()
    write_pcap(d / "SAT-03-11-2018_0", [(T0 + i) * S for i in range(10)])               # 0..9 s
    first1 = (T0 + 9) * S + int(gap_s * S) if not overlap else (T0 + 5) * S
    write_pcap(d / "SAT-03-11-2018_1", [first1 + i * S for i in range(10)])
    write_pcap(d / "SAT-03-11-2018_10", [(T0 + 3600 + i) * S for i in range(10)])
    (d / ".DS_Store").write_text("ignored")
    return d


def run(tmp_path, tools, *extra, input_dir=None):
    out = tmp_path / "out" / "ex.pcap"
    rc = excerpt.main(["--input", str(input_dir), "--out", str(out), *extra], tools=tools)
    meta = out.with_name("ex.excerpt.json")
    return rc, out, (json.loads(meta.read_text()) if meta.exists() else None)


# ------------------------------------------------------------ pure functions


def test_natural_order_matches_detector():
    names = ["SAT_10", "SAT_2", "SAT_0", "SAT_100", "SAT_1", "SAT_02", "SAT_1a", "SAT_1B"]
    got = sorted(names, key=functools.cmp_to_key(excerpt.natural_compare))

    # The same order capture.naturalCompare produces (see capture tests).
    assert got[:6] == ["SAT_0", "SAT_1", "SAT_1B", "SAT_1a", "SAT_2", "SAT_02"]
    assert got[6:] == ["SAT_10", "SAT_100"]


def test_time_parsing():
    assert excerpt.parse_time("2018-11-03T13:00:00Z") == T0 * S
    assert excerpt.parse_time("2018-11-03T13:00:00.25Z") == T0 * S + 250_000_000
    assert excerpt.parse_time(f"{T0}.5") == T0 * S + 500_000_000
    assert excerpt.parse_duration("60m") == 3600 * S
    assert excerpt.parse_duration("536.870912ms") == 1 << 29
    with pytest.raises(ValueError):
        excerpt.parse_time("2018-11-03T13:00:00+02:00")


def test_parse_capturecheck_output():
    text = textwrap.dedent("""\
        packets:   50 (ipv4 50, ipv6 0)
        skipped:   3 non-IP or truncated frames
        bytes:     36436 on the wire
        time span: 994.715ms (2004-08-21T13:44:20.570381Z to 2004-08-21T13:44:21.565096Z)
    """)
    s = excerpt.parse_capturecheck(Path("x"), text)

    assert (s.packets, s.skipped) == (50, 3)
    assert s.last_ns - s.first_ns == 994_715_000


# ------------------------------------------------------------ whole runs


def test_excerpt_within_close_files(tmp_path, tools):
    d = day(tmp_path, gap_s=0.5)

    rc, out, meta = run(tmp_path, tools, "--start", "2018-11-03T13:00:03Z", "--duration", "10s", input_dir=d)

    assert rc == 0 and out.exists()
    # Packets at 3..9 s from file _0 and 9.5..12.5 s from file _1.
    assert meta["packets_ip"] == 7 + 4
    assert meta["trace_start_ns"] == (T0 + 3) * S
    assert meta["trace_end_ns"] == (T0 + 12) * S + S // 2
    assert [Path(i["file"]).name for i in meta["inputs"]] == ["SAT-03-11-2018_0", "SAT-03-11-2018_1"]
    assert len(meta["discontinuities"]) == 1
    assert meta["discontinuities"][0]["gap_s"] == pytest.approx(0.5)
    assert meta["max_gap_s"] == pytest.approx(0.5)

    # The commands are recorded, with mergecap concatenating in order.
    merge = next(c for c in meta["commands"] if c[0].endswith("mergecap"))
    assert "-a" in merge and merge[-2].endswith("_0") and merge[-1].endswith("_1")
    assert merge[merge.index("-w") + 1] == "-"
    edit = next(c for c in meta["commands"] if c[0].endswith("editcap"))
    assert edit[-2] == "-"


def test_default_start_is_first_packet_of_day(tmp_path, tools):
    rc, _, meta = run(tmp_path, tools, "--duration", "5s", input_dir=day(tmp_path))

    assert rc == 0 and meta["trace_start_ns"] == T0 * S and meta["packets_ip"] == 5


def test_refuses_gap_longer_than_two_windows(tmp_path, tools):
    d = day(tmp_path, gap_s=3)  # 3 s > 2 x 0.537 s

    rc, out, _ = run(tmp_path, tools, "--duration", "30s", input_dir=d)
    assert rc == 2 and not out.exists()

    rc, _, meta = run(tmp_path, tools, "--duration", "30s", "--allow-gaps", input_dir=d)
    assert rc == 0
    assert meta["gap_rule"]["allowed"] and meta["max_gap_s"] == pytest.approx(3)


def test_window_length_sets_the_gap_limit(tmp_path, tools):
    d = day(tmp_path, gap_s=0.9)  # within 2 x 0.537 s, beyond 2 x 0.4 s

    assert run(tmp_path, tools, "--duration", "15s", input_dir=d)[0] == 0
    assert run(tmp_path, tools, "--duration", "15s", "--window", "400ms", "--force", input_dir=d)[0] == 2


def test_refuses_overlapping_files(tmp_path, tools):
    rc, _, _ = run(tmp_path, tools, "--duration", "15s", input_dir=day(tmp_path, overlap=True))

    assert rc == 2


def test_hour_gap_is_reported_when_spanned(tmp_path, tools):
    rc, _, meta = run(tmp_path, tools, "--start", "2018-11-03T13:00:15Z", "--duration", "2h",
                      "--allow-gaps", input_dir=day(tmp_path))

    assert rc == 0
    assert meta["discontinuities"][-1]["after"] == "SAT-03-11-2018_1"
    assert meta["max_gap_s"] > 3500


def test_non_ethernet_needs_rewrite(tmp_path, tools):
    d = tmp_path / "raw"
    d.mkdir()
    write_pcap(d / "a", [(T0 + i) * S for i in range(5)], linktype=101)

    assert run(tmp_path, tools, "--duration", "10s", input_dir=d)[0] == 2

    rc, _, meta = run(tmp_path, tools, "--duration", "10s", "--rewrite-mac",
                      "02:00:00:00:00:02,02:00:00:00:00:01", input_dir=d)
    assert rc == 0 and meta["link_type_input"] == 101
    rewrite = next(c for c in meta["commands"] if c[0].endswith("tcprewrite"))
    assert "--dlt=enet" in rewrite and "--enet-dmac=02:00:00:00:00:02" in rewrite
    assert "--infile=-" in rewrite


def test_refuses_attack_in_first_minutes(tmp_path, tools):
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    labels = tmp_path / "labels.parquet"
    pq.write_table(pa.table({
        "start_ns": [T0 * S, (T0 + 60) * S],
        "end_ns": [(T0 + 1) * S, (T0 + 70) * S],
        "label": ["BENIGN", "Syn"],
        "is_attack": [False, True],
    }), labels)

    d = day(tmp_path)
    rc, out, _ = run(tmp_path, tools, "--duration", "5s", "--labels", str(labels), input_dir=d)
    assert rc == 2 and not out.exists()

    rc, _, meta = run(tmp_path, tools, "--duration", "5s", "--labels", str(labels),
                      "--allow-early-attack", input_dir=d)
    assert rc == 0 and meta["early_attack_check"]["attacks"][0]["label"] == "Syn"

    rc, _, meta = run(tmp_path, tools, "--duration", "5s", "--labels", str(labels),
                      "--min-benign", "30s", "--force", input_dir=d)
    assert rc == 0 and meta["early_attack_check"]["attacks"] == []


def test_refuses_to_overwrite(tmp_path, tools):
    d = day(tmp_path)
    assert run(tmp_path, tools, "--duration", "5s", input_dir=d)[0] == 0
    assert run(tmp_path, tools, "--duration", "5s", input_dir=d)[0] == 2
    assert run(tmp_path, tools, "--duration", "5s", "--force", input_dir=d)[0] == 0
