"""Portable subprocess and disk-use regressions; no external tools required.

Run with python -m unittest discover -s scripts/tests -p test_excerpt_streaming.py.
The full excerpt suite additionally checks against the real Go capture reader.
"""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import excerpt


# Streaming substitutes for the command line tools on machines without them.
# These preserve the PCAP records and actually apply the requested MAC rewrite.
FAKE_TOOL = r'''
import struct, sys
from datetime import datetime

def read(stream):
    while header := stream.read(16):
        sec, usec, size, wire = struct.unpack("<IIII", header)
        data = stream.read(size)
        yield sec * 10**9 + usec * 1000, header, data

def stamp(text):
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp() * 10**9)

name, args = sys.argv[1], sys.argv[2:]
if args in (["-v"], ["-V"]):
    print(name + " test version"); sys.exit(0)
if name == "mergecap":
    assert args[args.index("-w") + 1] == "-"
    for i, path in enumerate(args[args.index("-w") + 2:]):
        with open(path, "rb") as source:
            header = source.read(24)
            if i == 0:
                sys.stdout.buffer.write(header)
            for _, record, data in read(source):
                sys.stdout.buffer.write(record + data)
elif name == "editcap":
    assert args[-2] == "-"
    start, end = stamp(args[args.index("-A") + 1]), stamp(args[args.index("-B") + 1])
    source = sys.stdin.buffer
    target = sys.stdout.buffer if args[-1] == "-" else open(args[-1], "wb")
    target.write(source.read(24))
    for ns, record, data in read(source):
        if start <= ns < end:
            target.write(record + data)
    target.flush()
elif name == "tcprewrite":
    options = dict(arg.split("=", 1) for arg in args)
    assert options["--infile"] == "-"
    source = sys.stdin.buffer
    header = source.read(24)
    link = struct.unpack("<I", header[20:24])[0]
    dst = bytes.fromhex(options["--enet-dmac"].replace(":", ""))
    src = bytes.fromhex(options["--enet-smac"].replace(":", ""))
    with open(options["--outfile"], "wb") as target:
        target.write(header[:20] + struct.pack("<I", 1))
        for _, record, data in read(source):
            sec, usec, size, wire = struct.unpack("<IIII", record)
            if link == 101:
                data = dst + src + b"\x08\x00" + data
                record = struct.pack("<IIII", sec, usec, size + 14, wire + 14)
            else:
                data = dst + src + data[12:]
            target.write(record + data)
elif name == "capturecheck":
    def iso(ns):
        sec, rem = divmod(ns, 10**9)
        from datetime import timezone
        return datetime.fromtimestamp(sec, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{rem:09d}Z"
    count, first, last = 0, 0, 0
    with open(args[-1], "rb") as source:
        source.read(24)
        for ns, _, data in read(source):
            if count == 0:
                first = ns
            last = ns
            count += 1
    print(f"packets: {count}\nskipped: 0\ntime span: test ({iso(first)} to {iso(last)})")
'''


def command(code):
    return [sys.executable, "-c", code]


class StreamingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tools = excerpt.Tools(log=lambda message: None)

    def test_three_stages_transfer_binary_without_intermediate_files(self):
        output = self.root / "output"
        block = bytes(range(256)) * 256
        self.tools.pipeline([
            command("import sys; b = bytes(range(256)) * 256; "
                    "[sys.stdout.buffer.write(b) for _ in range(128)]"),
            command("import sys, shutil; shutil.copyfileobj(sys.stdin.buffer, sys.stdout.buffer, 8192)"),
            command(f"import sys, shutil; f = open({str(output)!r}, 'wb'); "
                    "shutil.copyfileobj(sys.stdin.buffer, f, 8192); f.close()"),
        ])
        self.assertEqual(output.stat().st_size, len(block) * 128)
        self.assertEqual(hashlib.sha256(output.read_bytes()).digest(),
                         hashlib.sha256(block * 128).digest())
        self.assertEqual(list(self.root.iterdir()), [output])

    def test_upstream_failure_is_not_hidden_by_successful_consumer(self):
        with self.assertRaisesRegex(excerpt.ExcerptError, r"failed \(7\)"):
            self.tools.pipeline([
                command("import sys; sys.stdout.buffer.write(b'partial'); sys.exit(7)"),
                command("import sys; sys.stdin.buffer.read()"),
            ])

    def test_consumer_failure_reaps_blocked_producer(self):
        spawned = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        with patch.object(excerpt.subprocess, "Popen", side_effect=start):
            with self.assertRaisesRegex(excerpt.ExcerptError, r"failed \(9\)"):
                self.tools.pipeline([
                    command("import sys; b = b'x' * 65536\nwhile True: sys.stdout.buffer.write(b)"),
                    command("import sys; sys.exit(9)"),
                ])
        self.assertTrue(all(proc.poll() is not None for proc in spawned))

    def test_launch_failure_reaps_already_started_producer(self):
        spawned = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        with patch.object(excerpt.subprocess, "Popen", side_effect=start):
            with self.assertRaises(OSError):
                self.tools.pipeline([
                    command("import time; time.sleep(30)"),
                    [str(self.root / "missing-executable")],
                ])
        self.assertTrue(all(proc.poll() is not None for proc in spawned))

    def test_noisy_failure_keeps_only_bounded_diagnostics(self):
        with self.assertRaises(excerpt.ExcerptError) as caught:
            self.tools.run(command("import sys; sys.stderr.write('discard-me' + 'x' * 2**20 + 'THE-END'); "
                                   "sys.exit(3)"), capture=True)
        message = str(caught.exception)
        self.assertTrue(message.endswith("THE-END"))
        self.assertNotIn("discard-me", message.split(": ", 1)[-1])
        self.assertLess(len(message), excerpt.MAX_SUMMARY_BYTES + 1024)

    def test_oversized_summary_is_refused(self):
        with self.assertRaisesRegex(excerpt.ExcerptError, "summary exceeds"):
            self.tools.run(command("import sys; sys.stdout.write('x' * 2**20)"), capture=True)

    def test_small_summary_is_preserved(self):
        self.assertEqual(self.tools.run(command("print('packets: 42')"), capture=True), "packets: 42\n")

    def test_excerpt_workflow_uses_only_final_pcap_and_preserves_selection(self):
        helper = self.root / "fake_tool.py"
        helper.write_text(FAKE_TOOL)
        real_popen = subprocess.Popen
        original_capturecheck = excerpt.capturecheck
        input_dir = self.root / "input"
        input_dir.mkdir()
        t0 = 1_541_250_000

        for rewrite, link in ((False, 1), (True, 1), (True, 101)):
            with self.subTest(rewrite=rewrite, link=link):
                for index, seconds in enumerate(((0, 1, 2), (3, 4, 5))):
                    ip = b"\x45" + bytes(19)
                    frame = bytes(12) + b"\x08\x00" + ip if link == 1 else ip
                    with (input_dir / f"capture_{index}").open("wb") as target:
                        target.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
                        for sec in seconds:
                            target.write(struct.pack("<IIII", t0 + sec, 0, len(frame), len(frame)) + frame)
                out = self.root / f"out-{rewrite}-{link}" / "ex.pcap"

                def start(cmd, **kwargs):
                    if cmd[0] in ("mergecap", "editcap", "tcprewrite"):
                        cmd = [sys.executable, str(helper), *cmd]
                    return real_popen(cmd, **kwargs)

                def checked(tools, path, tmp):
                    # Once the pipeline has finished, there must only be one
                    # PCAP, even when MAC conversion is requested.
                    if path.name == "excerpt.pcap":
                        self.assertEqual(list(tmp.glob("*.pcap")), [path])
                    return original_capturecheck(tools, path, tmp)

                tools = excerpt.Tools(capturecheck=[sys.executable, str(helper), "capturecheck"],
                                      log=lambda message: None)
                args = ["--input", str(input_dir), "--out", str(out),
                        "--start", "2018-11-03T13:00:01Z", "--duration", "3s", "--allow-gaps"]
                if rewrite:
                    args.extend(["--rewrite-mac", "1a:5e:73:5b:e3:9b,16:53:d2:bc:4c:91"])
                with patch.object(excerpt.subprocess, "Popen", side_effect=start), \
                        patch.object(excerpt, "capturecheck", side_effect=checked):
                    self.assertEqual(excerpt.main(args, tools=tools), 0)
                meta = json.loads(out.with_name("ex.excerpt.json").read_text())
                self.assertEqual(meta["packets_ip"], 3)
                self.assertEqual(meta["trace_start_ns"], (t0 + 1) * 10**9)
                self.assertEqual(meta["trace_end_ns"], (t0 + 3) * 10**9)
                self.assertFalse(list(out.parent.glob(".excerpt-*")))
                if rewrite:
                    self.assertEqual(out.read_bytes()[40:52], bytes.fromhex("1a5e735be39b1653d2bc4c91"))

        # A failed downstream stage must not publish a partial excerpt or
        # metadata, and its temporary directory must release the disk space.
        helper.write_text(FAKE_TOOL.replace('elif name == "tcprewrite":',
                                          'elif name == "tcprewrite":\n    sys.exit(9)'))
        out = self.root / "failed" / "ex.pcap"
        args = ["--input", str(input_dir), "--out", str(out), "--duration", "5s", "--allow-gaps",
                "--rewrite-mac", "1a:5e:73:5b:e3:9b,16:53:d2:bc:4c:91"]
        with patch.object(excerpt.subprocess, "Popen", side_effect=start):
            self.assertEqual(excerpt.main(args, tools=tools), 2)
        self.assertEqual(list(out.parent.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
