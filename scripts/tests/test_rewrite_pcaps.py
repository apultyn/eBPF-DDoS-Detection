"""Directory rewriting with a fake tcprewrite; no root or network required."""

import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rewrite_pcaps  # noqa: E402


def capture(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 19
    path.write_bytes(header + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
    return path


class RewriteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "day one"
        self.source.mkdir()
        self.args = rewrite_pcaps.parse_args([
            "--input", str(self.source), "--out", str(self.root / "prepared"),
            "--src-mac", "16:53:d2:bc:4c:91", "--dst-mac", "02:00:00:00:00:02",
            "--reserve-mib", "0",
        ])
        self.calls = []
        for replacement in (
            patch.object(rewrite_pcaps.shutil, "which", return_value="/fake/tcprewrite"),
            patch.object(rewrite_pcaps.subprocess, "run", side_effect=self.rewrite),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def rewrite(self, command, **kwargs):
        self.calls.append(command)
        options = dict(option.split("=", 1) for option in command[1:] if "=" in option)
        shutil.copyfile(options["--infile"], options["--outfile"])
        return SimpleNamespace(returncode=0)

    def test_extensionless_nested_files_and_metadata_layout(self):
        ten = capture(self.source / "nested" / "SAT_10")
        two = capture(self.source / "nested" / "SAT_2")
        original = two.read_bytes()
        (self.source / "labels.csv").write_text("not a capture")
        (self.source / "pcapng").write_bytes(bytes.fromhex("0a0d0d0a") + b"\x00" * 24)
        self.assertEqual(rewrite_pcaps.run(self.args), 0)
        self.assertEqual(len(self.calls), 2)
        self.assertIn(f"--infile={two}", self.calls[0])
        self.assertIn(f"--infile={ten}", self.calls[1])
        for option in ("--enet-smac=16:53:d2:bc:4c:91", "--enet-dmac=02:00:00:00:00:02",
                       "--dlt=enet", "--mtu=1500", "--mtu-trunc", "--fixcsum"):
            self.assertIn(option, self.calls[0])
        output = self.args.out / "captures" / self.source.name / "nested" / "SAT_2"
        self.assertEqual(output.read_bytes(), original)
        self.assertEqual(two.read_bytes(), original)
        self.assertFalse(list((self.args.out / "captures").rglob("*log")))
        self.assertTrue((self.args.out / "logs" / self.source.name / "nested" /
                         "SAT_2" / "rewrite.log").is_file())
        state = json.loads((self.args.out / "rewrite.json").read_text())
        self.assertEqual(len(state["completed"]), 2)

    def test_all_classic_magic_signatures(self):
        path = self.root / "no extension"
        for magic in rewrite_pcaps.PCAP_MAGIC:
            with self.subTest(magic=magic.hex()):
                path.write_bytes(magic + b"\x00" * 20)
                self.assertTrue(rewrite_pcaps.is_pcap(path))
                path.write_bytes(magic)
                self.assertFalse(rewrite_pcaps.is_pcap(path))

    def test_resume_skips_only_unchanged_completed_files(self):
        source = capture(self.source / "trace")
        rewrite_pcaps.run(self.args)
        self.args.resume = True
        rewrite_pcaps.run(self.args)
        self.assertEqual(len(self.calls), 1)
        source.write_bytes(source.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            rewrite_pcaps.run(self.args)
        self.assertEqual(len(self.calls), 1)

    def test_resume_refuses_changed_settings_and_outputs(self):
        capture(self.source / "trace")
        rewrite_pcaps.run(self.args)
        self.args.resume = True
        self.args.mtu = 1400
        with self.assertRaisesRegex(ValueError, "settings differ"):
            rewrite_pcaps.run(self.args)
        self.args.mtu = 1500
        output = self.args.out / "captures" / self.source.name / "trace"
        output.write_bytes(output.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "changed"):
            rewrite_pcaps.run(self.args)

    def test_failure_keeps_completed_files_and_can_resume(self):
        first = capture(self.source / "trace_1")
        second = capture(self.source / "trace_2")

        def fail_second(command, **kwargs):
            result = self.rewrite(command, **kwargs)
            if f"--infile={second}" in command:
                return SimpleNamespace(returncode=7)
            return result

        with patch.object(rewrite_pcaps.subprocess, "run", side_effect=fail_second):
            with self.assertRaisesRegex(ValueError, "exited 7"):
                rewrite_pcaps.run(self.args)
        output = self.args.out / "captures" / self.source.name
        self.assertTrue((output / first.name).is_file())
        self.assertFalse((output / second.name).exists())
        self.assertFalse(list(self.args.out.rglob("*.partial")))
        state = json.loads((self.args.out / "rewrite.json").read_text())
        self.assertEqual(len(state["completed"]), 1)
        self.args.resume = True
        rewrite_pcaps.run(self.args)
        self.assertEqual(len(self.calls), 3)
        self.assertTrue((output / second.name).is_file())

    def test_low_space_stops_before_rewrite(self):
        capture(self.source / "trace")
        with patch.object(rewrite_pcaps.shutil, "disk_usage", return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(ValueError, "insufficient free space"):
                rewrite_pcaps.run(self.args)
        self.assertFalse(self.calls)

    def test_dry_run_needs_no_tcprewrite_and_writes_nothing(self):
        capture(self.source / "trace")
        self.args.dry_run = True
        with patch.object(rewrite_pcaps.shutil, "which", return_value=None):
            self.assertEqual(rewrite_pcaps.run(self.args), 0)
        self.assertFalse(self.args.out.exists())
        self.assertFalse(self.calls)

    def test_refuses_overlapping_directories(self):
        capture(self.source / "trace")
        self.args.out = self.source / "prepared"
        with self.assertRaisesRegex(ValueError, "must not contain each other"):
            rewrite_pcaps.run(self.args)

    def test_multiple_directories_preserve_separate_namespaces(self):
        capture(self.source / "trace")
        other = self.root / "day two"
        capture(other / "trace")
        self.args.input.append(other)
        rewrite_pcaps.run(self.args)
        self.assertEqual(len(self.calls), 2)
        for name in ("day one", "day two"):
            self.assertTrue((self.args.out / "captures" / name / "trace").is_file())

    def test_existing_outputs_are_not_overwritten(self):
        capture(self.source / "trace")
        rewrite_pcaps.run(self.args)
        with self.assertRaisesRegex(ValueError, "not empty"):
            rewrite_pcaps.run(self.args)

    def test_empty_selection_errors_without_creating_outputs(self):
        with self.assertRaisesRegex(ValueError, "no classic PCAP"):
            rewrite_pcaps.run(self.args)
        self.assertFalse(self.args.out.exists())

    def test_input_changed_during_rewrite_is_not_published(self):
        source = capture(self.source / "trace")

        def change_input(command, **kwargs):
            result = self.rewrite(command, **kwargs)
            source.write_bytes(source.read_bytes() + b"changed")
            return result

        with patch.object(rewrite_pcaps.subprocess, "run", side_effect=change_input):
            with self.assertRaisesRegex(ValueError, "input changed"):
                rewrite_pcaps.run(self.args)
        self.assertFalse((self.args.out / "captures" / self.source.name / "trace").exists())
        self.assertFalse(list(self.args.out.rglob("*.partial")))


if __name__ == "__main__":
    unittest.main()
