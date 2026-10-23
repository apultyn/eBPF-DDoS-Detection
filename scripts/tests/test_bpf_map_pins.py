"""Pin-directory regression checks; no root, BPF, or detector execution needed."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


BASH = os.environ.get("TEST_BASH") or shutil.which("bash")
SCRIPTS = Path(__file__).resolve().parent
HELPER = SCRIPTS.parent / "bpf-map-pins.sh"
LAYOUTS = ("xdp/globals", "tc/globals", "root")
USER_MAPS = ("us_blocklist_map", "us_blocked_stats")
KERNEL_MAPS = tuple(f"sketch_{i}" for i in range(4)) + tuple(
    f"topk_map_{i}" for i in range(4)
) + ("slot_stats", "blocked_stats", "blocklist_map")


@unittest.skipUnless(BASH, "needs Bash")
class PinDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bpf-pin-check-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.dirs = [self.work / layout for layout in LAYOUTS]

    @staticmethod
    def populate(directory, names=USER_MAPS):
        directory.mkdir(parents=True, exist_ok=True)
        for name in names:
            (directory / name).touch()

    def discover(self, dirs=None):
        command = '''
source "$1"
shift
BPF_PIN_DIRS=("$1" "$2" "$3")
shift 3
sudo() { "$@"; }
find_bpf_pin_dir "$@"
'''
        return subprocess.run(
            [BASH, "-c", command, "check", HELPER.as_posix(),
             *(p.as_posix() for p in (dirs or self.dirs)), *USER_MAPS],
            capture_output=True, text=True, timeout=15,
        )

    def test_each_loader_layout(self):
        for layout in LAYOUTS:
            with self.subTest(layout=layout):
                dirs = [self.work / layout / candidate for candidate in LAYOUTS]
                selected = dirs[LAYOUTS.index(layout)]
                self.populate(selected)
                result = self.discover(dirs)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), selected.as_posix())

    def test_partial_set_does_not_mask_complete_set(self):
        self.populate(self.dirs[0], USER_MAPS[:1])
        self.populate(self.dirs[1])
        result = self.discover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), self.dirs[1].as_posix())

    def test_missing_map_fails_with_diagnostics(self):
        self.populate(self.dirs[0], USER_MAPS[:1])
        result = self.discover()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("no complete set", result.stderr)
        self.assertIn(USER_MAPS[1], result.stderr)

    def test_distinct_complete_sets_are_refused(self):
        self.populate(self.dirs[0])
        self.populate(self.dirs[2])
        result = self.discover()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("multiple distinct", result.stderr)

    def test_symlinks_to_same_pin_directory_are_allowed(self):
        self.populate(self.dirs[0])
        self.dirs[1].parent.mkdir(parents=True)
        try:
            self.dirs[1].symlink_to(self.dirs[0], target_is_directory=True)
        except OSError:
            self.skipTest("directory symlinks are unavailable")
        result = self.discover()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), self.dirs[0].as_posix())

    def run_experiment(self, script, case, layouts, missing=False):
        case.mkdir(parents=True)
        pins = case / "pins"
        names = KERNEL_MAPS if script.name.startswith("ker-") else USER_MAPS
        for layout in layouts:
            self.populate(pins / layout, names[:-1] if missing else names)
        helper = case / "scripts" / HELPER.name
        helper.parent.mkdir()
        helper.write_text(HELPER.read_text() + '''
BPF_PIN_DIRS=("$MOCK_PIN_BASE/xdp/globals" "$MOCK_PIN_BASE/tc/globals" "$MOCK_PIN_BASE/root")
''', encoding="utf-8", newline="\n")
        log = case / "commands.tsv"
        mock = case / "mock-env.sh"
        mock.write_text('''
mock_log() {
    printf '%s' "$1" >> "$MOCK_LOG"
    shift
    printf '\\t%s' "$@" >> "$MOCK_LOG"
    printf '\\n' >> "$MOCK_LOG"
}
clang() { mock_log clang "$@"; }
go() { mock_log go "$@"; }
uname() { printf 'x86_64\\n'; }
ip() { mock_log ip "$@"; }
rm() { mock_log rm "$@"; }
python3() { mock_log python3 "$@"; }
sudo() {
    if [[ $1 == ./detector-* ]]; then mock_log "$@"; else "$@"; fi
}
''', encoding="utf-8", newline="\n")
        result = subprocess.run(
            [BASH, script.as_posix(), "17"], cwd=case,
            env=dict(os.environ, BASH_ENV=mock.as_posix(),
                     MOCK_PIN_BASE=pins.as_posix(), MOCK_LOG=log.as_posix()),
            capture_output=True, text=True, timeout=15,
        )
        entries = [line.split("\t") for line in log.read_text().splitlines()]
        return result, entries, pins

    def test_all_eight_scripts_pass_discovered_directory(self):
        scripts = sorted(SCRIPTS.glob("*.sh"))
        self.assertEqual(len(scripts), 8)
        for script in scripts:
            for layout in LAYOUTS:
                with self.subTest(script=script.name, layout=layout):
                    result, entries, pins = self.run_experiment(
                        script, self.work / script.stem / layout, [layout],
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    detector = next(e for e in entries if
                                    e[0].startswith("./detector-") or e[0] == "python3")
                    self.assertEqual(detector[detector.index("-pin-dir") + 1],
                                     (pins / layout).as_posix())
                    self.assertEqual(detector[detector.index("-duration") + 1], "44m30s")
                    removals = [e for e in entries if e[0] == "rm"]
                    self.assertEqual(len(removals), 3)
                    for candidate in LAYOUTS:
                        self.assertTrue(any((pins / candidate).as_posix() + "/sketch_0" in e
                                            for e in removals))

    def test_all_scripts_stop_and_detach_when_map_is_missing(self):
        for script in sorted(SCRIPTS.glob("*.sh")):
            with self.subTest(script=script.name):
                result, entries, _ = self.run_experiment(
                    script, self.work / script.stem, [LAYOUTS[0]], missing=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("no complete set", result.stderr)
                self.assertFalse(any(e[0].startswith("./detector-") or e[0] == "python3"
                                     for e in entries))
                self.assertTrue(any(e[0] == "ip" and e[-1] == "off" for e in entries))


if __name__ == "__main__":
    unittest.main()
