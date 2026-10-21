"""Tests for run-detector.sh, through --dry-run.

A dry run prints the commands without running them and skips the checks
that need root and a Linux interface, so the argument handling, the
refusal of blocking and the command lines can be checked anywhere. The
checks themselves (root, offload, attached XDP, the XDP mode actually in
effect) only run on the target machines.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "run-detector.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")


def dry(tmp_path, *args):
    out = tmp_path / "run"
    p = subprocess.run(["bash", str(SCRIPT), "--out", str(out), "--dry-run", *args],
                       capture_output=True, text=True)
    meta = out / "run-detector.json"
    return p, (json.loads(meta.read_text()) if meta.exists() else None)


def test_kernel_run_builds_attaches_and_detaches(tmp_path):
    p, meta = dry(tmp_path, "--variant", "kernel", "--iface", "ens7", "--duration", "65m",
                  "--xdp-mode", "drv")
    assert p.returncode == 0, p.stderr

    lines = [l for l in p.stderr.splitlines() if l.startswith("+ ")]
    text = "\n".join(lines)

    assert "./kernelspace/cmd/detector" in text
    assert "clang -O2 -g -target bpf" in text and "heavy_keeper.c" in text
    attach = next(i for i, l in enumerate(lines) if "xdpdrv obj" in l)
    run = next(i for i, l in enumerate(lines) if "memwatch.py" in l)
    detach = next(i for i, l in enumerate(lines) if "xdpdrv off" in l)
    assert attach < run < detach

    assert "-iface ens7 -duration 65m" in lines[run] and "-block" not in lines[run]

    assert meta["variant"] == "kernel" and meta["blocking"] is False
    assert meta["xdp_mode_requested"] == "drv"
    assert meta["exit_code"] == 0 and any("memwatch.py" in c for c in meta["commands"])


def test_userspace_run_has_no_xdp(tmp_path):
    p, meta = dry(tmp_path, "--variant", "userspace", "--iface", "eth0", "--duration", "65m", "--promisc")
    assert p.returncode == 0, p.stderr

    assert "./userspace/cmd/detector" in p.stderr
    assert " xdpdrv " not in p.stderr and " xdpgeneric " not in p.stderr and "clang" not in p.stderr
    assert "promisc on" in p.stderr
    assert meta["xdp_mode_requested"] is None and meta["promisc"] is True


@pytest.mark.parametrize("flag", ["-block", "--block", "-block=true", "-block-ttl=30s", "-allow=10.0.0.1"])
def test_blocking_flags_are_refused(tmp_path, flag):
    p, meta = dry(tmp_path, "--variant", "userspace", "--iface", "eth0", "--duration", "1m", "--", "-k", "20", flag)

    assert p.returncode == 2 and "blocking is not allowed" in p.stderr
    assert meta is None


@pytest.mark.parametrize("flag", ["-pcap", "-out=x", "-duration=5m", "-iface=eth1"])
def test_script_owned_flags_are_refused(tmp_path, flag):
    p, _ = dry(tmp_path, "--variant", "userspace", "--iface", "eth0", "--duration", "1m", "--", flag)

    assert p.returncode == 2 and "set by this script" in p.stderr


def test_bad_arguments(tmp_path):
    assert dry(tmp_path, "--variant", "both", "--iface", "e", "--duration", "1m")[0].returncode == 2
    assert dry(tmp_path, "--variant", "kernel", "--iface", "e", "--duration", "1m",
               "--xdp-mode", "native")[0].returncode == 2
    assert dry(tmp_path, "--variant", "kernel", "--iface", "e")[0].returncode == 2


def test_extra_detector_flags_are_passed_on(tmp_path):
    p, meta = dry(tmp_path, "--variant", "userspace", "--iface", "eth0", "--duration", "1m",
                  "--", "-k", "20", "-base-threshold", "400")

    assert p.returncode == 0
    assert "-k 20 -base-threshold 400" in p.stderr
    assert meta["extra_detector_flags"] == ["-k", "20", "-base-threshold", "400"]
