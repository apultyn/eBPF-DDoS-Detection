"""Tests for memwatch.py with a fake cgroup directory and fake systemd tools.

Nothing here needs root or systemd: systemd-run is replaced by a script
that just runs the command, systemctl by one that names a prepared fake
cgroup, and the "command" itself rewrites the fake cgroup's files to
simulate memory use. What only a real Linux system can show is listed in
scripts/README.md.
"""

import csv
import json
import os
import signal
import statistics
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import memwatch  # noqa: E402

STAT = """anon {anon}
file 4096000
kernel {kernel}
kernel_stack 16384
pagetables 81920
sec_pagetables 0
percpu 2048
sock {sock}
vmalloc 0
shmem 0
slab 300000
slab_reclaimable 100000
slab_unreclaimable 200000
"""

# Two /proc/stat snapshots of a two-core machine, as in the Go tests:
# columns are user nice system idle iowait irq softirq steal guest
# guest_nice, in 10 ms ticks. Between them cpu0 is busy for 90 of 100
# ticks, 50 of them in softirq, and cpu1 for 10; guest is already in user.
PROC_STAT_BEFORE = """cpu  2000 0 1000 50000 100 0 500 0 900 0
cpu0 1000 0 500 25000 50 0 400 0 900 0
cpu1 1000 0 500 25000 50 0 100 0 0 0
intr 123456 0 0
"""
PROC_STAT_AFTER = """cpu  2040 0 1010 50100 100 0 550 0 950 0
cpu0 1030 0 510 25010 50 0 450 0 950 0
cpu1 1010 0 500 25090 50 0 100 0 0 0
intr 123999 0 0
"""


def make_exe(path: Path, body: str) -> str:
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def fake(tmp_path, monkeypatch):
    """A fake system: cgroup root, mounts file and tools."""
    root = tmp_path / "cgroup"
    cg = root / "system.slice" / "fake.scope"
    cg.mkdir(parents=True)
    write_mem(cg, anon=1_000_000, kernel=500_000, sock=0)

    mounts = tmp_path / "mounts"
    mounts.write_text(f"cgroup2 {root} cgroup2 rw,nosuid 0 0\n")

    bin_ = tmp_path / "bin"
    bin_.mkdir()

    run = make_exe(bin_ / "systemd-run", """
        import os, sys
        args = sys.argv[1:]
        cmd = args[args.index("--") + 1:]
        os.execvp(cmd[0], cmd)
    """)
    ctl = make_exe(bin_ / "systemctl", """
        import os
        print(os.environ["FAKE_CGROUP"])
    """)
    bpf = make_exe(bin_ / "bpftool", """
        import json, sys
        kind = sys.argv[2]
        print(json.dumps([{"id": 7, "type": "array" if kind == "map" else "xdp"}]))
    """)

    proc_stat = tmp_path / "stat"
    proc_stat.write_text(PROC_STAT_BEFORE)

    monkeypatch.setenv("FAKE_CGROUP", "/system.slice/fake.scope")
    monkeypatch.setenv("CG", str(cg))
    monkeypatch.setenv("PROC_STAT", str(proc_stat))

    env = memwatch.Env(cgroup_root=root, mounts=mounts, systemd_run=run, systemctl=ctl,
                       bpftool=bpf, proc_stat=proc_stat, is_root=lambda: True, log=lambda m: None)

    return {"env": env, "cg": cg, "root": root, "out": tmp_path / "out", "tmp": tmp_path}


def write_mem(cg: Path, anon: int, kernel: int, sock: int, peak: int | None = None):
    (cg / "memory.stat").write_text(STAT.format(anon=anon, kernel=kernel, sock=sock))
    (cg / "memory.current").write_text(f"{anon + kernel + sock + 4096000}\n")
    (cg / "memory.peak").write_text(f"{peak or anon + kernel + sock + 5_000_000}\n")


# A command that grows its fake cgroup's memory three times and exits.
GROWING = """
import os, sys, time
cg = os.environ["CG"]
for i, anon in enumerate([2_000_000, 3_000_000, 2_500_000]):
    open(f"{cg}/memory.stat", "w").write(
        "anon %d\\nfile 1\\nkernel 600000\\nsock 4096\\npercpu 1\\nslab 2\\nvmalloc 3\\n"
        "kernel_stack 4\\npagetables 5\\n" % anon)
    open(f"{cg}/memory.current", "w").write(str(anon + 700000))
    open(f"{cg}/memory.peak", "w").write("9999999")
    time.sleep(0.12)
sys.exit(int(sys.argv[1]))
"""


def run_memwatch(fake, *command, extra=()):
    return memwatch.main(["--out", str(fake["out"]), "--interval", "0.05", *extra, "--", *command],
                         env=fake["env"])


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


# ------------------------------------------------------------ memory.stat


def test_parse_stat_by_name():
    stat = memwatch.parse_stat("kernel 10\nnew_field_in_middle 5\nanon 20\nsock 3\nbroken line here\n")

    assert stat == {"kernel": 10, "new_field_in_middle": 5, "anon": 20, "sock": 3}
    assert memwatch.main_value(stat) == 33


def test_main_does_not_add_kernel_parts_again():
    stat = memwatch.parse_stat(STAT.format(anon=100, kernel=50, sock=7))

    # percpu, slab, kernel_stack, pagetables are inside "kernel".
    assert memwatch.main_value(stat) == 157


def test_missing_field_leaves_cell_empty():
    s = memwatch.Sample(ts_ns=1, current=None, stat={"anon": 5, "kernel": 6}, stat_text="", peak=None)
    row = dict(zip(memwatch.CSV_COLUMNS, s.row()))

    assert row["anon"] == "5" and row["kernel"] == "6"
    assert row["sock"] == "" and row["current"] == "" and row["main"] == ""


def test_exit_code_of_signal_death():
    assert memwatch.exit_code(3) == 3
    assert memwatch.exit_code(-signal.SIGKILL) == 137


# ------------------------------------------------------------ preconditions


def test_requires_root(fake):
    fake["env"].is_root = lambda: False

    with pytest.raises(memwatch.MemwatchError, match="root"):
        memwatch.check_preconditions(fake["env"])


def test_requires_cgroup_v2(fake):
    fake["env"].mounts.write_text(f"tmpfs {fake['root']} tmpfs rw 0 0\n")

    with pytest.raises(memwatch.MemwatchError, match="cgroup2fs"):
        memwatch.check_preconditions(fake["env"])


def test_requires_systemd_run(fake):
    fake["env"].systemd_run = "/nonexistent/systemd-run"

    with pytest.raises(memwatch.MemwatchError, match="systemd-run"):
        memwatch.check_preconditions(fake["env"])


def test_cgroup_without_memory_files(fake):
    (fake["cg"] / "memory.peak").unlink()

    assert run_memwatch(fake, sys.executable, "-c", "pass") == 2
    assert not (fake["out"] / "memory_summary.json").exists()


# ------------------------------------------------------------ a run


def test_run_logs_samples_and_summary(fake):
    rc = run_memwatch(fake, sys.executable, "-c", GROWING, "3")

    assert rc == 3

    rows = read_csv(fake["out"] / "memory.csv")
    assert list(rows[0]) == memwatch.CSV_COLUMNS
    assert len(rows) >= 3

    # Every row is internally consistent and the growth was seen.
    for r in rows:
        assert int(r["main"]) == int(r["anon"]) + int(r["kernel"]) + int(r["sock"])
    assert max(int(r["anon"]) for r in rows) == 3_000_000

    ts = [int(r["ts_ns"]) for r in rows]
    assert ts == sorted(ts) and abs(ts[0] - time.time_ns()) < 60 * 10**9

    s = json.loads((fake["out"] / "memory_summary.json").read_text())
    assert s["exit_code"] == 3
    assert s["samples"] == len(rows)
    assert s["main_max"] == 3_000_000 + 600_000 + 4096
    assert s["main_median"] == statistics.median(int(r["main"]) for r in rows)
    assert s["current_max"] == max(int(r["current"]) for r in rows)
    assert s["peak"] == 9_999_999
    assert s["final_source"] == "after_exit"
    assert s["unit"].startswith("memwatch-") and s["unit"].endswith(".scope")
    assert s["kernel_version"] == os.uname().release

    assert "anon 2500000" in (fake["out"] / "memory.stat.final").read_text()


def test_final_falls_back_to_last_sample_when_cgroup_is_gone(fake):
    remove_cgroup = GROWING.replace("sys.exit(", "import shutil; shutil.rmtree(cg); sys.exit(")

    assert run_memwatch(fake, sys.executable, "-c", remove_cgroup, "0") == 0

    s = json.loads((fake["out"] / "memory_summary.json").read_text())
    assert s["final_source"] == "last_sample"
    assert s["peak"] == 9_999_999
    assert (fake["out"] / "memory.stat.final").exists()


def test_signal_death_exit_code(fake):
    rc = run_memwatch(fake, sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)")

    assert rc == 137
    assert json.loads((fake["out"] / "memory_summary.json").read_text())["exit_code"] == 137


def test_refuses_to_overwrite(fake):
    fake["out"].mkdir()
    (fake["out"] / "memory.csv").write_text("old")

    assert run_memwatch(fake, sys.executable, "-c", "pass") == 2
    assert (fake["out"] / "memory.csv").read_text() == "old"

    assert run_memwatch(fake, sys.executable, "-c", "pass", extra=["--force"]) == 0


# ------------------------------------------------------------ bpftool


def test_bpftool_snapshots_during_and_at_end(fake):
    rc = run_memwatch(fake, sys.executable, "-c", GROWING, "0", extra=["--bpftool", "--bpftool-after", "0.1"])

    assert rc == 0
    maps = json.loads((fake["out"] / "bpf_maps.json").read_text())
    progs = json.loads((fake["out"] / "bpf_progs.json").read_text())

    assert set(maps) == {"during", "end"} and maps["end"]["maps"][0]["type"] == "array"
    assert progs["during"]["progs"][0]["type"] == "xdp"


def test_missing_bpftool_warns_and_continues(fake):
    fake["env"].bpftool = "/nonexistent/bpftool"

    assert run_memwatch(fake, sys.executable, "-c", "pass", extra=["--bpftool"]) == 0

    s = json.loads((fake["out"] / "memory_summary.json").read_text())
    assert any("bpftool" in w for w in s["warnings"])
    assert not (fake["out"] / "bpf_maps.json").exists()


# ------------------------------------------------------------ signals


# Waits for SIGINT, counts how many it gets, then exits like the detector
# does after a clean shutdown.
INTERRUPTIBLE = """
import os, signal, sys, time
got = []
signal.signal(signal.SIGINT, lambda *_: got.append(1))
open(os.environ["READY"], "w").write("ready")
deadline = time.time() + 10
while not got and time.time() < deadline:
    time.sleep(0.01)
time.sleep(0.2)  # a second SIGINT, if any, would arrive here
open(os.environ["GOT"], "w").write(str(len(got)))
sys.exit(0 if got else 9)
"""


def test_ctrl_c_is_forwarded_once(fake):
    tmp = fake["tmp"]
    ready, got = tmp / "ready", tmp / "got"

    # Run memwatch in a child process with the fake environment, in its own
    # process group, so a group-wide SIGINT can stand in for Ctrl-C.
    runner = tmp / "runner.py"
    runner.write_text(textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(Path(memwatch.__file__).parent)!r})
        import memwatch
        from pathlib import Path
        env = memwatch.Env(cgroup_root=Path({str(fake['root'])!r}), mounts=Path({str(fake['env'].mounts)!r}),
                           systemd_run={fake['env'].systemd_run!r}, systemctl={fake['env'].systemctl!r},
                           is_root=lambda: True, log=lambda m: None)
        sys.exit(memwatch.main(sys.argv[1:], env=env))
    """))

    env = {**os.environ, "READY": str(ready), "GOT": str(got)}
    p = subprocess.Popen(
        [sys.executable, str(runner), "--out", str(fake["out"]), "--interval", "0.05",
         "--", sys.executable, "-c", INTERRUPTIBLE],
        env=env, start_new_session=True,
    )

    deadline = time.time() + 10
    while not ready.exists() and time.time() < deadline:
        time.sleep(0.02)
    assert ready.exists(), "command never started"

    # Like Ctrl-C: SIGINT to the whole foreground process group.
    os.killpg(p.pid, signal.SIGINT)

    assert p.wait(timeout=15) == 0
    assert got.read_text() == "1", "the command must get exactly one SIGINT"

    s = json.loads((fake["out"] / "memory_summary.json").read_text())
    assert s["signals_forwarded"] == ["SIGINT"]
    assert s["exit_code"] == 0


# ------------------------------------------------------------ cpu


def test_parse_proc_stat():
    t = memwatch.parse_proc_stat(PROC_STAT_BEFORE)

    assert t.all == [2000, 0, 1000, 50000, 100, 0, 500, 0]
    assert sorted(t.cores) == [0, 1] and t.cores[0][6] == 400

    # Missing trailing columns read as zero.
    assert memwatch.parse_proc_stat("cpu 1 2 3 4 5\n").all == [1, 2, 3, 4, 5, 0, 0, 0]

    for bad in ("intr 1 2\n", "cpu 1 2 3\n", "cpu 1 x 3 4\n"):
        with pytest.raises(ValueError):
            memwatch.parse_proc_stat(bad)


def test_cpu_sample():
    c = memwatch.cpu_sample(memwatch.parse_proc_stat(PROC_STAT_AFTER),
                            memwatch.parse_proc_stat(PROC_STAT_BEFORE), ts_ns=7)

    assert (c.busy, c.total, c.softirq) == (10**9, 2 * 10**9, 5 * 10**8)
    assert c.max_core_share == 0.9
    assert c.row() == [7, 10**9, 2 * 10**9, 5 * 10**8, "0.9000"]


def test_cpu_sample_counter_going_backwards_and_cores_coming_and_going():
    before = memwatch.parse_proc_stat("cpu 100 0 0 1000 50\ncpu0 100 0 0 1000 50\ncpu1 0 0 0 0 0\n")
    after = memwatch.parse_proc_stat("cpu 150 0 0 1050 30\ncpu0 150 0 0 1050 30\ncpu2 9 0 0 0 0\n")

    c = memwatch.cpu_sample(after, before, ts_ns=0)

    # iowait fell by 20 ticks and counts as zero; only cpu0 is at both ends.
    assert (c.busy, c.total) == (5 * 10**8, 10**9)
    assert c.max_core_share == 0.5


# Advances the fake /proc/stat three times, by the same step as from
# PROC_STAT_BEFORE to PROC_STAT_AFTER, and exits.
ADVANCING = """
import os, time
step = [[40, 0, 10, 100, 0, 0, 50, 0], [30, 0, 10, 10, 0, 0, 50, 0], [10, 0, 0, 90, 0, 0, 0, 0]]
base = [[2000, 0, 1000, 50000, 100, 0, 500, 0], [1000, 0, 500, 25000, 50, 0, 400, 0],
        [1000, 0, 500, 25000, 50, 0, 100, 0]]
for i in range(1, 4):
    lines = [name + " " + " ".join(str(b + i * s) for b, s in zip(base[n], step[n]))
             for n, name in enumerate(["cpu", "cpu0", "cpu1"])]
    tmp = os.environ["PROC_STAT"] + ".tmp"
    open(tmp, "w").write("\\n".join(lines) + "\\n")
    os.replace(tmp, os.environ["PROC_STAT"])
    time.sleep(0.12)
"""


def test_cpu_logs_machine_use(fake):
    assert run_memwatch(fake, sys.executable, "-c", ADVANCING, extra=["--cpu"]) == 0

    rows = read_csv(fake["out"] / "cpu.csv")
    assert list(rows[0]) == memwatch.CPU_CSV_COLUMNS
    assert len(rows) >= 3

    # The samples together cover the three steps, however they fell
    # between the reads.
    assert sum(int(r["host_busy_ns"]) for r in rows) == 3 * 10**9
    assert sum(int(r["host_total_ns"]) for r in rows) == 6 * 10**9
    assert max(float(r["host_max_core_share"] or 0) for r in rows) == 0.9

    c = json.loads((fake["out"] / "memory_summary.json").read_text())["cpu"]
    assert c["samples"] == len(rows)
    assert c["busy_share"] == 0.5 and c["softirq_share"] == 0.25
    assert c["max_core_share_max"] == 0.9


def test_cpu_not_logged_without_flag(fake):
    assert run_memwatch(fake, sys.executable, "-c", "pass") == 0

    assert not (fake["out"] / "cpu.csv").exists()
    assert "cpu" not in json.loads((fake["out"] / "memory_summary.json").read_text())


def test_unreadable_proc_stat_warns_and_continues(fake):
    fake["env"].proc_stat = fake["tmp"] / "missing"

    assert run_memwatch(fake, sys.executable, "-c", "pass", extra=["--cpu"]) == 0

    s = json.loads((fake["out"] / "memory_summary.json").read_text())
    assert any("CPU use is not recorded" in w for w in s["warnings"])
    assert "cpu" not in s
    assert not (fake["out"] / "cpu.csv").exists()
