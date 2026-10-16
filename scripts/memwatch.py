#!/usr/bin/env python3
"""Run a command in its own cgroup and log its memory use.

    sudo python3 scripts/memwatch.py --out results/run1 [--interval 0.5] \\
        [--bpftool] -- ./detector -iface eth0 -out results/run1

The command is started with systemd-run --scope, so it gets a cgroup of its
own while this script stays outside it and its own memory is not counted.
Every --interval seconds the cgroup's memory.current and memory.stat are
appended to <out>/memory.csv. When the command ends, <out>/memory.stat.final
and <out>/memory_summary.json are written.

The main figure is main = anon + kernel + sock. In memory.stat (Linux 6.8,
Documentation/admin-guide/cgroup-v2.rst) "kernel" is the total kernel memory
including kernel_stack, pagetables, percpu, vmalloc and slab, and "sock" is
network transmission buffers, which kernel does not include, so nothing is
counted twice. "file" (page cache) is logged but not part of main.

Ctrl-C is forwarded to the command as a single SIGINT, so it can shut down
cleanly; the script then records the final readings and exits with the
command's exit code. Linux only; standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import secrets
import shutil
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# memory.stat fields logged per sample, in CSV column order.
STAT_FIELDS = ["anon", "file", "kernel", "sock", "percpu", "slab", "vmalloc",
               "kernel_stack", "pagetables"]

CSV_COLUMNS = ["ts_ns", "current"] + STAT_FIELDS + ["main"]

# main = anon + kernel + sock. "kernel" already includes percpu, slab,
# vmalloc, kernel_stack and pagetables.
MAIN_FIELDS = ("anon", "kernel", "sock")

OUTPUT_FILES = ("memory.csv", "memory.stat.final", "memory_summary.json",
                "bpf_maps.json", "bpf_progs.json")


class MemwatchError(Exception):
    """A precondition failed; the message is shown to the user."""


@dataclass
class Env:
    """Everything that touches the system, replaceable in tests."""

    cgroup_root: Path = Path("/sys/fs/cgroup")
    mounts: Path = Path("/proc/self/mounts")
    systemd_run: str = "systemd-run"
    systemctl: str = "systemctl"
    bpftool: str = "bpftool"
    is_root: Callable[[], bool] = field(default=lambda: os.geteuid() == 0)
    now_ns: Callable[[], int] = time.time_ns
    log: Callable[[str], None] = field(default=lambda m: print(f"memwatch: {m}", file=sys.stderr, flush=True))


# ---------------------------------------------------------------- checks


def check_preconditions(env: Env) -> None:
    if not env.is_root():
        raise MemwatchError("must run as root (sudo), to create a cgroup and read its files")

    if shutil.which(env.systemd_run) is None:
        raise MemwatchError(f"{env.systemd_run} not found; systemd is required")

    if shutil.which(env.systemctl) is None:
        raise MemwatchError(f"{env.systemctl} not found; systemd is required")

    fstype = mount_type(env.mounts, env.cgroup_root)
    if fstype != "cgroup2":
        raise MemwatchError(
            f"{env.cgroup_root} is {fstype or 'not mounted'}, not cgroup2fs; "
            "a cgroup v2 (unified) hierarchy is required"
        )


def mount_type(mounts: Path, mount_point: Path) -> str | None:
    """File system type mounted at mount_point, from /proc/self/mounts."""
    try:
        lines = mounts.read_text().splitlines()
    except OSError:
        return None

    found = None
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == str(mount_point):
            found = parts[2]  # the last mount on a point is the visible one

    return found


# ---------------------------------------------------------------- cgroup


def unit_name() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"memwatch-{stamp}-{secrets.token_hex(3)}"


def find_cgroup(env: Env, unit: str, alive: Callable[[], bool], timeout: float = 5.0) -> Path:
    """Ask systemd for the scope's cgroup, retrying until it exists."""
    deadline = time.monotonic() + timeout

    while True:
        out = subprocess.run(
            [env.systemctl, "show", "-p", "ControlGroup", "--value", f"{unit}.scope"],
            capture_output=True, text=True,
        )
        rel = out.stdout.strip()

        if out.returncode == 0 and rel:
            path = env.cgroup_root / rel.lstrip("/")
            if path.is_dir():
                missing = [f for f in ("memory.current", "memory.stat", "memory.peak")
                           if not (path / f).exists()]
                if missing:
                    raise MemwatchError(f"{path} lacks {', '.join(missing)}; is the memory controller enabled?")
                return path

        if not alive():
            raise MemwatchError(f"the command exited before the cgroup of {unit}.scope could be found")

        if time.monotonic() > deadline:
            raise MemwatchError(f"no cgroup for {unit}.scope after {timeout:.0f} s (systemctl said {rel!r})")

        time.sleep(0.05)


def parse_stat(text: str) -> dict[str, int]:
    """Parse memory.stat, a flat "key value" file. Keys are looked up by
    name; the kernel may add or reorder entries."""
    stat = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                stat[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return stat


def main_value(stat: dict[str, int]) -> int | None:
    """anon + kernel + sock, or None if any of them is missing."""
    if any(f not in stat for f in MAIN_FIELDS):
        return None
    return sum(stat[f] for f in MAIN_FIELDS)


def read_int(path: Path) -> int | None:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


@dataclass
class Sample:
    ts_ns: int
    current: int | None
    stat: dict[str, int]
    stat_text: str
    peak: int | None

    @property
    def main(self) -> int | None:
        return main_value(self.stat)

    def row(self) -> list:
        """CSV row; a field missing from memory.stat is left empty."""
        cells = [self.ts_ns, _cell(self.current)]
        cells += [_cell(self.stat.get(f)) for f in STAT_FIELDS]
        cells.append(_cell(self.main))
        return cells


def _cell(v: int | None) -> str:
    return "" if v is None else str(v)


def read_sample(cgroup: Path, now_ns: int) -> Sample | None:
    """Read the cgroup's memory files, or None once it is gone."""
    try:
        stat_text = (cgroup / "memory.stat").read_text()
    except OSError:
        return None

    return Sample(
        ts_ns=now_ns,
        current=read_int(cgroup / "memory.current"),
        stat=parse_stat(stat_text),
        stat_text=stat_text,
        peak=read_int(cgroup / "memory.peak"),
    )


# ---------------------------------------------------------------- bpftool


def bpftool_snapshot(env: Env) -> dict:
    """Run bpftool -j map show and prog show; errors are recorded, not raised."""
    snap = {"ts_ns": env.now_ns()}
    for kind in ("map", "prog"):
        out = subprocess.run([env.bpftool, "-j", kind, "show"], capture_output=True, text=True)
        if out.returncode == 0:
            try:
                snap[kind] = json.loads(out.stdout or "[]")
            except json.JSONDecodeError:
                snap[kind] = {"error": "unparseable output", "raw": out.stdout}
        else:
            snap[kind] = {"error": out.stderr.strip() or f"exit {out.returncode}"}
    return snap


# ---------------------------------------------------------------- run


def exit_code(returncode: int) -> int:
    """Shell-style exit code: a death by signal N becomes 128 + N."""
    return 128 - returncode if returncode < 0 else returncode


def run(args: argparse.Namespace, env: Env) -> int:
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    existing = [f for f in OUTPUT_FILES if (out / f).exists()]
    if existing and not args.force:
        raise MemwatchError(f"{out} already has {', '.join(existing)}; use --force to overwrite")

    use_bpftool = False
    warnings: list[str] = []
    if args.bpftool:
        if shutil.which(env.bpftool):
            use_bpftool = True
        else:
            warnings.append(f"{env.bpftool} not found; BPF maps and programs are not recorded")
            env.log("warning: " + warnings[-1])

    unit = unit_name()
    cmd = [env.systemd_run, "--scope", f"--unit={unit}", "-p", "MemoryAccounting=yes",
           "--quiet", "--"] + args.command

    started_ns = env.now_ns()

    # The command gets its own session, so that a Ctrl-C in the terminal
    # reaches only this script, which forwards it exactly once. A second
    # SIGINT would otherwise kill the detector before it writes its files.
    child = subprocess.Popen(cmd, start_new_session=True)

    forwarded: list[int] = []

    def forward(signum, _frame):
        if child.poll() is None:
            forwarded.append(signum)
            env.log(f"forwarding {signal.Signals(signum).name} to the command")
            try:
                child.send_signal(signum)
            except ProcessLookupError:
                pass

    old = {s: signal.signal(s, forward) for s in (signal.SIGINT, signal.SIGTERM)}

    try:
        try:
            cgroup = find_cgroup(env, unit, alive=lambda: child.poll() is None)
        except MemwatchError:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            child.wait()
            raise

        env.log(f"watching {unit}.scope at {cgroup}")
        samples, last, bpf = poll(cgroup, child, args, env, use_bpftool)
    finally:
        for s, h in old.items():
            signal.signal(s, h)

    returncode = exit_code(child.wait())
    finished_ns = env.now_ns()

    # The cgroup is removed when the command exits. Try one last read; if
    # it is already gone, the last sample stands in for the final state.
    final = read_sample(cgroup, env.now_ns())
    final_source = "after_exit"
    if final is None:
        final, final_source = last, "last_sample"

    if use_bpftool:
        bpf["end"] = bpftool_snapshot(env)
        write_bpf(out, bpf)

    if final is not None:
        (out / "memory.stat.final").write_text(final.stat_text)

    summary = summarize(
        unit=unit, cgroup=cgroup, args=args, env=env, samples=samples, final=final,
        final_source=final_source, returncode=returncode, started_ns=started_ns,
        finished_ns=finished_ns, forwarded=forwarded, warnings=warnings,
    )
    (out / "memory_summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    env.log(f"{summary['samples']} samples; main max {fmt_bytes(summary['main_max'])}, "
            f"median {fmt_bytes(summary['main_median'])}; peak {fmt_bytes(summary['peak'])}; "
            f"command exited with {returncode}")

    return returncode


def poll(cgroup: Path, child: subprocess.Popen, args, env: Env, use_bpftool: bool):
    """Sample until the command exits. Returns main values, the last
    sample, and the bpftool snapshots taken so far."""
    mains: list[int | None] = []
    currents: list[int | None] = []
    last: Sample | None = None
    bpf: dict = {}

    start = time.monotonic()
    tick = 0

    with open(args.out / "memory.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)

        while True:
            s = read_sample(cgroup, env.now_ns())
            if s is not None:
                w.writerow(s.row())
                f.flush()
                mains.append(s.main)
                currents.append(s.current)
                last = s

            if use_bpftool and "during" not in bpf and time.monotonic() - start >= args.bpftool_after:
                bpf["during"] = bpftool_snapshot(env)

            if child.poll() is not None or s is None:
                break

            # Sample on a fixed grid, so slow reads do not stretch the interval.
            tick += 1
            delay = start + tick * args.interval - time.monotonic()
            if delay > 0:
                try:
                    child.wait(timeout=delay)
                except subprocess.TimeoutExpired:
                    pass

    return {"main": mains, "current": currents}, last, bpf


def write_bpf(out: Path, bpf: dict) -> None:
    for kind, name in (("map", "bpf_maps.json"), ("prog", "bpf_progs.json")):
        doc = {when: {"ts_ns": snap["ts_ns"], kind + "s": snap[kind]} for when, snap in bpf.items()}
        (out / name).write_text(json.dumps(doc, indent=2) + "\n")


def summarize(*, unit, cgroup, args, env, samples, final, final_source, returncode,
              started_ns, finished_ns, forwarded, warnings) -> dict:
    mains = [m for m in samples["main"] if m is not None]
    currents = [c for c in samples["current"] if c is not None]

    if len(mains) != len(samples["main"]):
        warnings.append("memory.stat lacked anon, kernel or sock in some samples; main is empty there")

    return {
        "unit": f"{unit}.scope",
        "cgroup": str(cgroup),
        "kernel_version": os.uname().release,
        "command": args.command,
        "interval_s": args.interval,
        "samples": len(samples["main"]),
        "main_definition": "anon + kernel + sock (memory.stat)",
        "main_max": max(mains) if mains else None,
        "main_median": statistics.median(mains) if mains else None,
        "current_max": max(currents) if currents else None,
        "peak": final.peak if final else None,
        "final_source": final_source,
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "exit_code": returncode,
        "signals_forwarded": [signal.Signals(s).name for s in forwarded],
        "warnings": warnings,
    }


def fmt_bytes(v) -> str:
    if v is None:
        return "n/a"
    return f"{v / 2**20:.1f} MiB"


# ---------------------------------------------------------------- CLI


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="memwatch.py",
        description="Run a command in its own cgroup and log its memory use.",
        usage="sudo python3 scripts/memwatch.py --out DIR [--interval S] [--bpftool] -- COMMAND ...",
    )
    p.add_argument("--out", required=True, type=Path, help="directory for memory.csv and the summary")
    p.add_argument("--interval", type=float, default=0.5, help="seconds between samples (default 0.5)")
    p.add_argument("--bpftool", action="store_true",
                   help="also record bpftool map and prog listings, during the run and at the end")
    p.add_argument("--bpftool-after", type=float, default=5.0,
                   help="seconds into the run for the first bpftool snapshot (default 5)")
    p.add_argument("--force", action="store_true", help="overwrite memwatch files in --out")
    p.add_argument("command", nargs=argparse.REMAINDER, help="command to run, after --")

    args = p.parse_args(argv)

    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        p.error("no command given; put it after --")
    if args.interval <= 0:
        p.error("--interval must be positive")

    return args


def main(argv: list[str] | None = None, env: Env | None = None) -> int:
    env = env or Env()
    args = parse_args(sys.argv[1:] if argv is None else argv)

    try:
        check_preconditions(env)
        return run(args, env)
    except MemwatchError as e:
        env.log(f"error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
