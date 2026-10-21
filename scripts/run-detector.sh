#!/usr/bin/env bash
# Run one live detection run on the detector machine, for evaluation.
#
#   sudo scripts/run-detector.sh --variant userspace|kernel --iface IF \
#       --out DIR --duration D [--xdp-mode drv|generic] [--promisc] \
#       [--bpftool] [--detector-bin PATH] [--no-wait] [--dry-run] \
#       [-- EXTRA DETECTOR FLAGS]
#
# The detector runs under scripts/memwatch.py for --duration and never with
# blocking: -block and its related flags are refused. For the kernel variant,
# heavy_keeper.o is compiled from source on every run, attached with XDP in
# the requested mode and detached afterwards, also on errors and Ctrl-C.
#
# Before anything runs the script checks that it is root, that the
# interface exists, that GRO and LRO are off, and that no XDP program is
# already attached. Everything run, and the versions involved, is recorded
# in <out>/run-detector.json.
#
# The detector must start after the replay, so that its warm-up sees
# traffic rather than empty windows. The script therefore builds and
# attaches everything first, then waits for Enter: start tcpreplay on the
# sender, then press Enter here. --no-wait starts the detector at once.
# See docs/live-evaluation.md.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PIN_DIR=/sys/fs/bpf
KERNEL_PINS=(sketch_0 sketch_1 sketch_2 sketch_3 topk_map_0 topk_map_1 topk_map_2 topk_map_3
             slot_stats blocked_stats blocklist_map)

variant="" iface="" out="" duration="" xdp_mode="drv" promisc=0 bpftool=0
detector_bin="" dry_run=0 wait=1
extra=()

die() { echo "run-detector: error: $*" >&2; exit 2; }
log() { echo "run-detector: $*" >&2; }

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --variant)      variant=$2; shift 2 ;;
        --iface)        iface=$2; shift 2 ;;
        --out)          out=$2; shift 2 ;;
        --duration)     duration=$2; shift 2 ;;
        --xdp-mode)     xdp_mode=$2; shift 2 ;;
        --promisc)      promisc=1; shift ;;
        --bpftool)      bpftool=1; shift ;;
        --detector-bin) detector_bin=$2; shift 2 ;;
        --dry-run)      dry_run=1; shift ;;
        --no-wait)      wait=0; shift ;;
        -h|--help)      usage 0 ;;
        --)             shift; extra=("$@"); break ;;
        *)              die "unknown option $1 (detector flags go after --)" ;;
    esac
done

[[ $variant == userspace || $variant == kernel ]] || die "--variant must be userspace or kernel"
[[ -n $iface ]] || die "--iface is required"
[[ -n $out ]] || die "--out is required"
[[ -n $duration ]] || die "--duration is required (the excerpt's length plus a margin)"
[[ $xdp_mode == drv || $xdp_mode == generic ]] || die "--xdp-mode must be drv or generic"

# Blocking must never be on in evaluation runs, and the flags the script
# sets itself must not be overridden.
for a in "${extra[@]+"${extra[@]}"}"; do
    case "$a" in
        -block|--block|-block=*|--block=*|-block-ttl*|--block-ttl*|-allow*|--allow*)
            die "blocking is not allowed in evaluation runs ($a)" ;;
        -pcap*|--pcap*|-iface*|--iface*|-out*|--out*|-duration*|--duration*)
            die "$a is set by this script" ;;
    esac
done

commands=()

# run executes a command, or prints it with --dry-run, and records it.
run() {
    commands+=("$(printf '%q ' "$@")")
    if (( dry_run )); then
        echo "+ $*" >&2
    else
        "$@"
    fi
}

# ------------------------------------------------------------ checks

if (( ! dry_run )); then
    [[ $(id -u) -eq 0 ]] || die "must run as root (sudo)"
    ip link show dev "$iface" >/dev/null 2>&1 || die "no interface $iface"

    offload=$(ethtool -k "$iface") || die "ethtool -k $iface failed"
    for feature in generic-receive-offload large-receive-offload; do
        state=$(awk -v f="$feature:" '$1 == f { print $2 }' <<<"$offload")
        [[ $state == off ]] || die "$feature is ${state:-unknown} on $iface; turn it off: ethtool -K $iface gro off lro off"
    done

    attached=$(ip -j -d link show dev "$iface" | python3 -c 'import json,sys; print("xdp" in json.load(sys.stdin)[0])')
    [[ $attached == False ]] || die "an XDP program is already attached to $iface; detach it first (ip link set dev $iface xdp off)"
else
    offload="(dry run)"
fi

mkdir -p "$out"
for f in windows.csv ips.csv run.json memory.csv run-detector.json; do
    [[ ! -e $out/$f ]] || die "$out/$f exists; choose a new --out"
done

# ------------------------------------------------------------ cleanup

attached_mode=""
promisc_was_on=""

cleanup() {
    local rc=$?
    if [[ -n $attached_mode ]]; then
        log "detaching XDP from $iface"
        run ip link set dev "$iface" "$attached_mode" off || true
        remove_pins
    fi
    if [[ $promisc_was_on == no ]]; then
        run ip link set dev "$iface" promisc off || true
    fi
    if [[ -f $out/run-detector.json ]]; then
        finish_record "$rc" || true
    fi
    exit "$rc"
}
trap cleanup EXIT

remove_pins() {
    for p in "${KERNEL_PINS[@]}"; do
        run rm -f "$PIN_DIR/$p"
    done
}

# ------------------------------------------------------------ build

if [[ -z $detector_bin ]]; then
    detector_bin="$out/detector"
    # The kernel variant's code lives in kernelspace/.
    src_dir=$([[ $variant == kernel ]] && echo kernelspace || echo userspace)
    run go -C "$REPO" build -o "$(cd "$out" && pwd)/detector" "./$src_dir/cmd/detector"
fi

xdp_obj="" xdp_sha="" xdp_actual=""
if [[ $variant == kernel ]]; then
    xdp_obj="$out/heavy_keeper.o"
    run clang -O2 -g -target bpf -I"/usr/include/$(uname -m)-linux-gnu" \
        -c "$REPO/kernelspace/heavykeeper/heavy_keeper.c" -o "$xdp_obj"
    (( dry_run )) || xdp_sha=$(sha256sum "$xdp_obj" | cut -d' ' -f1)

    # Fresh maps every run: pinned maps from an earlier run would be reused.
    remove_pins

    attached_mode="xdp$xdp_mode"
    run ip link set dev "$iface" "$attached_mode" obj "$xdp_obj" sec xdp \
        || { attached_mode=""; die "attaching XDP in $xdp_mode mode failed; try --xdp-mode generic"; }

    if (( ! dry_run )); then
        # iproute2 reports the mode as 1 (driver), 2 (generic), 3 (offload).
        xdp_actual=$(ip -j -d link show dev "$iface" | python3 -c '
import json, sys
x = json.load(sys.stdin)[0].get("xdp", {})
print({1: "drv", 2: "generic", 3: "offload"}.get(x.get("mode"), "unknown"))')
        [[ $xdp_actual == "$xdp_mode" ]] || die "XDP attached in $xdp_actual mode, not $xdp_mode"
        log "heavy_keeper.o attached to $iface in $xdp_actual mode"
    fi
fi

if (( promisc )) && (( ! dry_run )); then
    if ip -j link show dev "$iface" | grep -q PROMISC; then
        promisc_was_on=yes
    else
        promisc_was_on=no
        run ip link set dev "$iface" promisc on
    fi
elif (( promisc )); then
    run ip link set dev "$iface" promisc on
fi

# ------------------------------------------------------------ record

detector_sha=""
(( dry_run )) || detector_sha=$(sha256sum "$detector_bin" | cut -d' ' -f1)

version() { "$@" 2>&1 | head -n1 || echo unavailable; }

record() {
    VARIANT=$variant IFACE=$iface OUT=$out DURATION=$duration XDP_MODE=$xdp_mode \
    XDP_ACTUAL=$xdp_actual XDP_SHA=$xdp_sha DETECTOR_BIN=$detector_bin DETECTOR_SHA=$detector_sha \
    PROMISC=$promisc OFFLOAD=$offload DRY_RUN=$dry_run \
    GIT_COMMIT=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown) \
    GIT_DIRTY=$(git -C "$REPO" status --porcelain --untracked-files=no 2>/dev/null | grep -q . && echo true || echo false) \
    KERNEL=$(uname -r) ARCH=$(uname -m) \
    OS=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s) \
    CLANG=$(version clang --version) GO=$(version go version) \
    EXTRA=$(printf '%s\n' "${extra[@]+"${extra[@]}"}") \
    COMMANDS=$(printf '%s\n' "${commands[@]}") \
    python3 - "$out/run-detector.json" <<'EOF'
import json, os, sys
from datetime import datetime, timezone
e = os.environ
lines = lambda k: [l for l in e.get(k, "").splitlines() if l]
json.dump({
    "variant": e["VARIANT"],
    "iface": e["IFACE"],
    "duration": e["DURATION"],
    "blocking": False,
    "xdp_mode_requested": e["XDP_MODE"] if e["VARIANT"] == "kernel" else None,
    "xdp_mode_actual": e["XDP_ACTUAL"] or None,
    "heavy_keeper_o_sha256": e["XDP_SHA"] or None,
    "detector_bin": e["DETECTOR_BIN"],
    "detector_sha256": e["DETECTOR_SHA"] or None,
    "promisc": e["PROMISC"] == "1",
    "offload": lines("OFFLOAD"),
    "git_commit": e["GIT_COMMIT"],
    "git_dirty": e["GIT_DIRTY"] == "true",
    "kernel": e["KERNEL"],
    "arch": e["ARCH"],
    "os": e["OS"],
    "clang": e["CLANG"],
    "go": e["GO"],
    "extra_detector_flags": lines("EXTRA"),
    "commands": lines("COMMANDS"),
    "started_at": datetime.now(timezone.utc).isoformat(),
    "dry_run": e["DRY_RUN"] == "1",
}, open(sys.argv[1], "w"), indent=2)
EOF
}

finish_record() {
    COMMANDS=$(printf '%s\n' "${commands[@]}") RC=$1 python3 - "$out/run-detector.json" <<'EOF'
import json, os, sys
from datetime import datetime, timezone
p = sys.argv[1]
d = json.load(open(p))
d["commands"] = [l for l in os.environ["COMMANDS"].splitlines() if l]
d["finished_at"] = datetime.now(timezone.utc).isoformat()
d["exit_code"] = int(os.environ["RC"])
json.dump(d, open(p, "w"), indent=2)
EOF
}

detector_cmd=("$detector_bin" -iface "$iface" -duration "$duration" -out "$out" "${extra[@]+"${extra[@]}"}")
memwatch=(python3 "$REPO/scripts/memwatch.py" --out "$out")
(( bpftool )) && memwatch+=(--bpftool)

commands+=("$(printf '%q ' "${memwatch[@]}" -- "${detector_cmd[@]}")")
record

# ------------------------------------------------------------ run

if (( wait )) && (( ! dry_run )); then
    read -r -p "run-detector: ready. Start tcpreplay on the sender now, then press Enter here: " _ </dev/tty
fi

log "running the $variant detector on $iface for $duration"
if (( dry_run )); then
    echo "+ ${memwatch[*]} -- ${detector_cmd[*]}" >&2
else
    "${memwatch[@]}" -- "${detector_cmd[@]}"
fi
