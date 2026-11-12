#!/bin/bash

set -euo pipefail

if [[ $# -ne 1 || ! ${1:-} =~ ^[1-9][0-9]*$ ]]; then
    echo "Usage: bash $0 TEST_NUMBER (positive integer)" >&2
    exit 2
fi

out="results/usr-per-gen-$1"
if [[ -e $out ]]; then
    echo "Result path $out already exists; choose an unused test number." >&2
    exit 2
fi

# Preserve failures for && chains, and release XDP even when a run fails.
attached=0
cleanup() {
    local status=$?
    trap - EXIT
    if (( attached )); then
        if sudo ip link set dev enp7s0 xdpgeneric off; then
            for dir in /sys/fs/bpf /sys/fs/bpf/tc/globals; do
                if ! sudo rm -f -- "$dir"/{blocklist_map,sketch_{0..3},topk_map_{0..3},slot_stats,blocked_stats,us_blocklist_map,us_blocked_stats}; then
                    if (( status == 0 )); then status=1; fi
                fi
            done
        elif (( status == 0 )); then
            status=1
        fi
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 1. Compile
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c userspace/blocklist/blocklist.c -o userspace/blocklist/blocklist.o
# Build the detector so this script also works as the first test.
go build -o detector-userspace ./userspace/cmd/detector
# 2. Attach
sudo ip link set dev enp7s0 xdpgeneric obj userspace/blocklist/blocklist.o sec xdp
attached=1
# 3. Double check the attach
ip link show
# 4. Run the test
sudo python3 scripts/memwatch.py --cpu --out "$out" -- ./detector-userspace -pin-dir /sys/fs/bpf/xdp/globals -iface enp7s0 -window 536.870912ms -duration 44m30s --out "$out" -block
# XDP and its pinned maps are released by the EXIT trap above.
