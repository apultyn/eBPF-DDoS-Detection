#!/bin/bash

set -euo pipefail

if [[ $# -ne 1 || ! ${1:-} =~ ^[1-9][0-9]*$ ]]; then
    echo "Usage: bash $0 TEST_NUMBER (positive integer)" >&2
    exit 2
fi

out="results/ker-acc-nat-$1"
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
        if sudo ip link set dev enp7s0 xdpdrv off; then
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

clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c kernelspace/heavykeeper/heavy_keeper.c -o kernelspace/heavykeeper/heavy_keeper.o
# 2. Build the detector
go build -o detector-xdp ./kernelspace/cmd/detector
# 2. Attach
sudo ip link set dev enp7s0 xdpdrv obj kernelspace/heavykeeper/heavy_keeper.o sec xdp
attached=1
# 3. Double check the attach
ip link show
# 4. Run the test
sudo ./detector-xdp -pin-dir /sys/fs/bpf/xdp/globals -iface enp7s0 -duration 44m30s -out "$out"
# # 5. Evaluate live run (you don't have to get new reference)
# python3 -m analysis.evaluate --labels /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --run "$out/" --excerpt /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.excerpt.json --reference results/ref-pcap/ --out "results/eval-ker-acc-nat-$1"
# XDP and its pinned maps are released by the EXIT trap above.
