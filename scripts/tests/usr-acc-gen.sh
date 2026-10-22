#!/bin/bash

set -euo pipefail

if [[ $# -ne 1 || ! ${1:-} =~ ^[1-9][0-9]*$ ]]; then
    echo "Usage: bash $0 TEST_NUMBER (positive integer)" >&2
    exit 2
fi

out="results/usr-acc-gen-$1"
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

# 1. Compile (on both machines)
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c userspace/blocklist/blocklist.c -o userspace/blocklist/blocklist.o
# 2. Build the detector
go build -o detector-userspace ./userspace/cmd/detector
# 2. Attach
sudo ip link set dev enp7s0 xdpgeneric obj userspace/blocklist/blocklist.o sec xdp
attached=1
# 3. Double check the attach
ip link show

# # 4. Preprocess the dataset (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# python -m analysis.preprocess --dataset cicddos2019 --input /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/01-12/ --out /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --time-offset +4h
# # 5. Get the PCAP file for testing (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# python3 scripts/excerpt.py --input /mnt/attack_data/DAT300-data/CICDDoS2019/PCAP/01-12/PCAP-01-12_0-249/ --out /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.pcap --start 2018-12-01T14:21:52Z --duration 40m --rewrite-mac 1a:5e:73:5b:e3:9b,16:53:d2:bc:4c:91
# # 6. Get the baseline (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# ./detector-userspace -pcap /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.pcap -window 536.870912ms -out results/ref-pcap/
# 7. Run the online test test (on the victim)

sudo ./detector-userspace -iface enp7s0 -window 536.870912ms -duration 44m30s --out "$out"
# # 8. Evaluate live run
# python3 -m analysis.evaluate --labels /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --run "$out/" --excerpt /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.excerpt.json --reference results/ref-pcap/ --out "results/eval-usr-acc-gen-$1"
# XDP and its pinned maps are released by the EXIT trap above.
