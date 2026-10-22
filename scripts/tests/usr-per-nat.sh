#!/bin/bash

# 1. Compile
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c userspace/blocklist/blocklist.c -o userspace/blocklist/blocklist.o
# 2. Attach
sudo ip link set dev enp7s0 xdpnative obj userspace/blocklist/blocklist.o sec xdp
# 3. Double check the attach
ip link show
# 4. Run the test
sudo python3 scripts/memwatch.py --cpu --out results/usr-per-gen-1 -- ./detector-userspace -pin-dir /sys/fs/bpf/xdp/globals -iface enp7s0 -window 536.870912ms -duration 44m30s --out results/usr-per-gen-1 -block
# 5. Detach
sudo ip link set dev enp7s0 xdpnative off
# 6. Delete all the pinned bpf maps
for dir in /sys/fs/bpf /sys/fs/bpf/tc/globals; do
    sudo rm -f -- "$dir"/{blocklist_map,sketch_{0..3},topk_map_{0..3},slot_stats,blocked_stats,us_blocklist_map,us_blocked_stats}
done