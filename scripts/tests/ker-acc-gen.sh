#!/bin/bash

clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c kernelspace/heavykeeper/heavy_keeper.c -o kernelspace/heavykeeper/heavy_keeper.o
# 2. Build the detector
go build -o detector-xdp ./kernelspace/cmd/detector
# 2. Attach
sudo ip link set dev enp7s0 xdpgeneric obj kernelspace/heavykeeper/heavy_keeper.o sec xdp
# 3. Double check the attach
ip link show
# 4. Run the test
./detector-xdp -pin-dir /sys/fs/bpf/xdp/globals -iface enp7s0 -duration 44m30s -out results/ker-acc-gen-1
# # 5. Evaluate live run (you don't have to get new reference)
# python3 -m analysis.evaluate --labels /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --run results/ker-acc-gen-1/ --excerpt /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.excerpt.json --reference results/ref-pcap/ --out results/eval-ker-acc-gen-1
# 6. Detach
sudo ip link set dev enp7s0 xdpgeneric off
# 7. Delete all the pinned bpf maps
for dir in /sys/fs/bpf /sys/fs/bpf/tc/globals; do
    sudo rm -f -- "$dir"/{blocklist_map,sketch_{0..3},topk_map_{0..3},slot_stats,blocked_stats,us_blocklist_map,us_blocked_stats}
done