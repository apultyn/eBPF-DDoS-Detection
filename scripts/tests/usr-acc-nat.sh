#!/bin/bash

# 1. Compile (on both machines)
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c userspace/blocklist/blocklist.c -o userspace/blocklist/blocklist.o
# 2. Build the detector
go build -o detector-userspace ./userspace/cmd/detector
# 2. Attach
sudo ip link set dev enp7s0 xdpnative obj userspace/blocklist/blocklist.o sec xdp
# 3. Double check the attach
ip link show

# # 4. Preprocess the dataset (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# python -m analysis.preprocess --dataset cicddos2019 --input /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/01-12/ --out /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --time-offset +4h
# # 5. Get the PCAP file for testing (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# python3 scripts/excerpt.py --input /mnt/attack_data/DAT300-data/CICDDoS2019/PCAP/01-12/PCAP-01-12_0-249/ --out /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.pcap --start 2018-12-01T14:21:52Z --duration 40m --rewrite-mac 1a:5e:73:5b:e3:9b,16:53:d2:bc:4c:91
# # 6. Get the baseline (ONLY ONCE, ON THE ATTACKER, BEFORE ALL TESTS)
# ./detector-userspace -pcap /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.pcap -window 536.870912ms -out results/ref-pcap/
# 7. Run the online test test (on the victim)

./detector-userspace -iface enp7s0 -window 536.870912ms -duration 44m30s --out results/usr-acc-gen-1
# # 8. Evaluate live run
# python3 -m analysis.evaluate --labels /mnt/attack_data/DAT300-data/CICDDoS2019/CSV/labels.csv --run results/usr-acc-gen-1/ --excerpt /mnt/attack_data/DAT300-data/CICDDoS2019/excerpts/01-12.excerpt.json --reference results/ref-pcap/ --out results/eval-usr-acc-gen-1
# 9. Detach
sudo ip link set dev enp7s0 xdpnative off
# 10. Delete all the pinned bpf maps
for dir in /sys/fs/bpf /sys/fs/bpf/tc/globals; do
    sudo rm -f -- "$dir"/{blocklist_map,sketch_{0..3},topk_map_{0..3},slot_stats,blocked_stats,us_blocklist_map,us_blocked_stats}
done