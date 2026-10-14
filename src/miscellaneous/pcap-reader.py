from urllib.request import urlopen
from scapy.all import PcapReader, IP, IPv6, TCP, UDP
from datetime import datetime

url = "http://127.0.0.1:18000/PCAP-03-11/SAT-03-11-2018_0"

packet_count = 0
tcp_count = 0
udp_count = 0

with urlopen(url, timeout=60) as response:
    with PcapReader(response) as reader:
        start = datetime.now()
        for i, packet in enumerate(reader):
            packet_count += 1
            tcp_count += int(TCP in packet)
            udp_count += int(UDP in packet)

            network = (
                packet[IP] if IP in packet
                else packet[IPv6] if IPv6 in packet
                else None
            )

            if network is not None:
                src_ip = network.src
                dst_ip = network.dst
                timestamp = float(packet.time)

                if packet_count <= 5:
                    print(timestamp, src_ip, dst_ip, packet.summary())

            if packet_count % 100_000 == 0:
                print(f"Processed {packet_count:,} packets", flush=True)

print(f"Total: {packet_count:,}; TCP: {tcp_count:,}; UDP: {udp_count:,}")
print(f"Time: {datetime.now() - start}")
