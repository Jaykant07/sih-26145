from scapy.all import IP, TCP, wrpcap
import time

packets = []
# Simulate an IP scanning port 80 across multiple hosts
src_ip = "192.168.1.100"
for i in range(1, 30):
    dst_ip = f"192.168.1.{i}"
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=80, flags="S")
    packets.append(pkt)

wrpcap("scan_test.pcap", packets)
print("scan_test.pcap generated")
