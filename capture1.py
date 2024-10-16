from scapy.all import *

packets = rdpcap('captured_traffic.pcap')

for packet in packets:
    print(packet.summary())
    # packet.show()