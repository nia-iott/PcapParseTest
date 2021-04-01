from scapy.all import *
import time

start = time.perf_counter()

packet1 = rdpcap('wrccdc.2018-03-23.010014000000000.pcap')
packet2 = rdpcap('wrccdc.2018-03-23.010103000000000.pcap')

def print_DNS():
    for packet in packet1:
        if packet.haslayer(DNSRR):
            if isinstance(packet.an, DNSRR):
                print(packet.an.rrname)
    print("_________________________________________________________________________")
    for packet in packet2:
        if packet.haslayer(DNSRR):
            if isinstance(packet.an, DNSRR):
                print(packet.an.rrname)

print_DNS()

finish = time.perf_counter()
print (f'This took {round(finish-start, 2)} seconds')