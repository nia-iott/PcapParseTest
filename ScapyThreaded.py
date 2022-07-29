from scapy.all import *
import time
import concurrent.futures

start = time.perf_counter()

data = ['[PCAP_File_Name]', '[PCAP_File_Name]' ]
packets = rdpcap(data)


def print_DNS(packets):
    for packet in packets:
        if packet.haslayer(DNSRR):
            if isinstance(packet.an, DNSRR):
                print(packet.an.rrname)


with concurrent.futures.ThreadPoolExecutor() as executor:
    executor.map(print_DNS, data)

finish = time.perf_counter()
print (f'This took {round(finish-start, 2)} seconds')
