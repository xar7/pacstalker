from sys import argv
from scapy.all import *

if (len(argv) == 1):
    print("Non interactiv mode of pacstalker is to be used with an input file.")
    exit(1)

if (len(argv) > 2):
    print("Pacstalker can only deal with one input file at a time.")
    exit(1)

load_layer("tls")
packets = rdpcap(argv[1])
pkg_session = []
total_size = 0

session_counter = 0

for pkt in packets:
    total_size += pkt.len
    if TLS in pkt:
        if pkt[TLS].type == 20: # 20 means ChangeCipherSpec
            pkg_session.append(0)
        elif pkt[TLS].type == 23: # ApplicationData
            pkg_session[-1] += pkt.len
print(f"{len(pkg_session)} tls sessions were catched!")

for i in range(len(pkg_session)):
    print(f"Session number {i} transmits {pkg_session[i]} bytes of data.")

print(f"{total_size} bytes were transferred during the record.")
