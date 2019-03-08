from scapy.all import *

load_layer("tls")
packets = rdpcap("test_pacman.pcap")

counter = 0
session_counter = 0
for pkt in packets:
    if TCP in pkt:
        if TLS in pkt:
            if pkt[TLS].type == 20: # 20 means ChangeCipherSpec
                session_counter += 1
                print(f"{pkt[TLS].type}")
                for tls_msg in pkt[TLS].msg:
                    print(type(tls_msg))
        counter += 1
print(f"{session_counter} sessions were catched!")
