from scapy.all import *

load_layer("tls")
packets = rdpcap("test_pacman.pcap")

counter = 0
session_counter = 0
for pkt in packets:
    if TCP in pkt:
        if TLS in pkt:
            #pkt.show()
            print(f"packet len = {pkt.len} && tls layer len = {pkt[TLS].len}")
            print(pkt[TLS].type)
            if pkt[TLS].type == 20: # 20 means ChangeCipherSpec
                session_counter += 1
                for tls_msg in pkt[TLS].msg:
                    print(type(tls_msg))
        counter += 1
print(f"{session_counter} tls sessions were catched!")
