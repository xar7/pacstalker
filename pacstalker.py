from urllib.request import urlopen, Request
from re import sub
from os import path
from sys import argv
from numpy import log as ln
from scapy.all import *
from scapy_http.http import *

def getpkglist():
    """
    Connect to the mirror and create the plain text file package_list.
    This file will be used to match a packet name by its size.
    Automatically called by loadpkglist when the file is not found in local.
    """

    mirror_link = 'https://mirror.osbeck.com/archlinux'
    core_sub = '/core/os/x86_64/'

    # Must use a header or I could get a 403 from mirror!
    fake_headers = { 'User-Agent' : 'Pacstalker' }
    req_core = Request(mirror_link + core_sub, headers=fake_headers)

    content = urlopen(req_core).read().decode('utf-8')
    content = sub(r'<.*?>', '', content)
    lines = content.split('\r\n')

    # Get all line but the first and last one which useless.
    with open('package_list', 'w') as pkg_list_file:
        for l in lines[1:-1]:
            pkg_list_file.write(l + '\n')

    print('package_list successfully created!')


def loadpkglist():
    if not path.isfile('package_list'):
        print('Package list not found.\nDownloading it from mirror.')
        getpkglist()
    else:
        print('Package list found.')

    pkg_list = []
    with open('package_list', 'r') as pkg_list_file:
        for line in pkg_list_file:
            pkg_info = line.split()

            # Skip signatures.
            if pkg_info[0][-4:] == '.sig':
                continue

            pkg = {}
            pkg['name'] = pkg_info[0]
            pkg['date'] = pkg_info[1] + ' ' +  pkg_info[2]
            pkg['size'] = int(pkg_info[3])
            pkg_list.append(pkg)

    pkg_list.sort(key=lambda p : p['size'])
    return pkg_list

def search_match(size, pkg_list, eps):
    begin = 0
    end = len(pkg_list) - 1
    m = pkg_list[(end+begin)//2]['size']

    c = 0
    while end - begin > 4:
        if m > size + eps:
            end = (end+begin)//2
        if m < size - eps:
            begin = (end+begin)//2
        m = pkg_list[(end+begin)//2]['size']

        c += 1
        if c > 100:
            break

    return begin, end

def analyze_pcap(pcapfile):
    load_layer("tls")
    packets = rdpcap(pcapfile)
    lol_size, estimated_size = 0, 0

    sessions = packets.sessions()
    for s in sessions:
        for pkt in sessions[s]:
            if pkt.haslayer(TLSServerHello):
                transfer_s = s

    for pkt in sessions[transfer_s]:
        print(f"{pkt.summary()} {len(pkt)}")
        lol_size += len(pkt.payload)
        if (pkt.haslayer(TLSApplicationData)):
            if (pkt[TLS].payload):
                estimated_size += pkt[TLS].payload.len
        elif (pkt.haslayer(SSLv2)):
            pass
#            estimated_size += pkt[SSLv2].len
#            if (pkt[SSLv2].payload):
#                estimated_size += pkt[SSLv2].payload.len
#

    print(f"Estimated size : {estimated_size}")
    print(f"Lolsize : {lol_size}")

if (len(argv) == 1):
    print("No input file.")
    exit(1)
if (len(argv) > 2):
    print("Only the first input file will be considered.")

def analyze_pcap_clear(pcapfile):
    packets = rdpcap(pcapfile)
    estimated_size = 0

    transfer_s = ""
    sessions = packets.sessions()

    for s in sessions:
        for pkt in sessions[s]:
            if (pkt.haslayer(HTTPResponse)):
                transfer_s = s
                ptest = pkt

    for pkt in sessions[transfer_s]:
        if (pkt.haslayer(Raw)):
            estimated_size += len(pkt[Raw].load)

    print(f"Size transferred during this session: {estimated_size} bytes.")


# analyze_pcap_clear(argv[1])
analyze_pcap(argv[1])
