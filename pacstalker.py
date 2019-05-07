from urllib.request import urlopen, Request
from re import sub
from os import path
from sys import argv
from numpy import log as ln
from scapy.all import *
from scapy_http.http import *
from optparse import OptionParser

def getpkglist():
    """
    Connect to the mirror and create the plain text file package_list.
    This file will be used to match a packet name by its size.
    Automatically called by loadpkglist when the file is not found in local.
    """

    mirror_link = 'https://mirror.osbeck.com/archlinux'
    core_sub = '/core/os/x86_64/'

    print(f"Dowloading package list from: {mirror_link}")

    # Must use a header or I could get a 403 from mirror!
    fake_headers = { 'User-Agent' : 'Pacstalker' }
    req_core = Request(mirror_link + core_sub, headers=fake_headers)

    content = urlopen(req_core).read().decode('utf-8')
    content = sub(r'<.*?>', '', content)
    lines = content.split('\r\n')

    with open('package_list', 'w') as pkg_list_file:
        for l in lines[1:-1]:
            pkg_list_file.write(l + '\n')

    print('package_list successfully created!')


def loadpkglist():
    if not path.isfile('package_list'):
        print('Package list not found.\n')
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
    while end - begin > 1:
        if m > size + eps:
            end = (end+begin)//2
        if m < size - eps:
            begin = (end+begin)//2
        m = pkg_list[(end+begin)//2]['size']

        c += 1
        if c > 100:
            break

    print("Your package matches:")
    for i in range(begin, end):
        print(f"{pkg_list[i]['name']} S:{pkg_list[i]['size']} LM:{pkg_list[i]['date']}")

    return begin, end

def get_tls_transfer(sessions):
    for s in sessions:
        for pkt in sessions[s]:
            if pkt.haslayer(TLSServerHello):
                return s;

def analyze_pcap(pcapfile):
    load_layer("tls")
    packets = rdpcap(pcapfile)

    estimated_size = 0
    ip_tcp_header_size = 52 + 32
    tls_header_size = 5
    http_header_size = 0
    sessions = packets.sessions()

    transfer_s = get_tls_transfer(sessions)
    c = 0

    for pkt in sessions[transfer_s]:
        if (pkt.haslayer(TLSApplicationData) or pkt.haslayer(SSLv2)):
            estimated_size += len(pkt[TCP].payload) - tls_header_size
            c += 1
        # elif (pkt.haslayer(SSLv2)):
        #     estimated_size += len(pkt[TCP].payload) - tls_header_size

    estimated_size -= http_header_size

    print(f"Number of ApplicationData packets: {c}\nEstimated size : {estimated_size}")

    return estimated_size


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
            estimated_size += len(pkt.load)

    print(f"Size transferred during this session: {estimated_size} bytes.")

    return estimated_size



parser = OptionParser(usage = "Usage: pacstalker.py [options] <record>")
parser.add_option("-c", "--clear", action="store_true", default=False, help="to analyze clear traffic (no tls for testing purposes)")
parser.add_option("-u", "--update", action="store_true", default=False, help="update package list from mirror")
parser.add_option("-s", "--size", action="store_true", default=False, help="just print the estimated size of the record and does not try to match package")

(options, args) = parser.parse_args()

if not args:
    parser.error("Pcap record not given.")

if options.update:
    getpkglist()

size = 0
if options.clear:
    size = analyze_pcap_clear(args[0])
else:
    size = analyze_pcap(args[0])

if not options.size:
    pkg_list = loadpkglist()
    search_match(size, pkg_list, 10)
