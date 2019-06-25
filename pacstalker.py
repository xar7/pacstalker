from urllib.request import urlopen, Request
from re import sub
from os import path
from os import remove
from sys import argv
from numpy import log as ln
from scapy.all import *
from scapy_http.http import *
from optparse import OptionParser

import subprocess

def getpkglist():
    """
    Connect to the mirror and create the plain text file package_list.
    This file will be used to match a packet name by its size.
    Automatically called by loadpkglist when the file is not found in local.
    """

    # Delete the existing package list
    remove('package_list')

    #mirror_link = 'https://mirror.osbeck.com/archlinux'
    mirror_link = 'https://mirrors.niyawe.de/archlinux/'
    subs = ['/core/os/x86_64/', '/community/os/x86_64/', '/extra/os/x86_64/']

    for sub_mirror in subs:
        print(f"Dowloading package list from: {mirror_link}")

        # Must use a header or I could get a 403 from mirror!
        fake_headers = { 'User-Agent' : 'Pacstalker' }
        req_core = Request(mirror_link + sub_mirror, headers=fake_headers)

        content = urlopen(req_core).read().decode('utf-8')
        content = sub(r'<.*?>', '', content)
        lines = content.split('\r\n')

        with open('package_list', 'a') as pkg_list_file:
            for l in lines[4:-3]:
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

            if pkg_info[0][-4:] == '.sig' or pkg_info[0][:6] == 'local/':
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
    while end - begin > 6:
        if m > size + eps:
            end = (end+begin)//2
        if m < size - eps:
            begin = (end+begin)//2
        m = pkg_list[(end+begin)//2]['size']

        c += 1
        if c > 100:
            break

    matching_pkg = []
    for i in range(begin, end):
        pkg_list[i]['match'] = 100 - abs(pkg_list[i]['size'] - size) / size * 100
        matching_pkg.append(pkg_list[i])

    matching_pkg.sort(key=lambda p : p['match'], reverse=True)
    print("Your package matches:")
    for pkg in matching_pkg:
        print(f" M:{pkg['match']:.4}% S:{pkg['size']} LM:{pkg['date']} {pkg['name']}")

    return begin, end

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

def get_size(pcapfile):
    output = subprocess.run(["src/pacstalker", pcapfile], capture_output=True)
    size = int(output.stdout.decode().strip())
    print(f"package size: {size}")
    return size


parser = OptionParser(usage = "Usage: pacstalker.py [options] <record>")
parser.add_option("-c", "--clear", action="store_true", default=False,
                  help="to analyze clear traffic (no tls for testing purposes)")
parser.add_option("-u", "--update", action="store_true", default=False,
                  help="update package list from mirror")
parser.add_option("-s", "--size", action="store_true", default=False,
                  help="just print the estimated size (no pkg match)")
parser.add_option("-t", "--ta-mere", type=int)

(options, args) = parser.parse_args()

if options.ta_mere:
    pkg_list = loadpkglist()
    search_match(options.ta_mere, pkg_list, 10)
    sys.exit(0)

if not args:
    parser.error("No pcap record given.")
    sys.exit(1)

if options.update:
    getpkglist()

size = get_size(args[0])
pkg_list = loadpkglist()
search_match(size, pkg_list, 10)
