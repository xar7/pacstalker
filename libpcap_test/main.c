#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "debug.h"
#include "tls.h"

void pktHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    DBG("Entering pktHandler: len = %u\n", h->len);
    const struct ether_header *ethHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    u_int sourcePort, destPort;
    int dataLength = 0;

    ethHeader = (struct ether_header *) bytes;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *)(bytes + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

        if (ipHeader->ip_p == IPPROTO_TCP) {
            DBG("SourceIp: %s\nDestIp: %s\n", sourceIp, destIp);

            tcpHeader = (struct tcphdr *)(bytes + sizeof(struct ether_header)
                                          + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);

            DBG("DestPort: %u\n", destPort);
            DBG("SourcePort: %u\n", sourcePort);

            if (sourcePort == 443) {
                dataLength = h->len - (sizeof(struct ether_header)
                                       + sizeof(struct ip));

                DBG("Dataoffset: %d\n", tcpHeader->th_off * 4);
                DBG("Datasize: %d\n", dataLength - tcpHeader->th_off * 4);

                if (dataLength - tcpHeader->th_off * 4 != 0) {
                    struct tlshdr *tlsHeader = (struct tlshdr *) ((void *) tcpHeader
                                                                  + tcpHeader->th_off
                                                                  + sizeof(struct tcphdr));

                    DBG("TLS:  Type=%u LegacyVersion=%u Length=%u\n", tlsHeader->type,
                        tlsHeader->legacy_version,
                        tlsHeader->length);
                }
            }
        }
    }

    DBG("End of pktHandler.\n\n");
}


int main(void)
{
    DBG("Pacstalker: running in debug mode!\n");

    pcap_t *mypcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    mypcap = pcap_open_offline("../pcap/sl_tls.pcap", errbuf);
    if (!mypcap) {
        fprintf(stderr, "pcap_open_live() failed: %s", errbuf);
        return 1;
    }

    if (pcap_loop(mypcap, -1, pktHandler, NULL) != 0) {
        fprintf(stderr, "pcap_loop() failed: %s", pcap_geterr(mypcap));
        return 1;
    }

    return 0;
}
