#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "debug.h"
#include "tls.h"

size_t encrypted_size = 0;

void pktHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    DBG("Entering pktHandler: len = %u\n", h->len);

    const struct ether_header *ethHeader;
    const struct ip *ipHeader;
    const struct tcphdr *tcpHeader;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    u_int sourcePort, destPort;
    int dataLength = 0;

    /* The current offset to the find the next tls header */
    static size_t remaining_size = 0;

    ethHeader = (struct ether_header *) bytes;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip *)(bytes + sizeof(struct ether_header));
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct tcphdr *)(bytes + sizeof(struct ether_header)
                                          + sizeof(struct ip));
            sourcePort = ntohs(tcpHeader->source);
            destPort = ntohs(tcpHeader->dest);

            dataLength = h->len - (sizeof(struct ether_header)
                                   + sizeof(struct ip));

            DBG("Dataoffset: %d\n", tcpHeader->th_off * 4);
            DBG("Datasize: %d\n", dataLength - tcpHeader->th_off * 4);

            size_t tls_size = dataLength - tcpHeader->th_off * 4;
            DBG("tls_size: %lu\n", tls_size);

            if (remaining_size != 0)
                DBG("REMAINING_SIZE = %u\n", remaining_size);

            /**
             * We are on a TCP packet, we now have to check the tls
             * header to get the size of the encrypted data.
             * It is possible that the header is not at the start but
             * in the middle of the packet, the start being the rest
             * of a previous tls packet.
             **/

            struct tlshdr *tlsHeader;
            tlsHeader = (struct tlshdr *) ((char *) tcpHeader
                                           + tcpHeader->th_off * 4);

            while (tls_size > 0) {
                if (remaining_size == 0)
                    tlsHeader = (struct tlshdr *) ((char *) tcpHeader
                                                   + tcpHeader->th_off * 4);
                else if (remaining_size > tls_size)
                    remaining_size -= tls_size;
                else if (remaining_size < tls_size)
                {
                    tlsHeader = (struct tlshdr *) ((char *) tcpHeader
                                                   + tcpHeader->th_off * 4
                                                   + remaining_size);
                    remaining_size = 0;
                }
                DBG("TLS: Type:%u Version: %u Length:%u\n", tlsHeader->type,
                    ntohs(tlsHeader->legacy_version), ntohs(tlsHeader->length));

                if (tlsHeader->type != TLS_APPLICATION_DATA)
                    break; /* We don't care if not APP DATA */

                tls_size -= ntohs(tlsHeader->length);
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
