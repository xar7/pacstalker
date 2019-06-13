#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "tls.h"

char *tls_data_base = 0;
size_t tls_data_size = TLS_BEGIN_SIZE;
size_t current_offset = 0;

void pktHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    const struct ether_header *ethHeader = (const struct ether_header *) bytes;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(bytes + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = (struct tcphdr *)(bytes + sizeof(struct ether_header)
                                          + sizeof(struct ip));

            size_t useless_size = (size_t) tcpHeader + tcpHeader->th_off * 4
                - (size_t) bytes;
            size_t size_to_copy = h->len - useless_size;

            if (current_offset + size_to_copy >= tls_data_size)
            {
                tls_data_size = current_offset + 2 * size_to_copy;
                tls_data_base = realloc(tls_data_base, tls_data_size);
            }

            memcpy(tls_data_base + current_offset, bytes + useless_size,
                   size_to_copy);

            current_offset += size_to_copy;
        }
    }
}

size_t get_tls_size() {
    size_t my_offset = 0;
    size_t total_size = 0;

    while (my_offset != current_offset)
    {
        struct tlshdr *tlsHeader = (struct tlshdr *) (tls_data_base + my_offset);

        DBG("TLSHeader: TYPE:%u VERSION:%u LENGTH:%u\n", tlsHeader->type, ntohs(tlsHeader->legacy_version),
            ntohs(tlsHeader->length));

        if (tlsHeader->type == TLS_APPLICATION_DATA) {
            total_size += ntohs(tlsHeader->length);
            DBG("ADDING\n");
        }

        my_offset += sizeof(struct tlshdr) + ntohs(tlsHeader->length);
    }

    return total_size;
}


int main(void)
{
    DBG("Pacstalker: running in debug mode!\n");

    pcap_t *mypcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    tls_data_base = malloc(TLS_BEGIN_SIZE);
    if (!tls_data_base) {
        fprintf(stderr, "malloc() failed, you are in deep shit");
        return 1;
    }

    mypcap = pcap_open_offline("../pcap/binutils.pcap", errbuf);
    if (!mypcap) {
        fprintf(stderr, "pcap_open_live() failed: %s", errbuf);
        return 1;
    }

    if (pcap_loop(mypcap, -1, pktHandler, NULL) != 0) {
        fprintf(stderr, "pcap_loop() failed: %s", pcap_geterr(mypcap));
        return 1;
    }

    printf("Total tls size: %zu\n", get_tls_size());

    return 0;
}
