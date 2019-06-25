#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "tls.h"

#define HTTP_HEADER_SIZE 299

char *tls_data_base = 0;
size_t tls_data_size = TLS_BEGIN_SIZE;
size_t current_offset = 0;

void pktHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void) user;
    const struct ether_header *ethHeader = (const struct ether_header *) bytes;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(bytes + sizeof(struct ether_header));

        if (ipHeader->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcpHeader = (struct tcphdr *)(bytes + sizeof(struct ether_header)
                                          + sizeof(struct ip));

            /* We just want the TLS traffic! */
            if (ntohs(tcpHeader->source) != TLS_PORT)
                return;

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

size_t get_tls_size(bool keep_header) {
    (void) keep_header;
    size_t my_offset = 0;
    size_t total_size = 0;
    int c = 0;

    while (my_offset < current_offset)
    {
        struct tlshdr *tlsHeader = (struct tlshdr *) (tls_data_base + my_offset);

        DBG("TLSHeader: Type:%u Version:%u Length:%u\n", tlsHeader->type, ntohs(tlsHeader->legacy_version),
            ntohs(tlsHeader->length));

        if (tlsHeader->type == TLS_APPLICATION_DATA) {
            c++;
            total_size += ntohs(tlsHeader->length) - 23;
            DBG("TLSApplicationData found: Incrementing size\n");
        }

        DBG("TLS: Number of application data found: %d\n", c);
        my_offset += sizeof(struct tlshdr) + ntohs(tlsHeader->length);
    }

    return total_size - HTTP_HEADER_SIZE;
}


int main(int argc, char **argv)
{
    DBG("Pacstalker: running in debug mode!\n");

    pcap_t *mypcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    int opt = 0;
    int option_index = 0;
    bool keep_header = false;
    struct option options[] = {
        {"help", no_argument, 0, 'h'},
        {"keep_header", no_argument, 0, 'k'}
    };

    while ((opt = getopt_long(argc, argv, "hk", options, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            puts("Pacstalker is a pcap analysis tool that is capable of determinating the total size of the tls encrypted data contained in a pcap record.\n");
            puts("Usage: ./pacstalker [option] pcaprecord\n");
            puts("Options:\n\t--help -h: Display this help and exit\n\t--keep_header -k: Keep the size of the html header when calculating the tls total size.\n");
            return 0;
        case 'k':
            keep_header = true;
            break;
        default:
            fprintf(stderr, "invalid option bro!\n");
            break;
        }
    }

    tls_data_base = malloc(TLS_BEGIN_SIZE);
    if (!tls_data_base) {
        fprintf(stderr, "malloc() failed, you are in deep shit\n");
        return 1;
    }

    mypcap = pcap_open_offline(argv[argc - 1], errbuf);
    if (!mypcap) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_loop(mypcap, -1, pktHandler, NULL) != 0) {
        fprintf(stderr, "pcap_loop() failed: %s\n", pcap_geterr(mypcap));
        return 1;
    }

    printf("%zu\n", get_tls_size(keep_header));

    return 0;
}
