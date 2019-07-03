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
                if (!tls_data_base) {
                    fprintf(stderr, "realloc failed!\n");
                    exit(1);
                }
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
    size_t current_size = 0;

    unsigned c = 0;
    unsigned server_hello_c = 0;

    while (my_offset < current_offset)
    {
        struct tlshdr *tlsHeader = (struct tlshdr *) (tls_data_base + my_offset);

        DBG("TLSHeader: Type:%u Version:%u Length:%u\n", tlsHeader->type, ntohs(tlsHeader->legacy_version),
            ntohs(tlsHeader->length));

        if (tlsHeader->type == TLS_APPLICATION_DATA) {
            c++;
            current_size += ntohs(tlsHeader->length) - TLS_WAT_SIZE;
            total_size += ntohs(tlsHeader->length) - TLS_WAT_SIZE;
            DBG("TLSApplicationData found: Incrementing size\n");
        }
        else if (tlsHeader->type == TLS_HANDSHAKE) {
            uint8_t *handshake_type = (uint8_t *) (tlsHeader + 1);
            if (*handshake_type == TLS_SERVER_HELLO) {
                if (server_hello_c != 0) {
                    printf("%zu\n", current_size - HTTP_HEADER_SIZE);
                    current_size = 0;
                }
                server_hello_c++;
            }
            DBG("TLS Handshake type: %u\n", *handshake_type);
        }

        DBG("TLS: Number of application data found: %u\n", c);
        my_offset += sizeof(struct tlshdr) + ntohs(tlsHeader->length);
    }

    DBG("Number of server hello: %u\n", server_hello_c);
    printf("%zu\n", current_size - HTTP_HEADER_SIZE);

    return total_size - HTTP_HEADER_SIZE;
}


int main(int argc, char **argv)
{
    DBG("Pacstalker: running in debug mode!\n");

    pcap_t *mypcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    tls_data_base = malloc(TLS_BEGIN_SIZE);
    if (!tls_data_base) {
        fprintf(stderr, "malloc() failed\n");
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

    get_tls_size();

    return 0;
}
