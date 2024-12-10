#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "lib/common.h"
#include "udp_display.h"


const unsigned char* display_udp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity)
{
    if(bytes + sizeof(struct udphdr) > end_stream)
    {
        return NULL;
    }

    const struct udphdr* udp = (const struct udphdr*)bytes;
    *dest_port = ntohs(udp->uh_dport);
    *src_port = ntohs(udp->uh_sport);
    if(verbosity <= 2)
    {
        printf("UDP: src_port=%d dst_port=%d", *src_port, *dest_port);
        if(verbosity <= 1)
        {
            printf("    ");
        }
        else
        {
            putchar('\n');
        }
    }
    else
    {
        printf("UDP:\n");
        printf("\tSource port: %u\n", *src_port);
        printf("\tDestination port: %u\n", *dest_port);
        printf("\tLength: %u\n", ntohs(udp->uh_ulen));
        printf("\tChecksum: 0x%04x\n", ntohs(udp->uh_sum));
    }
    return bytes + sizeof(struct udphdr);
}
