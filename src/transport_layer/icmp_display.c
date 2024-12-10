#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "lib/common.h"
#include "icmp_display.h"


const unsigned char* display_icmp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    if(bytes + 4 > end_stream)
    {
        return NULL;
    }

    const struct icmphdr* icmp = (const struct icmphdr*)bytes;

    printf("ICMP");
    if(verbosity <= 1)
    {
        printf("    ");
    }
    else
    {
        if(verbosity > 2)
        {
            putchar(':');
        }
        putchar('\n');
    }

    if(verbosity > 2)
    {
        printf("\tType: %d\n", icmp->type);
        printf("\tCode: %d\n", icmp->code);
        printf("\tChecksum: 0x%04x\n", icmp->checksum);
    }

    return bytes + 4;
}