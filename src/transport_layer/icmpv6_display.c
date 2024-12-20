#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "lib/common.h"
#include "icmp_display.h"
#include "src/network_layer/ip_display.h"

enum ICMPv6_TYPES {
    DESTINATION_UNREACHABLE = 1,
};

static void display_icmp6_type(uint8_t type)
{
    switch(type)
    {
        case DESTINATION_UNREACHABLE:
            printf(" (Destination Unreachable)");
            break;
    }
}

static void display_icmp6_code(uint8_t type, uint8_t code)
{
    switch(type)
    {
        case DESTINATION_UNREACHABLE:
            switch(code)
            {
                case 0:
                    printf(" (No route to destination )");
                    break;
                case 1:
                    printf(" (Communication with destination administratively prohibited)");
                    break;
                case 2:
                    printf(" (Beyond scope of source address)");
                    break;
                case 3:
                    printf(" (Address unreachable)");
                    break;
                case 4:
                    printf(" (Port unreachable)");
                    break;
                case 5:
                    printf(" (Source address failed ingress/egress policy)");
                    break;
                case 6:
                    printf(" (Reject route to destination)");
                    break;
                case 7:
                    printf(" (Error in Source Routing Header)");
                    break;
            }
            break;
    }
}

const unsigned char* display_icmp6(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    char buffer[INET6_ADDRSTRLEN];

    if(bytes + 4 > end_stream)
    {
        return NULL;
    }

    const struct icmphdr* icmp = (const struct icmphdr*)bytes;

    printf("ICMPv6");
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
        printf("\tType: %d", icmp->type);
        display_icmp6_type(icmp->type);
        printf("\n\tCode: %d", icmp->code);
        display_icmp6_code(icmp->type, icmp->code);
        printf("\n\tChecksum: 0x%04x\n", icmp->checksum);
    }

    bytes += 4;

    switch(icmp->type)
    {
        case DESTINATION_UNREACHABLE:
            if(bytes + 4 > end_stream)
            {
                return NULL;
            }
            if(verbosity > 2)
            {
                uint8_t garbage;
                printf("\tIP Address: %s\n", inet_ntop(AF_INET6, bytes, buffer, INET6_ADDRSTRLEN));
                printf("\tCopy of IP Header:\n");
                bytes = display_ip(bytes+4, &end_stream, &garbage, verbosity, 1, 1);
                if(bytes == NULL)
                {
                    return NULL;
                }
            }
            break;
    }
    return bytes;
}