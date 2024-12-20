#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "lib/common.h"
#include "icmp_display.h"
#include "src/network_layer/ip_display.h"


enum ICMP_TYPES {
    ECHO_REPLY = 0,
    DESTINATION_UNREACHABLE = 3,
    REDIRECT = 5,
    ECHO_REQUEST = 8,
    TIME_EXCEEDED = 11,
    ADDRESS_MASK_REQUEST = 17,
    ADDRESS_MASK_REPLY = 18,
};

struct addr_mask_hdr {
    uint16_t identifier;
    uint16_t seq_num;
    uint32_t addr_mask;
};


struct dst_unreachable_hdr {
    uint8_t unused;
    uint8_t length;
    uint16_t next_hop_mtu;
};

static void display_icmp_type(uint8_t type)
{
    switch(type)
    {
        case ECHO_REPLY:
            printf(" (Echo reply)");
            break;
        case DESTINATION_UNREACHABLE:
            printf(" (Destination Unreachable)");
            break;
        case REDIRECT:
            printf(" (Redirect)");
            break;
        case ECHO_REQUEST:
            printf(" (Echo Request)");
            break;
        case TIME_EXCEEDED:
            printf(" (Time Exceeded)");
            break;
        case ADDRESS_MASK_REQUEST:
            printf(" (Address Mask Request)");
            break;
        case ADDRESS_MASK_REPLY:
            printf(" (Address Mask Reply)");
            break;
    }
}

static void display_icmp_code(uint8_t type, uint8_t code)
{
    switch(type)
    {
        case ECHO_REPLY:
            break;
        case DESTINATION_UNREACHABLE:
            switch(code)
            {
                case 0:
                    printf(" (Network unreachable error)");
                    break;
                case 1:
                    printf(" (Host unreachable error)");
                    break;
                case 2:
                    printf(" (Protocol unreachable error)");
                    break;
                case 3:
                    printf(" (Port unreachable error)");
                    break;
                case 4:
                    printf(" (The datagram is too big - need fragmentation but DF flag is on)");
                    break;
                case 5:
                    printf(" (Source route failed error)");
                    break;
                case 6:
                    printf(" (Destination network unknown error)");
                    break;
                case 7:
                    printf(" (Destination host unknown error)");
                    break;
                case 8:
                    printf(" (Source host isolated error)");
                    break;
                case 9:
                    printf(" (The destination network is administratively prohibited)");
                    break;
                case 10:
                    printf(" (The destination host is administratively prohibited)");
                    break;
                case 11:
                    printf(" (The network is unreachable for Type Of Service)");
                    break;
                case 12:
                    printf(" (The host is unreachable for Type Of Service)");
                    break;
                case 13:
                    printf(" (Communication administratively prohibited)");
                    break;
                case 14:
                    printf(" (Host precedence violation)");
                    break;
                case 15:
                    printf(" (Precedence cutoff in effect)");
                    break;
            }
            break;
        case REDIRECT:
            switch(code)
            {
                case 0:
                    printf(" (Redirect for Network)");
                    break;
                case 1:
                    printf(" (Redirect for Host)");
                    break;
                case 2:
                    printf(" (Redirect for Type of Service and Network)");
                    break;
                case 3:
                    printf(" (Redirect for Type of Service and Host)");
                    break;
            }
            break;
        case ECHO_REQUEST:
            break;
        case TIME_EXCEEDED:
            switch(code)
            {
                case 0:
                    printf(" (Time-to-live exceeded in transit)");
                    break;
                case 1:
                    printf(" (Fragment reassembly time exceeded)");
                    break;
            }
            break;
        case ADDRESS_MASK_REQUEST:
            break;
        case ADDRESS_MASK_REPLY:
            break;
    }
}

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
        if(verbosity == 2)
        {
            display_icmp_type(icmp->type);
        }
        else
        {
            putchar(':');
        }
        putchar('\n');
    }

    if(verbosity > 2)
    {
        printf("\tType: %d", icmp->type);
        display_icmp_type(icmp->type);
        printf("\n\tCode: %d", icmp->code);
        display_icmp_code(icmp->type, icmp->code);
        printf("\n\tChecksum: 0x%04x\n", icmp->checksum);
    }

    bytes += 4;

    switch(icmp->type)
    {
        char buffer[INET_ADDRSTRLEN];
        case DESTINATION_UNREACHABLE:
            if(bytes + sizeof(struct dst_unreachable_hdr) > end_stream)
            {
                return NULL;
            }
            if(verbosity > 2)
            {
                const struct dst_unreachable_hdr* dst_unreachable = (const struct dst_unreachable_hdr*)bytes;
                uint8_t garbage;
                printf("\tLength: %d\n", dst_unreachable->length);
                printf("\tNext Hop MTU: %d\n", ntohs(dst_unreachable->next_hop_mtu));
                printf("\tCopy of IP Header:\n");
                bytes = display_ip(bytes+4, &end_stream, &garbage, verbosity, 1, 1);
                if(bytes == NULL)
                {
                    return NULL;
                }
            }
            break;
        case TIME_EXCEEDED:
            if(bytes + 4 > end_stream)
            {
                return NULL;
            }
            if(verbosity > 2)
            {
                uint8_t garbage;
                printf("\tIP Address: %s\n", inet_ntop(AF_INET, bytes, buffer, INET_ADDRSTRLEN));
                printf("\tCopy of IP Header:\n");
                bytes = display_ip(bytes+4, &end_stream, &garbage, verbosity, 1, 1);
                if(bytes == NULL)
                {
                    return NULL;
                }
            }
            break;
        case REDIRECT:
            if(bytes + 4 > end_stream)
            {
                return NULL;
            }
            if(verbosity > 2)
            {
                uint8_t garbage;
                printf("\tCopy of IP Header:\n");
                bytes = display_ip(bytes+4, &end_stream, &garbage, verbosity, 1, 1);
                if(bytes == NULL)
                {
                    return NULL;
                }
            }
            break;
        case ADDRESS_MASK_REQUEST:
        case ADDRESS_MASK_REPLY:
            if(bytes + sizeof(struct addr_mask_hdr) > end_stream)
            {
                return NULL;
            }
            if(verbosity > 2)
            {
                const struct addr_mask_hdr* addr_mask = (const struct addr_mask_hdr*)bytes;
                printf("\tIdentifier: 0x%04x\n", ntohs(addr_mask->identifier));
                printf("\tSequence Number: 0x%04x\n", ntohs(addr_mask->seq_num));
                printf("\tAddress Mask: %s\n", inet_ntop(AF_INET, &(addr_mask->addr_mask), buffer, INET_ADDRSTRLEN));
            }
            bytes += sizeof(struct addr_mask_hdr);
    }

    return bytes;
}
