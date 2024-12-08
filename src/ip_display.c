#include <bits/endian.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ip_display.h"

static const unsigned char* display_ipv4(const unsigned char* bytes, const unsigned char* end_stream, uint8_t* protocol, int verbosity)
{
    if(bytes + sizeof(struct iphdr) > end_stream)
    {
        return NULL;
    }

    const struct iphdr* ip = (const struct iphdr*)bytes;

    if(bytes + 4 * ip->ihl > end_stream)
    {
        return NULL;
    }

    char buffer[INET_ADDRSTRLEN];
    uint16_t frag_off = ntohs(ip->frag_off);
    uint8_t flags = (uint8_t)(frag_off >> 13);

    *protocol = ip->protocol;

    if(verbosity <= 2)
    {
        printf("IP: %s -> ", inet_ntop(AF_INET, &(ip->saddr), buffer, INET_ADDRSTRLEN));
        printf("%s", inet_ntop(AF_INET, &(ip->daddr), buffer, INET_ADDRSTRLEN));
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
        printf("IP:\n");
        printf("\tVersion: %d\n", ip->version);
        printf("\tHeader Length: %d (%d bytes)\n", ip->ihl, 4 * ip->ihl);
        printf("\tType of Service: 0x%02x\n", ip->tos);
        printf("\tTotal Length: %d\n", ntohs(ip->tot_len));
        printf("\tIdentification: 0x%04x\n", ntohs(ip->id));
        printf("\tFlags 0x%x (R=%d DF=%d MF=%d)\n", flags, (flags >> 2) & 0x1, (flags >> 1) & 0x1, flags & 0x1);
        printf("\tFragment Offset (without flags): %d\n", frag_off & ~(0x7 << 13));
        printf("\tTime To Live: %d\n", ip->ttl);
        printf("\tProtocol: 0x%02x\n", ip->protocol);
        printf("\tHeader Checksum: 0x%04x\n", ntohs(ip->check));
        printf("\tSource address: %s\n", inet_ntop(AF_INET, &(ip->saddr), buffer, INET_ADDRSTRLEN));
        printf("\tDestination address: %s\n", inet_ntop(AF_INET, &(ip->daddr), buffer, INET_ADDRSTRLEN));
        if(ip->ihl > 5)
        {
            printf("\tOptions: ");
            for(int i = 0; i < 4 * (ip->ihl-5); i++)
            {
                printf("%02x", (bytes + sizeof(struct iphdr))[i]);
                if(i & 0x1)
                {
                    putchar(' ');
                }
            }
            putchar('\n');
        }
    }
    return bytes + 4 * ip->ihl;
}

static const unsigned char* display_ipv6(const unsigned char* bytes, const unsigned char* end_stream, uint8_t* protocol, int verbosity)
{
    if(bytes + sizeof(struct ip6_hdr) > end_stream)
    {
        return NULL;
    }

    char buffer[INET6_ADDRSTRLEN];
    const struct ip6_hdr* ip = (const struct ip6_hdr*)bytes;
    uint32_t version_tc_fl = ntohl(ip->ip6_ctlun.ip6_un1.ip6_un1_flow);

    *protocol =  ip->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if(verbosity <= 2)
    {
        printf("IP: %s -> ", inet_ntop(AF_INET6, &(ip->ip6_src), buffer, INET6_ADDRSTRLEN));
        printf("%s", inet_ntop(AF_INET6, &(ip->ip6_dst), buffer, INET6_ADDRSTRLEN));
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
        printf("IP:\n");
        printf("\tVersion: %u\n", version_tc_fl >> 28);
        printf("\tTraffic class: 0x%02x\n", (version_tc_fl >> 20) & 0xFF);
        printf("\tFlow Label: 0x%05x\n", version_tc_fl & 0xFFFFF);
        printf("\tPayload Length: %u\n", ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen));
        printf("\tNext Header: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_nxt);
        printf("\tHop Limit: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_hlim);
        printf("\tSource address: %s\n", inet_ntop(AF_INET6, &(ip->ip6_src), buffer, INET6_ADDRSTRLEN));
        printf("\tDestination address: %s\n", inet_ntop(AF_INET6, &(ip->ip6_dst), buffer, INET6_ADDRSTRLEN));
    }
    return bytes + sizeof(struct ip6_hdr);
}

const unsigned char* display_ip(const unsigned char* bytes, const unsigned char* end_stream, uint8_t* protocol, int verbosity)
{
    if(bytes + 1 > end_stream)
    {
        return NULL;
    }
    const struct iphdr* ip = (const struct iphdr*)bytes;
    if(ip->version == 4)
    {
        return display_ipv4(bytes, end_stream, protocol, verbosity);
    }
    return display_ipv6(bytes, end_stream, protocol, verbosity);
}