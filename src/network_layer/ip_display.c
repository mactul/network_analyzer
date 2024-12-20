#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/common.h"
#include "ip_display.h"

enum IPV6_NEXT_HEADERS {
    HOP_BY_HOP = 0,
    ROUTING = 43,
    FRAGMENT = 44,
    ENCAPSULATING_SECURITY_PROTOCOL = 50,
    AUTHENTIFICATION_HEADER = 51,
    DESTINATION_OPTIONS = 60,
    MOBILITY = 135,
    HOST_IDENTITY_PROTOCOL = 139,
    SHIM6 = 140,
};


static const unsigned char* display_next_ipv6_header(const unsigned char* bytes, const unsigned char* end_stream, uint8_t* protocol, int verbosity, int tab_count)
{
    while(bytes != NULL && (
        *protocol    == HOP_BY_HOP
        || *protocol == ROUTING
        || *protocol == FRAGMENT
        || *protocol == ENCAPSULATING_SECURITY_PROTOCOL
        || *protocol == AUTHENTIFICATION_HEADER
        || *protocol == DESTINATION_OPTIONS
        || *protocol == MOBILITY
        || *protocol == HOST_IDENTITY_PROTOCOL
        || *protocol == SHIM6))
    {
        if(bytes + 8 > end_stream)
        {
            return NULL;
        }
        const struct ip6_ext* ext = (const struct ip6_ext*)bytes;
        if(bytes + 8 * (1 + (uint32_t)ext->ip6e_len) > end_stream)
        {
            return NULL;
        }
        if(verbosity > 2)
        {
            display_n_tabs(tab_count);
            printf("\tExtension ");
            switch((enum IPV6_NEXT_HEADERS)*protocol)
            {
                case HOP_BY_HOP:
                    printf("Hop By Hop:\n");
                    break;
                case ROUTING:
                    printf("Routing:\n");
                    break;
                case FRAGMENT:
                    printf("Fragment:\n");
                    break;
                case ENCAPSULATING_SECURITY_PROTOCOL:
                    printf("Encapsulating Security Protocol:\n");
                    break;
                case AUTHENTIFICATION_HEADER:
                    printf("Authentification Header:\n");
                    break;
                case DESTINATION_OPTIONS:
                    printf("Destination Options:\n");
                    break;
                case MOBILITY:
                    printf("Mobility:\n");
                    break;
                case HOST_IDENTITY_PROTOCOL:
                    printf("Host Identity Protocol:\n");
                    break;
                case SHIM6:
                    printf("SHIM6:\n");
                    break;
                default:
                    // This can't happen unless the code is modified by mistake.
                    abort();
            }
            display_generic_bytes(bytes + sizeof(struct ip6_hdr), 8 * (1 + (int)ext->ip6e_len) - (int)sizeof(struct ip6_hdr), tab_count + 2, NULL, 0);
        }
        *protocol = ext->ip6e_nxt;
        bytes += 8 * (1 + ext->ip6e_len);
    }
    return bytes;
}


static const unsigned char* display_ipv6(const unsigned char* bytes, const unsigned char** end_stream, uint8_t* protocol, int verbosity, int tab_count, bool dont_set_end_stream)
{
    if(bytes + sizeof(struct ip6_hdr) > *end_stream)
    {
        return NULL;
    }

    char buffer[INET6_ADDRSTRLEN];
    const struct ip6_hdr* ip = (const struct ip6_hdr*)bytes;
    uint32_t version_tc_fl = ntohl(ip->ip6_ctlun.ip6_un1.ip6_un1_flow);
    uint16_t payload_length = ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen);

    if(!dont_set_end_stream)
    {
        if(bytes + sizeof(struct ip6_hdr) + payload_length > *end_stream)
        {
            return NULL;
        }
        *end_stream = bytes + sizeof(struct ip6_hdr) + payload_length;
    }

    *protocol =  ip->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if(verbosity <= 2)
    {
        display_n_tabs(tab_count);
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
        display_n_tabs(tab_count);
        printf("IP:\n");
        display_n_tabs(tab_count);
        printf("\tVersion: %u\n", version_tc_fl >> 28);
        display_n_tabs(tab_count);
        printf("\tTraffic class: 0x%02x\n", (version_tc_fl >> 20) & 0xFF);
        display_n_tabs(tab_count);
        printf("\tFlow Label: 0x%05x\n", version_tc_fl & 0xFFFFF);
        display_n_tabs(tab_count);
        printf("\tPayload Length: %u\n", payload_length);
        display_n_tabs(tab_count);
        printf("\tNext Header: %d\n", *protocol);
        display_n_tabs(tab_count);
        printf("\tHop Limit: %d\n", ip->ip6_ctlun.ip6_un1.ip6_un1_hlim);
        display_n_tabs(tab_count);
        printf("\tSource address: %s\n", inet_ntop(AF_INET6, &(ip->ip6_src), buffer, INET6_ADDRSTRLEN));
        display_n_tabs(tab_count);
        printf("\tDestination address: %s\n", inet_ntop(AF_INET6, &(ip->ip6_dst), buffer, INET6_ADDRSTRLEN));
    }
    bytes += sizeof(struct ip6_hdr);

    return display_next_ipv6_header(bytes, *end_stream, protocol, verbosity, tab_count);
}


static const unsigned char* display_ipv4(const unsigned char* bytes, const unsigned char** end_stream, uint8_t* protocol, int verbosity, int tab_count, bool dont_set_end_stream)
{
    if(bytes + sizeof(struct iphdr) > *end_stream)
    {
        return NULL;
    }

    const struct iphdr* ip = (const struct iphdr*)bytes;

    if(bytes + 4 * ip->ihl > *end_stream)
    {
        return NULL;
    }

    char buffer[INET_ADDRSTRLEN];
    uint16_t frag_off = ntohs(ip->frag_off);
    uint8_t flags = (uint8_t)(frag_off >> 13);
    uint16_t total_length = ntohs(ip->tot_len);

    if(!dont_set_end_stream)
    {
        if(bytes + total_length > *end_stream)
        {
            return NULL;
        }
        *end_stream = bytes + total_length;
    }

    *protocol = ip->protocol;

    if(verbosity <= 2)
    {
        display_n_tabs(tab_count);
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
        display_n_tabs(tab_count);
        printf("IP:\n");
        display_n_tabs(tab_count);
        printf("\tVersion: %d\n", ip->version);
        display_n_tabs(tab_count);
        printf("\tHeader Length: %d (%d bytes)\n", ip->ihl, 4 * ip->ihl);
        display_n_tabs(tab_count);
        printf("\tType of Service: 0x%02x\n", ip->tos);
        display_n_tabs(tab_count);
        printf("\tTotal Length: %d\n", total_length);
        display_n_tabs(tab_count);
        printf("\tIdentification: 0x%04x\n", ntohs(ip->id));
        display_n_tabs(tab_count);
        printf("\tFlags 0x%x (R=%d DF=%d MF=%d)\n", flags, (flags >> 2) & 0x1, (flags >> 1) & 0x1, flags & 0x1);
        display_n_tabs(tab_count);
        printf("\tFragment Offset (without flags): %d\n", frag_off & ~(0x7 << 13));
        display_n_tabs(tab_count);
        printf("\tTime To Live: %d\n", ip->ttl);
        display_n_tabs(tab_count);
        printf("\tProtocol: 0x%02x\n", ip->protocol);
        display_n_tabs(tab_count);
        printf("\tHeader Checksum: 0x%04x\n", ntohs(ip->check));
        display_n_tabs(tab_count);
        printf("\tSource address: %s\n", inet_ntop(AF_INET, &(ip->saddr), buffer, INET_ADDRSTRLEN));
        display_n_tabs(tab_count);
        printf("\tDestination address: %s\n", inet_ntop(AF_INET, &(ip->daddr), buffer, INET_ADDRSTRLEN));
        if(ip->ihl > 5)
        {
            display_n_tabs(tab_count);
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

const unsigned char* display_ip(const unsigned char* bytes, const unsigned char** end_stream, uint8_t* protocol, int verbosity, int tab_count, bool dont_set_end_stream)
{
    if(bytes + 1 > *end_stream)
    {
        return NULL;
    }
    const struct iphdr* ip = (const struct iphdr*)bytes;
    if(ip->version == 4)
    {
        return display_ipv4(bytes, end_stream, protocol, verbosity, tab_count, dont_set_end_stream);
    }
    return display_ipv6(bytes, end_stream, protocol, verbosity, tab_count, dont_set_end_stream);
}