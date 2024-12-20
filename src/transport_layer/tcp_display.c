#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#include "lib/common.h"
#include "tcp_display.h"


enum TCP_TLV_TYPES {
    TCP_TLV_END = 0,
    TCP_TLV_NOOP = 1,
    TCP_TLV_MAX_SEG_SIZE = 2,
    TCP_TLV_WINDOW_SCALE = 3,
    TCP_TLV_SACK_ENABLE = 4,
    TCP_TLV_SACK = 5,
    TCP_TLV_TIMESTAMP = 8,
    TCP_TLV_USER_TIMEOUT = 28,
    TCP_TLV_AUTH = 29,
    TCP_TLV_MULTIPATH = 30
};


static void display_tcp_tlv_type(uint8_t type)
{
    switch(type)
    {
        case TCP_TLV_MAX_SEG_SIZE:
            printf(" (Maximum Segment Size)");
            break;
        case TCP_TLV_WINDOW_SCALE:
            printf(" (Windows Scale)");
            break;
        case TCP_TLV_SACK_ENABLE:
            printf(" (SACK enabled)");
            break;
        case TCP_TLV_SACK:
            printf(" (SACK)");
            break;
        case TCP_TLV_TIMESTAMP:
            printf(" (Timestamp)");
            break;
        case TCP_TLV_USER_TIMEOUT:
            printf(" (User Timeout)");
            break;
        case TCP_TLV_AUTH:
            printf(" (Auth options)");
            break;
        case TCP_TLV_MULTIPATH:
            printf(" (Multipath)");
            break;
    }
}


static bool display_tcp_tlv(const unsigned char* bytes, const unsigned char* end_stream)
{
    while(bytes < end_stream)
    {
        if(bytes + sizeof(uint8_t) > end_stream)
        {
            return false;
        }
        uint8_t type = *bytes;
        bytes++;

        if(type == TCP_TLV_END)
        {
            return true;
        }
        if(type == TCP_TLV_NOOP)
        {
            continue;
        }

        if(bytes + sizeof(uint8_t) > end_stream)
        {
            return false;
        }

        uint8_t length = *bytes;
        bytes++;

        if(length < 2)
        {
            return false;
        }


        printf("\t\tType: %d", type);
        display_tcp_tlv_type(type);
        printf("\n\t\tLength: %d\n", length);

        length -= 2;

        if(bytes + length > end_stream)
        {
            return false;
        }

        printf("\t\tValue:");
        switch(type)
        {
            case TCP_TLV_MAX_SEG_SIZE:
                if(length != 2)
                {
                    return false;
                }
                printf(" %d\n", ntohs(*((uint16_t*)bytes)));
                break;

            case TCP_TLV_WINDOW_SCALE:
                if(length != 1)
                {
                    return false;
                }
                printf(" %d\n", *bytes);
                break;

            case TCP_TLV_SACK:
                if(length % 8 != 0)
                {
                    return false;
                }
                putchar('\n');
                for(int i = 0; i < length; i += 8)
                {
                    printf("\t\t\tbegin ptr: %u, end ptr: %u\n", ntohl(*((uint32_t*)bytes)), ntohl(*((uint32_t*)(bytes+4))));
                }
                break;

            case TCP_TLV_TIMESTAMP:
                if(length != 8)
                {
                    return false;
                }
                printf(" timestamp: %u, previous timestamp: %u\n", ntohl(*((uint32_t*)bytes)), ntohl(*((uint32_t*)(bytes+4))));
                break;

            case TCP_TLV_SACK_ENABLE:
            case TCP_TLV_USER_TIMEOUT:
                if(length != 0)
                {
                    return false;
                }
                putchar('\n');
                break;

            default:
                putchar('\n');
                display_generic_bytes(bytes, length, 3, NULL, 0);
        }
        putchar('\n');

        bytes += length;
    }

    if(bytes != end_stream)
    {
        return false;
    }

    return true;
}


const unsigned char* display_tcp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity)
{
    if(bytes + sizeof(struct tcphdr) > end_stream)
    {
        return NULL;
    }

    const struct tcphdr* tcp = (const struct tcphdr*)bytes;

    if(bytes + 4 * tcp->th_off > end_stream)
    {
        return NULL;
    }

    *dest_port = ntohs(tcp->th_dport);
    *src_port = ntohs(tcp->th_sport);

    if(verbosity <= 2)
    {
        printf("TCP: src_port=%d dst_port=%d", *src_port, *dest_port);
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
        printf("TCP:\n");
        printf("\tSource port: %u\n", *src_port);
        printf("\tDestination port: %u\n", *dest_port);
        printf("\tSequence Number: 0x%08x\n", ntohl(tcp->th_seq));
        if(tcp->ack)
            printf("\tAck Number: 0x%08x\n", ntohl(tcp->th_ack));
        printf("\tData Offset: %d\n", tcp->th_off);
        printf("\tFlags: %d (CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d)\n", tcp->th_flags, tcp->res2 >> 1, tcp->res2 & 0x1, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
        printf("\tWindow: %d\n", ntohs(tcp->th_win));
        printf("\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
        printf("\tUrgent Pointer: %d\n", ntohs(tcp->th_urp));

        if(tcp->th_off * 4 > sizeof(struct tcphdr))
        {
            printf("\tOptions:\n");
            if(!display_tcp_tlv(bytes + sizeof(struct tcphdr), bytes + tcp->th_off * 4))
            {
                return NULL;
            }
        }
    }

    return bytes + tcp->th_off * 4;
}
