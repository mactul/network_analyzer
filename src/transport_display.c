#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "transport_display.h"

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
    }

    return bytes + tcp->th_off * 4;
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