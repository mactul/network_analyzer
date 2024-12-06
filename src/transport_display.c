#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ip_display.h"

const unsigned char* display_udp(const unsigned char* bytes, uint16_t* dest_port, uint16_t* src_port)
{
    struct udphdr* udp = (struct udphdr*)bytes;
    *dest_port = ntohs(udp->uh_dport);
    *src_port = ntohs(udp->uh_sport);
    printf("UDP:\n");
    printf("\tSource port: %u\n", *src_port);
    printf("\tDestination port: %u\n", *dest_port);
    printf("\tLength: %u\n", ntohs(udp->uh_ulen));
    printf("\tChecksum: %04x\n", ntohs(udp->uh_sum));
    return bytes + sizeof(struct udphdr);
}

const unsigned char* display_tcp(const unsigned char* bytes, uint16_t* dest_port, uint16_t* src_port)
{
    struct tcphdr* tcp = (struct tcphdr*)bytes;
    *dest_port = ntohs(tcp->th_dport);
    *src_port = ntohs(tcp->th_sport);
    printf("TCP:\n");
    printf("\tSource port: %u\n", *src_port);
    printf("\tDestination port: %u\n", *dest_port);
    printf("\tSequence Number: %08x\n", ntohl(tcp->th_seq));
    if(tcp->ack)
        printf("\tAck Number: %08x\n", ntohl(tcp->th_ack));
    printf("\tData Offset: %d\n", tcp->th_off);
    printf("\tFlags: %d (CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d)\n", tcp->th_flags, tcp->res2 >> 1, tcp->res2 & 0x1, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
    printf("\tWindow: %d\n", ntohs(tcp->th_win));
    printf("\tChecksum: %d\n", ntohs(tcp->th_sum));
    printf("\tUrgent Pointer: %d\n", ntohs(tcp->th_urp));

    return bytes + tcp->th_off * 4;
}