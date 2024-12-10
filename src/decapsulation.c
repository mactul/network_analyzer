#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>

#include "lib/common.h"
#include "physical_layer/ethernet_display.h"
#include "network_layer/ip_display.h"
#include "network_layer/arp_display.h"
#include "transport_layer/tcp_display.h"
#include "transport_layer/udp_display.h"
#include "transport_layer/icmp_display.h"
#include "transport_layer/sctp_display.h"
#include "application_layer/dns_display.h"
#include "application_layer/dhcp_display.h"
#include "application_layer/text_based_display.h"

#include "decapsulation.h"


void decapsulation(const unsigned char* left_bytes, const unsigned char* end_stream, int verbosity)
{
    uint16_t ether_type = 0x0000;
    uint8_t protocol = 0xFF;
    uint16_t dest_port = 0;
    uint16_t src_port = 0;
    int align_offset = 0;
    const unsigned char* sctp_reentrant = NULL;

    if((left_bytes = display_ethernet_frame(left_bytes, end_stream, &ether_type, verbosity)) == NULL)
    {
        fprintf(stderr, "Malformed Ethernet header\n\n");
        return;
    }

    if(ether_type == ETHERTYPE_ARP)
    {
        if((left_bytes = display_arp(left_bytes, end_stream, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed ARP header\n\n");
            return;
        }
    }
    else if(ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6)
    {
        if((left_bytes = display_ip(left_bytes, &end_stream, &protocol, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed IP header\n\n");
            return;
        }
    }

    if(protocol == 0x01)
    {
        if((left_bytes = display_icmp(left_bytes, end_stream, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed ICMP header\n\n");
            return;
        }
    }
    else if(protocol == 0x3A)
    {
        if((left_bytes = display_icmp(left_bytes, end_stream, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed ICMPv6 header\n\n");
            return;
        }
    }
    else if(protocol == 0x11)
    {
        if((left_bytes = display_udp(left_bytes, end_stream, &dest_port, &src_port, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed UDP header\n");
            return;
        }
    }
    else if(protocol == 0x06)
    {
        if((left_bytes = display_tcp(left_bytes, end_stream, &dest_port, &src_port, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed TCP header\n");
            return;
        }
    }
    else if(protocol == 0x84)
    {
SCTP:  // This ugly label is used when a sctp segment contains multiple data chunks, in this case we have no other choices than to come back here.
        if((left_bytes = display_sctp(left_bytes, &end_stream, &dest_port, &src_port, verbosity, &sctp_reentrant, &align_offset)) == NULL)
        {
            fprintf(stderr, "Malformed SCTP header\n");
            return;
        }
    }

    if(dest_port == 67 || dest_port == 68 || src_port == 67 || src_port == 68)
    {
        if((left_bytes = display_dhcp(left_bytes, end_stream, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed BOOTP header\n");
            return;
        }
    }
    else if(dest_port == 53 || src_port == 53)
    {
        if((left_bytes = display_dns(left_bytes, end_stream, verbosity)) == NULL)
        {
            fprintf(stderr, "Malformed DNS header\n");
            return;
        }
    }
    else if(dest_port == 80 || src_port == 80)
    {
        left_bytes = display_http(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 443 || src_port == 443)
    {
        left_bytes = display_https(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 25 || src_port == 25)
    {
        left_bytes = display_smtp(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 587 || src_port == 587 || dest_port == 465 || src_port == 465)
    {
        left_bytes = display_smtps(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 110 || src_port == 110)
    {
        left_bytes = display_pop(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 143 || src_port == 143 || dest_port == 220 || src_port == 220)
    {
        left_bytes = display_imap(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 993 || src_port == 993)
    {
        left_bytes = display_imaps(left_bytes, end_stream, verbosity);
    }
    else if(dest_port == 23 || src_port == 23)
    {
        left_bytes = display_telnet(left_bytes, end_stream, verbosity);
    }

    if(verbosity > 2)
    {
        int left = (int)(end_stream - left_bytes);
        if(left > 0)
        {
            printf("Data:\n");
            display_generic_bytes(left_bytes, left, 1);
        }
    }
    putchar('\n');
    if(sctp_reentrant)
    {
        printf("SCTP (continuation of previous SCTP segment):\n");
        goto SCTP;
    }
}
