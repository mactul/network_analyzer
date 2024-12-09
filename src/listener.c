#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>

#include "common.h"
#include "ip_display.h"
#include "arp_display.h"
#include "dns_display.h"
#include "dhcp_display.h"
#include "ethernet_display.h"
#include "transport_display.h"
#include "text_based_display.h"

#include "listener.h"

#define MAX_INTERFACE_NAME 256
#define MAX_INT_STR_SIZE 8

static char _errbuf[PCAP_ERRBUF_SIZE];

static void select_interface(char* buffer, unsigned int buffer_size)
{
    int answer = 0;
    pcap_if_t* interfaces_list_root;
    pcap_if_t* current_interface;

    if(pcap_findalldevs(&interfaces_list_root, _errbuf))
    {
        fprintf(stderr, "%s\n", _errbuf);
        exit(EXIT_FAILURE);
    }

    if(interfaces_list_root == NULL)
    {
        fprintf(stderr, "There is no interface that can be analyzed\nMaybe try running this program as root\n");
        exit(EXIT_FAILURE);
    }

    while(answer == 0)
    {
        int counter = 0;
        char str[MAX_INT_STR_SIZE];
        current_interface = interfaces_list_root;
        while(current_interface != NULL)
        {
            counter++;
            printf("%d: %s\n", counter, current_interface->name);
            current_interface = current_interface->next;
        }
        printf("Select an interface (1-%d): ", counter);
        if(fgets(str, MAX_INT_STR_SIZE, stdin) == NULL)
        {
            putchar('\n');
            fprintf(stderr, "End of file on stdin and the interface wasn't specified\n");
            exit(EXIT_FAILURE);
        }
        answer = atoi(str);
        if(answer > counter)
        {
            answer = 0;
        }
    }

    current_interface = interfaces_list_root;
    for(int i = 1; i < answer; i++)
    {
        current_interface = current_interface->next;
    }

    strncpy(buffer, current_interface->name, buffer_size-1);
    buffer[buffer_size-1] = '\0';

    pcap_freealldevs(interfaces_list_root);
    interfaces_list_root = NULL;
    current_interface = NULL;
}



static void callback(u_char* user, const struct pcap_pkthdr* header, const unsigned char* bytes)
{
    uint16_t ether_type = 0x0000;
    uint8_t protocol = 0xFF;
    uint16_t dest_port = 0;
    uint16_t src_port = 0;
    int verbosity = (int)((size_t)user);
    const unsigned char* left_bytes = bytes;
    const unsigned char* end_stream = bytes + header->caplen;

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
        if((left_bytes = display_sctp(left_bytes, end_stream, &dest_port, &src_port, verbosity)) == NULL)
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
}

int run_pcap(int verbosity, char* interface_name, char* filter, char* offline_filename)
{
    int r;
    int return_code = 1;
    pcap_t* interface = NULL;
    char interface_buffer[MAX_INTERFACE_NAME];

    pcap_init(PCAP_CHAR_ENC_UTF_8, _errbuf);

    if(offline_filename != NULL)
    {
        if((interface = pcap_open_offline(offline_filename, _errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }
    }
    else
    {
        if(interface_name == NULL)
        {
            interface_name = interface_buffer;
            select_interface(interface_name, MAX_INTERFACE_NAME);
        }

        printf("Scanning interface: %s\n", interface_name);

        if((interface = pcap_create(interface_name, _errbuf)) == NULL)
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }

        pcap_set_immediate_mode(interface, 1);
        pcap_set_promisc(interface, 1);

        if((r = pcap_activate(interface)))
        {
            if(r < 0)
            {
                pcap_perror(interface, "Activation error: ");
                goto CLOSE;
            }
            else
            {
                pcap_perror(interface, "Activation warning: ");
            }
        }
    }

    if(filter != NULL)
    {
        struct bpf_program compiled_filter;
        bpf_u_int32 ip, mask;
        if(pcap_lookupnet(interface_name, &ip, &mask, _errbuf))
        {
            fprintf(stderr, "%s\n", _errbuf);
            goto CLOSE;
        }
        if(pcap_compile(interface, &compiled_filter, filter, 0, mask))
        {
            pcap_perror(interface, "Filter compilation error: ");
            goto CLOSE;
        }
        if(pcap_setfilter(interface, &compiled_filter))
        {
            pcap_perror(interface, "Filter can't be set: ");
            goto CLOSE;
        }
    }

    printf("start capture\n");

    pcap_loop(interface, -1, callback, (u_char*)((size_t)verbosity));

    return_code = 0;
CLOSE:
    if(interface != NULL)
    {
        pcap_close(interface);
        interface = NULL;
    }

    return return_code;
}