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


#define MAX_INTERFACE_NAME 256
#define MAX_INT_STR_SIZE 8

static char _errbuf[PCAP_ERRBUF_SIZE];

void select_interface(char* buffer, unsigned int buffer_size)
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
        fgets(str, MAX_INT_STR_SIZE, stdin);
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



void callback(u_char* user, const struct pcap_pkthdr* header, const unsigned char* bytes)
{
    uint16_t ether_type;
    uint8_t protocol = 0xFF;
    uint16_t dest_port = 0;
    uint16_t src_port = 0;
    const unsigned char* left_bytes = bytes;
    int verbosity = (int)((size_t)user);
    left_bytes = display_ethernet_frame(left_bytes, &ether_type, verbosity);

    if(ether_type == ETHERTYPE_ARP)
    {
        left_bytes = display_arp(left_bytes, verbosity);
    }
    else if(ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6)
    {
        left_bytes = display_ip(left_bytes, &protocol, verbosity);
    }

    if(protocol == 0x01)
    {
        left_bytes = display_icmp(left_bytes, verbosity);
    }
    else if(protocol == 0x3A)
    {
        left_bytes = display_icmp(left_bytes, verbosity);
    }
    else if(protocol == 0x11)
    {
        left_bytes = display_udp(left_bytes, &dest_port, &src_port, verbosity);
    }
    else if(protocol == 0x06)
    {
        left_bytes = display_tcp(left_bytes, &dest_port, &src_port, verbosity);
    }

    if(dest_port == 67 || dest_port == 68 || src_port == 67 || src_port == 68)
    {
        left_bytes = display_dhcp(left_bytes, verbosity);
    }
    else if(dest_port == 53 || src_port == 53)
    {
        left_bytes = display_dns(left_bytes, verbosity);
    }

    if(verbosity > 2)
    {
        printf("Data:\n");
        display_generic_bytes(left_bytes, (int)header->caplen - (int)(left_bytes - bytes), 1);
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
       interface = pcap_open_offline(offline_filename, _errbuf);
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