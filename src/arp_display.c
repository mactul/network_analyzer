#include <stdio.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include "common.h"
#include "arp_display.h"


void display_protocol_addr(const uint8_t* addr, uint8_t len)
{
    for(uint8_t i = 0; i < len-1; i++)
    {
        printf("%d.", addr[i]);
    }
    printf("%d\n", addr[len-1]);
}


const unsigned char* display_arp(const unsigned char* bytes, int verbosity)
{
    struct arphdr* arp = (struct arphdr*)bytes;

    printf("ARP");
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
        printf("\tHardware Type: %d\n", ntohs(arp->ar_hrd));
        printf("\tProtocol Type: 0x%04x\n", ntohs(arp->ar_pro));
        printf("\tHardware Addr Length: %d\n", arp->ar_hln);
        printf("\tProtocol Length: %d\n", arp->ar_pln);
        printf("\tOperation: %d\n", ntohs(arp->ar_op));
        printf("\tSender Hardware Address: ");
        display_hardware_addr(bytes + sizeof(struct arphdr), arp->ar_hln);
        printf("\n\tSender Protocol Address: ");
        display_protocol_addr(bytes + sizeof(struct arphdr) + arp->ar_hln, arp->ar_pln);
        printf("\tTarget Hardware Address: ");
        display_hardware_addr(bytes + sizeof(struct arphdr) + arp->ar_hln + arp->ar_pln, arp->ar_hln);
        printf("\n\tTarget Protocol Address: ");
        display_protocol_addr(bytes + sizeof(struct arphdr) + 2 * arp->ar_hln + arp->ar_pln, arp->ar_pln);
    }

    return bytes + sizeof(struct arphdr) + 2 * arp->ar_hln + 2 * arp->ar_pln;
}