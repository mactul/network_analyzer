#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ethernet_display.h"

static void display_mac_addr(uint8_t* addr)
{
    for(int i = 0; i < ETH_ALEN-1; i++)
    {
        printf("%x:", addr[i]);
    }
    printf("%x", addr[ETH_ALEN-1]);
}

const unsigned char* display_ethernet_frame(const unsigned char* bytes, int verbosity)
{
    if(verbosity > 1)
    {
        struct ether_header* ethernet = (struct ether_header*)bytes;

        if(verbosity == 2)
        {
            printf("Ethernet: ");
            display_mac_addr(ethernet->ether_shost);
            printf(" -> ");
            display_mac_addr(ethernet->ether_dhost);
            putchar('\n');
        }
        else
        {
            puts("Ethernet:");

            printf("\tDestination address: ");
            display_mac_addr(ethernet->ether_dhost);
            putchar('\n');

            printf("\tSource address:      ");
            display_mac_addr(ethernet->ether_shost);
            putchar('\n');

            printf("\tData type: 0x%04x\n", ntohs(ethernet->ether_type));
        }
    }

    return bytes + sizeof(struct ether_header);
}