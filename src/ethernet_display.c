#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "ethernet_display.h"

void display_mac_addr(uint8_t* addr)
{
    for(int i = 0; i < ETH_ALEN-1; i++)
    {
        printf("%x:", addr[i]);
    }
    printf("%x\n", addr[ETH_ALEN-1]);
}

const unsigned char* display_ethernet_frame(const unsigned char* bytes)
{
    struct ether_header* ethernet = (struct ether_header*)bytes;

    puts("Ethernet:");

    printf("\tDestination address: ");
    display_mac_addr(ethernet->ether_dhost);

    printf("\tSource address:      ");
    display_mac_addr(ethernet->ether_shost);

    printf("\tData type: 0x%04x\n", ntohs(ethernet->ether_type));

    return bytes + sizeof(struct ether_header);
}