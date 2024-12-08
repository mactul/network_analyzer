#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "common.h"
#include "ethernet_display.h"


const unsigned char* display_ethernet_frame(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* ether_type, int verbosity)
{
    if(bytes + sizeof(struct ether_header) > end_stream)
    {
        return NULL;
    }

    const struct ether_header* ethernet = (const struct ether_header*)bytes;

    *ether_type = ntohs(ethernet->ether_type);

    if(verbosity <= 1)
    {
        printf("Ethernet    ");
    }
    else if(verbosity == 2)
    {
        printf("Ethernet: ");
        display_hardware_addr(ethernet->ether_shost, ETH_ALEN);
        printf(" -> ");
        display_hardware_addr(ethernet->ether_dhost, ETH_ALEN);
        putchar('\n');
    }
    else
    {
        puts("Ethernet:");

        printf("\tDestination address: ");
        display_hardware_addr(ethernet->ether_dhost, ETH_ALEN);
        putchar('\n');

        printf("\tSource address:      ");
        display_hardware_addr(ethernet->ether_shost, ETH_ALEN);
        putchar('\n');

        printf("\tData type: 0x%04x\n", *ether_type);
    }

    return bytes + sizeof(struct ether_header);
}