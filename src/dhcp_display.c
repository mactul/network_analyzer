#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "dhcp_display.h"
#include "common.h"

struct bootp {
    uint8_t code_op;
    uint8_t hardware_type;
    uint8_t hardware_addr_len;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    char sname[64];
    char file[128];
    uint8_t vendor_specific[64];
} __attribute__((packed));


const unsigned char* display_dhcp(const unsigned char* bytes, int verbosity)
{
    bool dhcp = false;
    char buffer[INET_ADDRSTRLEN];
    const struct bootp* bootp = (const struct bootp*)bytes;

    if(memcmp(bootp->vendor_specific, "\x63\x82\x53\x63", 4) == 0)
    {
        printf("DHCP");
        dhcp = true;
    }
    else
    {
        printf("BOOTP");
    }
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
        printf("\tCode OP: %d\n", bootp->code_op);
        printf("\tHardware Type: %d\n", bootp->hardware_type);
        printf("\tHardware address Length: %d\n", bootp->hardware_addr_len);
        printf("\tHop Count: %d\n", bootp->hops);
        printf("\tTransaction ID: 0x%08x\n", ntohl(bootp->xid));
        printf("\tseconds: %d\n", ntohs(bootp->secs));
        if(dhcp)
        {
            printf("\tFlags: %d\n", ntohs(bootp->flags));
        }
        printf("\tClient IP (ciaddr) %s\n", inet_ntop(AF_INET, &(bootp->ciaddr), buffer, INET_ADDRSTRLEN));
        printf("\tYour IP (yiaddr) %s\n", inet_ntop(AF_INET, &(bootp->yiaddr), buffer, INET_ADDRSTRLEN));
        printf("\tServer IP (siaddr) %s\n", inet_ntop(AF_INET, &(bootp->siaddr), buffer, INET_ADDRSTRLEN));
        printf("\tGateway IP (giaddr) %s\n", inet_ntop(AF_INET, &(bootp->giaddr), buffer, INET_ADDRSTRLEN));
        printf("\tClient Hardware address ");
        if(bootp->hardware_addr_len > 16)
        {
            display_hardware_addr(bootp->chaddr, 16);
        }
        else
        {
            display_hardware_addr(bootp->chaddr, bootp->hardware_addr_len);
        }

        printf("\n\tServer name: %.64s\n", bootp->sname);
        printf("\tFile Name: %.127s\n", bootp->file);

        printf("\tVendor specific:\n");
        display_generic_bytes(bootp->vendor_specific, 64, 2);
    }

    return bytes + sizeof(struct bootp);
}