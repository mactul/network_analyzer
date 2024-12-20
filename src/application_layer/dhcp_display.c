#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "dhcp_display.h"
#include "lib/common.h"

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
    unsigned char sname[64];
    unsigned char file[128];
    uint8_t vendor_specific[];  // Apparently, DHCP can have vendor specific options that are less than the classic 64 bytes.
} __attribute__((packed));


enum DHCP_TLV_TYPES {
    DHCP_TLV_NOP = 0,
    DHCP_TLV_SUBNET_MASK = 1,
    DHCP_TLV_ROUTER = 3,
    DHCP_TLV_NAMESERVERS = 6,
    DHCP_TLV_HOSTNAME = 12,
    DHCP_TLV_DOMAIN_NAME = 15,
    DHCP_TLV_NTP_SERVERS = 42,
    DHCP_TLV_ADDRESS_REQUEST = 50,
    DHCP_TLV_LEASE_TIME = 51,
    DHCP_TLV_MESSAGE_TYPE = 53,
    DHCP_TLV_SERVER_ID = 54,
    DHCP_TLV_PARAMETER_REQUEST_LIST = 55,
    DHCP_TLV_RENEWAL = 58,
    DHCP_TLV_REBINDING = 59,
    DHCP_TLV_CLIENT_ID = 61,
    DHCP_TLV_END = 255
};

static const char* dhcp_messages_types_lookup[] = {"UNKNOWN DHCP MESSAGE", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NACK", "RELEASE"};


static void display_dhcp_tlv_type(uint8_t type)
{
    switch(type)
    {
        case DHCP_TLV_SUBNET_MASK:
            printf(" (Subnet Mask)");
            break;
        case DHCP_TLV_ROUTER:
            printf(" (Router)");
            break;
        case DHCP_TLV_NAMESERVERS:
            printf(" (Nameservers)");
            break;
        case DHCP_TLV_HOSTNAME:
            printf(" (Hostname)");
            break;
        case DHCP_TLV_DOMAIN_NAME:
            printf(" (Domain Name)");
            break;
        case DHCP_TLV_NTP_SERVERS:
            printf(" (NTP Servers Addresses)");
            break;
        case DHCP_TLV_ADDRESS_REQUEST:
            printf(" (Requested IP Address)");
            break;
        case DHCP_TLV_LEASE_TIME:
            printf(" (IP Address Lease Time)");
            break;
        case DHCP_TLV_MESSAGE_TYPE:
            printf(" (Message Type)");
            break;
        case DHCP_TLV_SERVER_ID:
            printf(" (Server Identifier)");
            break;
        case DHCP_TLV_RENEWAL:
            printf(" (Renewal Time)");
            break;
        case DHCP_TLV_REBINDING:
            printf(" (Rebinding Time)");
            break;
        case DHCP_TLV_PARAMETER_REQUEST_LIST:
            printf(" (Parameter Request List)");
            break;
        case DHCP_TLV_CLIENT_ID:
            printf(" (Client Identifier)");
            break;
    }
}


static bool display_dhcp_tlv(const unsigned char* bytes, const unsigned char* end_stream)
{
    printf("\t\tMagic Cookie: 0x%08x\n", ntohl(*((uint32_t*)bytes)));
    bytes += 4;
    while(bytes < end_stream)
    {
        if(bytes + sizeof(uint8_t) > end_stream)
        {
            return false;
        }
        uint8_t type = *bytes;
        bytes++;

        if(type == DHCP_TLV_END)
        {
            return true;
        }
        if(type == DHCP_TLV_NOP)
        {
            continue;
        }

        if(bytes + sizeof(uint8_t) > end_stream)
        {
            return false;
        }

        uint8_t length = *bytes;
        bytes++;

        if(bytes + length > end_stream)
        {
            return false;
        }

        printf("\t\tType: %d", type);
        display_dhcp_tlv_type(type);
        printf("\n\t\tLength: %d\n", length);

        printf("\t\tValue:");
        switch(type)
        {
            char buffer[INET_ADDRSTRLEN];

            case DHCP_TLV_SUBNET_MASK:
            case DHCP_TLV_ADDRESS_REQUEST:
            case DHCP_TLV_SERVER_ID:
                if(length != 4)
                {
                    return false;
                }
                printf(" %s\n", inet_ntop(AF_INET, bytes, buffer, INET_ADDRSTRLEN));
                break;

            case DHCP_TLV_ROUTER:
            case DHCP_TLV_NAMESERVERS:
            case DHCP_TLV_NTP_SERVERS:
                if(length < 4 || length % 4 != 0)
                {
                    return false;
                }
                putchar('\n');
                for(int i = 0; i < length; i += 4)
                {
                    printf("\t\t\t%s\n", inet_ntop(AF_INET, bytes + i, buffer, INET_ADDRSTRLEN));
                }
                break;

            case DHCP_TLV_HOSTNAME:
            case DHCP_TLV_DOMAIN_NAME:
                putchar(' ');
                display_string(bytes, length);
                putchar('\n');
                break;

            case DHCP_TLV_LEASE_TIME:
            case DHCP_TLV_RENEWAL:
            case DHCP_TLV_REBINDING:
                if(length != 4)
                {
                    return false;
                }
                printf(" %u seconds\n", ntohl(*((uint32_t*)bytes)));
                break;

            case DHCP_TLV_MESSAGE_TYPE:
                if(length != 1)
                {
                    return false;
                }
                {
                    uint8_t message_type = *bytes;
                    if(message_type > 7)
                    {
                        message_type = 0;
                    }
                    printf(" %d (%s)\n", *bytes, dhcp_messages_types_lookup[message_type]);
                }
                break;

            case DHCP_TLV_PARAMETER_REQUEST_LIST:
                putchar('\n');
                for(int i = 0; i < length; i++)
                {
                    printf("\t\t\t%d", bytes[i]);
                    display_dhcp_tlv_type(bytes[i]);
                    putchar('\n');
                }
                break;
            case DHCP_TLV_CLIENT_ID:
                if(length < 1)
                {
                    return false;
                }
                printf("\n\t\t\tHardware Address Type: %d\n", *bytes);
                printf("\t\t\tHardware Address: ");
                display_hardware_addr(bytes + 1, length-1);
                putchar('\n');
                break;

            default:
                putchar('\n');
                display_generic_bytes(bytes, length, 3, NULL, 0);
        }
        putchar('\n');

        bytes += length;
    }

    if(bytes != end_stream)
    {
        return false;
    }

    return true;
}


const unsigned char* display_dhcp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    if(bytes + sizeof(struct bootp) + 4 > end_stream)
    {
        return NULL;
    }

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

        printf("\n\tServer name: ");
        display_string(bootp->sname, 63);
        printf("\n\tFile Name: ");
        display_string(bootp->file, 127);

        printf("\n\tVendor specific:\n");
        if(dhcp)
        {
            // According to the RFC, DHCP options are now variable in length (>= 64), hence the end_stream use instead of just 64
            display_dhcp_tlv(bootp->vendor_specific, end_stream);
        }
        else
        {
            if(bootp->vendor_specific + 64 > end_stream)
            {
                return NULL;
            }
            display_generic_bytes(bootp->vendor_specific, 64, 2, NULL, 0);
        }
    }

    return end_stream;
}