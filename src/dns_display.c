#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "common.h"
#include "dns_display.h"

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}  __attribute__((packed));

bool print_len_str(const unsigned char* bytes, unsigned int *offset, bool display)
{
    uint8_t len = bytes[*offset];
    (*offset)++;
    if(len == 0)
    {
        return false;
    }
    if(len < 64)
    {
        if(display)
            fwrite(bytes + *offset, sizeof(char), len, stdout);
        *offset += len;
        return bytes[*offset] != 0;
    }
    unsigned int ptr = (unsigned int)(((uint16_t)(len & 0b00111111) << 8) | (uint16_t)bytes[*offset]);
    while(print_len_str(bytes, &ptr, display))
    {
        if(display)
            putchar('.');
    }
    return 0;
}

static void display_rr(const unsigned char* bytes, unsigned int* offset, int verbosity)
{

    if(verbosity > 2)
        printf("\t\tName: ");
    while(print_len_str(bytes, offset, verbosity > 2))
    {
        if(verbosity > 2)
            putchar('.');
    }
    (*offset)++;
    if(verbosity > 2)
    {
        printf("\n\t\tType: %d\n", ntohs(*((uint16_t*)(bytes + *offset))));
        *offset += 2;
        printf("\t\tClass: %d\n", ntohs(*((uint16_t*)(bytes + *offset))));
        *offset += 2;
        printf("\t\tTTL: %d\n", ntohl(*((uint32_t*)(bytes + *offset))));
        *offset += 4;
    }
    else
    {
        *offset += 8;
    }
    uint16_t data_len = ntohs(*((uint16_t*)(bytes + *offset)));
    *offset += 2;
    if(verbosity > 2)
    {
        printf("\t\tData Length: %d\n", data_len);
        printf("\t\tData:\n");
        display_generic_bytes(bytes + *offset, data_len, 3);
    }

    *offset += data_len;
}

const unsigned char* display_dns(const unsigned char* bytes, int verbosity)
{
    struct dnshdr* dns = (struct dnshdr*) bytes;
    uint16_t flags = ntohs(dns->flags);

    printf("DNS");
    if(verbosity <= 1)
    {
        printf("    ");
    }
    else
    {
        printf(": ");
    }
    if(verbosity > 2)
    {
        putchar('\n');
    }

    if(verbosity > 2)
    {
        printf("\tId: 0x%04x\n", ntohs(dns->id));
        printf("\tIs query: %d\n", flags >> 15);
        printf("\tOP Code: %d\n", (flags >> 11) & 0xf);
        printf("\tAuthoritative Answer: %d\n", (flags >> 10) & 0x1);
        printf("\tTruncation: %d\n", (flags >> 9) & 0x1);
        printf("\tRecursion Desired: %d\n", (flags >> 8) & 0x1);
        printf("\tRecursion Available: %d\n", (flags >> 7) & 0x1);
        printf("\tResponse Code: %d\n", flags & 0xf);
        printf("\tQuestion Count: %d\n", ntohs(dns->qdcount));
        printf("\tAnswer Count: %d\n", ntohs(dns->ancount));
        printf("\tName servers Count: %d\n", ntohs(dns->nscount));
        printf("\tAdditional Records Count: %d\n", ntohs(dns->arcount));
    }

    unsigned int offset = sizeof(struct dnshdr);
    for(uint16_t qc = 0; qc < ntohs(dns->qdcount); qc++)
    {
        if(verbosity > 2)
        {
            printf("\tQuestion %d:\n", qc+1);
            printf("\t\tName: ");
        }
        while(print_len_str(bytes, &offset, verbosity > 1))
        {
            if(verbosity > 1)
            {
                putchar('.');
            }
        }
        offset++;
        if(verbosity > 1)
        {
            putchar(' ');
        }
        if(verbosity > 2)
        {
            printf("\n\t\tType: %d\n", ntohs(*((uint16_t*)(bytes + offset))));
            offset += 2;
            printf("\t\tClass: %d\n", ntohs(*((uint16_t*)(bytes + offset))));
            offset += 2;
        }
        else
        {
            offset += 4;
        }
    }
    for(uint16_t ac = 0; ac < ntohs(dns->ancount); ac++)
    {
        if(verbosity > 2)
            printf("\tAnswer %d:\n", ac+1);
        display_rr(bytes, &offset, verbosity);
    }
    for(uint16_t nc = 0; nc < ntohs(dns->nscount); nc++)
    {
        if(verbosity > 2)
            printf("\tAuthority %d:\n", nc+1);
        display_rr(bytes, &offset, verbosity);
    }
    for(uint16_t ac = 0; ac < ntohs(dns->arcount); ac++)
    {
        if(verbosity > 2)
            printf("\tAdditional %d:\n", ac+1);
        display_rr(bytes, &offset, verbosity);
    }

    if(verbosity == 2)
    {
        putchar('\n');
    }


    return bytes + offset;
}