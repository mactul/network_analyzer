#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "lib/common.h"
#include "dns_display.h"

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
}  __attribute__((packed));

enum PRINT_ERRORS {
    PE_MORE_LEFT,
    PE_NO_MORE,
    PE_ERROR
};

static enum PRINT_ERRORS print_len_str(const unsigned char* bytes, const unsigned char* end_stream, unsigned int *offset, bool display, int stack_recursion_left)
{
    if(stack_recursion_left <= 0)
    {
        return PE_ERROR;
    }
    stack_recursion_left--;

    if(bytes + *offset >= end_stream)
    {
        return PE_ERROR;
    }

    uint8_t len = bytes[*offset];
    (*offset)++;

    if(len == 0)
    {
        return PE_NO_MORE;
    }
    if(len < 64)
    {
        if(bytes + *offset + len > end_stream)
        {
            return PE_ERROR;
        }
        if(display)
        {
            for(int i = 0; i < len; i++)
            {
                display_byte((bytes + *offset)[i]);
            }
        }
        *offset += len;
        return bytes[*offset] == 0 ? PE_NO_MORE : PE_MORE_LEFT;
    }
    unsigned int ptr = (unsigned int)(((uint16_t)(len & ((1 << 6) - 1)) << 8) | (uint16_t)bytes[*offset]);
    if(bytes + ptr >= end_stream)
    {
        return PE_ERROR;
    }
    enum PRINT_ERRORS r;
    while((r = print_len_str(bytes, end_stream, &ptr, display, stack_recursion_left)) == PE_MORE_LEFT)
    {
        if(display)
            putchar('.');
    }
    return r;
}

static bool display_rr(const unsigned char* bytes, const unsigned char* end_stream, unsigned int* offset, int verbosity)
{
    enum PRINT_ERRORS r;
    if(verbosity > 2)
        printf("\t\tName: ");
    while((r = print_len_str(bytes, end_stream, offset, verbosity > 2, 255)) == PE_MORE_LEFT)
    {
        if(verbosity > 2)
            putchar('.');
    }
    if(verbosity > 2)
    {
        putchar('\n');
    }
    if(r == PE_ERROR)
    {
        return false;
    }
    if(bytes + *offset + 11 > end_stream)
    {
        return false;
    }
    (*offset)++;
    if(verbosity > 2)
    {
        printf("\t\tType: %d\n", ntohs(*((uint16_t*)(bytes + *offset))));
        *offset += 2;
        printf("\t\tClass: %d\n", ntohs(*((uint16_t*)(bytes + *offset))));
        *offset += 2;
        printf("\t\tTTL: %u\n", ntohl(*((uint32_t*)(bytes + *offset))));
        *offset += 4;
    }
    else
    {
        *offset += 8;
    }
    uint16_t data_len = ntohs(*((uint16_t*)(bytes + *offset)));
    *offset += 2;
    if(bytes + *offset + data_len > end_stream)
    {
        return false;
    }
    if(verbosity > 2)
    {
        printf("\t\tData Length: %d\n", data_len);
        printf("\t\tData:\n");
        display_generic_bytes(bytes + *offset, data_len, 3, NULL, 0);
    }

    *offset += data_len;
    return true;
}

const unsigned char* display_dns(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    if(bytes + sizeof(struct dnshdr) > end_stream)
    {
        return NULL;
    }

    const struct dnshdr* dns = (const struct dnshdr*) bytes;
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
        enum PRINT_ERRORS r;
        if(verbosity > 2)
        {
            printf("\tQuestion %d:\n", qc+1);
            printf("\t\tName: ");
        }
        while((r = print_len_str(bytes, end_stream, &offset, verbosity > 1, 255)) == PE_MORE_LEFT)
        {
            if(verbosity > 1)
            {
                putchar('.');
            }
        }
        if(verbosity > 1)
        {
            putchar(' ');
        }
        if(verbosity > 2)
        {
            putchar('\n');
        }
        if(r == PE_ERROR)
        {
            return NULL;
        }
        if(bytes + offset + 5 > end_stream)
        {
            return NULL;
        }
        offset++;
        if(verbosity > 2)
        {
            printf("\t\tType: %d\n", ntohs(*((uint16_t*)(bytes + offset))));
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
        if(!display_rr(bytes, end_stream, &offset, verbosity))
        {
            return NULL;
        }
    }
    for(uint16_t nc = 0; nc < ntohs(dns->nscount); nc++)
    {
        if(verbosity > 2)
            printf("\tAuthority %d:\n", nc+1);
        if(!display_rr(bytes, end_stream, &offset, verbosity))
        {
            return NULL;
        }
    }
    for(uint16_t ac = 0; ac < ntohs(dns->arcount); ac++)
    {
        if(verbosity > 2)
            printf("\tAdditional %d:\n", ac+1);
        if(!display_rr(bytes, end_stream, &offset, verbosity))
        {
            return NULL;
        }
    }

    if(verbosity == 2)
    {
        putchar('\n');
    }

    if(bytes + offset > end_stream)
    {
        return NULL;
    }

    return bytes + offset;
}