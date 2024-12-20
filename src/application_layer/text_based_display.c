#include <stdio.h>
#include <stdbool.h>

#include "lib/common.h"
#include "text_based_display.h"


static bool startswith(const char* str, const char* ref)
{
    while(*str != '\0' && *ref != '\0' && *str == *ref)
    {
        str++;
        ref++;
    }
    return *ref == '\0';
}


const unsigned char* display_text_protocol(const char* name, const unsigned char* bytes, const unsigned char* end_stream, int verbosity, const unsigned char* to_highlight, int nb_to_highlight)
{
    printf("%s", name);
    if(verbosity <= 2)
    {
        if(verbosity <= 1)
        {
            printf("    ");
        }
        else
        {
            putchar('\n');
        }
    }
    else if(bytes < end_stream)
    {
        printf(":\n");
        display_generic_bytes(bytes, (int)(end_stream - bytes), 1, to_highlight, nb_to_highlight);
    }
    else
    {
        putchar('\n');
    }

    return end_stream;
}


const unsigned char* display_http(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    if(verbosity >= 2)
    {
        if(startswith((const char*)bytes, "GET "))
        {
            puts("HTTP: GET");
        }
        else if(startswith((const char*)bytes, "POST "))
        {
            puts("HTTP: POST");
        }
        else if(startswith((const char*)bytes, "HEAD "))
        {
            puts("HTTP: HEAD");
        }
        else if(startswith((const char*)bytes, "OPTIONS "))
        {
            puts("HTTP: OPTIONS");
        }
        else if(startswith((const char*)bytes, "PUT "))
        {
            puts("HTTP: PUT");
        }
        else if(startswith((const char*)bytes, "PATCH "))
        {
            puts("HTTP: PATCH");
        }
        else if(startswith((const char*)bytes, "DELETE "))
        {
            puts("HTTP: DELETE");
        }
        else if(startswith((const char*)bytes, "CONNECT "))
        {
            puts("HTTP: CONNECT");
        }
        else if(startswith((const char*)bytes, "TRACE "))
        {
            puts("HTTP: TRACE");
        }
        else if(verbosity > 2 && bytes < end_stream)
        {
            puts("HTTP:");
        }
        else
        {
            puts("HTTP");
        }

        if(verbosity > 2 && bytes < end_stream)
        {
            display_generic_bytes(bytes, (int)(end_stream - bytes), 1, (const unsigned char*)"\r\n", 3);
        }
    }
    else
    {
        printf("HTTP    ");
    }
    return end_stream;
}