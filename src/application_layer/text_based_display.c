#include <stdio.h>
#include <stdbool.h>

#include "lib/common.h"
#include "text_based_display.h"


static bool startswith(const unsigned char* bytes, const unsigned char* end_stream, const char* ref)
{
    while(bytes < end_stream && *bytes != '\0' && *ref != '\0' && (char)*bytes == *ref)
    {
        bytes++;
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
        if(startswith(bytes, end_stream, "GET "))
        {
            puts("HTTP: GET");
        }
        else if(startswith(bytes, end_stream, "POST "))
        {
            puts("HTTP: POST");
        }
        else if(startswith(bytes, end_stream, "HEAD "))
        {
            puts("HTTP: HEAD");
        }
        else if(startswith(bytes, end_stream, "OPTIONS "))
        {
            puts("HTTP: OPTIONS");
        }
        else if(startswith(bytes, end_stream, "PUT "))
        {
            puts("HTTP: PUT");
        }
        else if(startswith(bytes, end_stream, "PATCH "))
        {
            puts("HTTP: PATCH");
        }
        else if(startswith(bytes, end_stream, "DELETE "))
        {
            puts("HTTP: DELETE");
        }
        else if(startswith(bytes, end_stream, "CONNECT "))
        {
            puts("HTTP: CONNECT");
        }
        else if(startswith(bytes, end_stream, "TRACE "))
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