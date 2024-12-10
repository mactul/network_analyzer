#include <stdio.h>

#include "lib/common.h"


const unsigned char* display_text_protocol(const char* name, const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    printf("%s", name);
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

    if(bytes < end_stream)
    {
        display_generic_bytes(bytes, (int)(end_stream - bytes), 1);
    }

    return end_stream;
}