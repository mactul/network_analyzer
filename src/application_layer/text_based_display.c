#include <stdio.h>

#include "lib/common.h"


const unsigned char* display_text_protocol(const char* name, const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
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
        display_generic_bytes(bytes, (int)(end_stream - bytes), 1);
    }
    else
    {
        putchar('\n');
    }

    return end_stream;
}