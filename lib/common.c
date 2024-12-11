#include <stdio.h>
#include <sys/ioctl.h>

#include "common.h"


void display_hardware_addr(const uint8_t* addr, uint8_t len)
{
    for(uint8_t i = 0; i < len-1; i++)
    {
        printf("%x:", addr[i]);
    }
    printf("%x", addr[len-1]);
}


void display_byte(unsigned char byte)
{
    if(byte >= ' ' && byte <= '~')
    {
        putchar(byte);
    }
    else
    {
        printf("\U000000B7");
    }
}

void display_string(const unsigned char* str, int max_len)
{
    while(max_len > 0 && *str)
    {
        display_byte(*str);
        str++;
        max_len--;
    }
}

void display_generic_bytes(const unsigned char* bytes, int len, int tab_count)
{
    struct winsize w;
    ioctl(0, TIOCGWINSZ, &w);

    // nb_col = len(\t) * tab_count + 2 * ideal_max_hex + 1 + ideal_max_hex
    // ideal_max_hex = (nb_col - 1 - len(\t) * tab_count) / 3.5

    // We calculate the maximum power of 2 as the number of hex numbers we can print per line for everything to fit in the console.
    int max_hex = 1;
    while(max_hex <= 2 * (w.ws_col - 1 - 8 * tab_count) / 7)
    {
        max_hex *= 2;
    }
    if(max_hex > 1)
        max_hex /= 2;

    for(int i = 0; i < tab_count; i++)
    {
        putchar('\t');
    }
    for(int i = 0; i <= len - max_hex; i += max_hex)
    {
        for(int j = 0; j < max_hex; j++)
        {
            printf("%02x", bytes[i+j]);
            if(j & 0x1)
            {
                putchar(' ');
            }
        }

        for(int j = 0; j < max_hex; j++)
        {
            display_byte(bytes[i+j]);
        }
        putchar('\n');
        for(int j = 0; j < tab_count; j++)
        {
            putchar('\t');
        }
    }
    for(int i = (len / max_hex) * max_hex; i < len; i++)
    {
        printf("%02x", bytes[i]);
        if(i & 0x1)
        {
            putchar(' ');
        }
    }
    if(len % 2 == 1)
    {
        putchar(' ');
    }
    for(int i = 0; i < max_hex - len % max_hex; i++)
    {
        printf("  ");
        if(i & 0x1)
        {
            putchar(' ');
        }
    }
    for(int i = (len / max_hex) * max_hex; i < len; i++)
    {
        display_byte(bytes[i]);
    }

    putchar('\n');
}