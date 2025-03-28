/**
 * @file common.c
 * @author Macéo Tuloup
 * @brief This file contains useful display functions that are used across multiple files of the project.
 * @version 1.0.0
 * @date 2024-12-20
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdbool.h>

#include "common.h"


static bool need_highlight(unsigned char byte, const unsigned char* to_highlight, int nb_to_highlight)
{
    for(int i = 0; i < nb_to_highlight; i++)
    {
        if(byte == to_highlight[i])
        {
            return true;
        }
    }
    return false;
}


void display_hardware_addr(const uint8_t* addr, uint8_t len)
{
    for(uint8_t i = 0; i < len-1; i++)
    {
        printf("%02x:", addr[i]);
    }
    printf("%02x", addr[len-1]);
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

static void display_byte_highlighted(unsigned char byte)
{
    if(byte >= ' ' && byte <= '~')
    {
        printf("\033[31m%c\033[0m", byte);
    }
    else
    {
        printf("\033[31m\U000000B7\033[0m");
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

void display_generic_bytes(const unsigned char* bytes, int len, int tab_count, const unsigned char* to_highlight, int nb_to_highlight)
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

    display_n_tabs(tab_count);
    for(int i = 0; i <= len - max_hex; i += max_hex)
    {
        for(int j = 0; j < max_hex; j++)
        {
            if(need_highlight(bytes[i+j], to_highlight, nb_to_highlight))
            {
                printf("\033[31m%02x\033[0m", bytes[i+j]);
            }
            else
            {
                printf("%02x", bytes[i+j]);
            }
            if(j & 0x1)
            {
                putchar(' ');
            }
        }

        for(int j = 0; j < max_hex; j++)
        {
            if(need_highlight(bytes[i+j], to_highlight, nb_to_highlight))
            {
                display_byte_highlighted(bytes[i+j]);
            }
            else
            {
                display_byte(bytes[i+j]);
            }
        }
        putchar('\n');
        display_n_tabs(tab_count);
    }
    for(int i = (len / max_hex) * max_hex; i < len; i++)
    {
        if(need_highlight(bytes[i], to_highlight, nb_to_highlight))
        {
            printf("\033[31m%02x\033[0m", bytes[i]);
        }
        else
        {
            printf("%02x", bytes[i]);
        }
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
        if(need_highlight(bytes[i], to_highlight, nb_to_highlight))
        {
            display_byte_highlighted(bytes[i]);
        }
        else
        {
            display_byte(bytes[i]);
        }
    }

    putchar('\n');
}