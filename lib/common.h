#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

/**
 * @brief Display a byte if it's a printable ascii char, else display an UTF-8 dot
 * 
 * @param byte the byte to print
 */
void display_byte(unsigned char byte);


/**
 * @brief Display at least `max_len` bytes of the string `str` either with printable ascii chars or with dots.
 * 
 * @param str the NULL terminated string to display
 * @param max_len The maximum number to display
 */
void display_string(const unsigned char* str, int max_len);


/**
 * @brief Display a chunk of bytes like a hexdump, with hexadecimal values on the left and printable characters on the right.  
 * The number of columns displayed is the biggest power of 2 that fit in the screen.
 * 
 * @param bytes The bytes to display.
 * @param len The number of bytes to display.
 * @param tab_count How many indentations should the function put before each line.
 */
void display_generic_bytes(const unsigned char* bytes, int len, int tab_count);


/**
 * @brief Display an address in the mac addr format, but even if the address has more or less than 6 bytes.
 * 
 * @param addr The address to display.
 * @param len The number of bytes the address have.
 */
void display_hardware_addr(const uint8_t* addr, uint8_t len);

#endif