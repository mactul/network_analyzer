#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

void display_byte(unsigned char byte);
void display_generic_bytes(const unsigned char* bytes, int len, int tab_count);
void display_hardware_addr(const uint8_t* addr, uint8_t len);

#endif