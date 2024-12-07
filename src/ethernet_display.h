#ifndef ETHERNET_DISPLAY_H
#define ETHERNET_DISPLAY_H

#include <stdint.h>

const unsigned char* display_ethernet_frame(const unsigned char* bytes, uint16_t* ether_type, int verbosity);

#endif