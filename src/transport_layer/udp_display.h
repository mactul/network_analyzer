#ifndef UDP_DISPLAY_H
#define UDP_DISPLAY_H

#include <stdint.h>

const unsigned char* display_udp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity);

#endif