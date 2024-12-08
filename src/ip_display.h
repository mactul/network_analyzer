#ifndef IP_DISPLAY_H
#define IP_DISPLAY_H

#include <stdint.h>

const unsigned char* display_ip(const unsigned char* bytes, const unsigned char* end_stream, uint8_t* protocol, int verbosity);

#endif