#ifndef ICMP_DISPLAY_H
#define ICMP_DISPLAY_H

#include <stdint.h>

const unsigned char* display_icmp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity);

#endif