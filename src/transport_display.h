#ifndef TRANSPORT_DISPLAY_H
#define TRANSPORT_DISPLAY_H

#include <stdint.h>

const unsigned char* display_udp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity);
const unsigned char* display_tcp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity);
const unsigned char* display_sctp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity);
const unsigned char* display_icmp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity);

#endif