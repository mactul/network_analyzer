#ifndef ICMP_DISPLAY_H
#define ICMP_DISPLAY_H

#include <stdint.h>


/**
 * @brief Display the ICMP header.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return A pointer to the data carried in the icmp packet or NULL if the header was malformed.
 */
const unsigned char* display_icmp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity);
const unsigned char* display_icmp6(const unsigned char* bytes, const unsigned char* end_stream, int verbosity);

#endif