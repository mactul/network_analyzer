#ifndef TCP_DISPLAY_H
#define TCP_DISPLAY_H

#include <stdint.h>

/**
 * @brief Display the TCP header and fill the dest_port and src_port for the upper layer.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param dest_port A pointer to a uint16_t that will be filled with the destination port parsed.
 * @param src_port A pointer to a uint16_t that will be filled with the source port parsed.
 * @param verbosity A number between 1 and 3.
 * @return A pointer to the start of the application layer in the packet or NULL if the header was malformed.
 */
const unsigned char* display_tcp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity);

#endif