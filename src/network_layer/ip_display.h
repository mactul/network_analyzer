#ifndef IP_DISPLAY_H
#define IP_DISPLAY_H

#include <stdint.h>

/**
 * @brief Take a pointer to the start of a packet and a pointer to a pointer to the end of the packet, display the IP header, fill the protocol variable for the upper layer and set the end of the stream to eliminate ethernet padding.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to a pointer to the end of the packet.
 * @param protocol A pointer to a uint8_t that will be filled with the protocol parsed.
 * @param verbosity A number between 1 and 3.
 * @return A pointer to the start of the transport layer in the packet or NULL if the header was malformed.
 */
const unsigned char* display_ip(const unsigned char* bytes, const unsigned char** end_stream, uint8_t* protocol, int verbosity);

#endif