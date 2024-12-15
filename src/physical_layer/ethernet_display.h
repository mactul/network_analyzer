#ifndef ETHERNET_DISPLAY_H
#define ETHERNET_DISPLAY_H

#include <stdint.h>

/**
 * @brief Display the Ethernet header and fill the ether_type variable for the upper layer.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param ether_type A pointer to a uint16_t that will be filled with the ether type parsed.
 * @param verbosity A number between 1 and 3.
 * @return A pointer to the start of the network layer in the packet or NULL if the header was malformed.
 */
const unsigned char* display_ethernet_frame(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* ether_type, int verbosity);

#endif