#ifndef DECAPSULATION_H
#define DECAPSULATION_H

/**
 * @brief Takes a pointer to a network packet and a pointer to the end of this packet and display every protocol in this packet.
 * 
 * @param left_bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3. 1 -> one line by packet, 2 -> one line by protocol, 3 -> full display.
 */
void decapsulation(const unsigned char* left_bytes, const unsigned char* end_stream, int verbosity);

#endif