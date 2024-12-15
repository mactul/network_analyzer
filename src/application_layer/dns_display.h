#ifndef DNS_DISPLAY_H
#define DNS_DISPLAY_H

/**
 * @brief Display the DNS header.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return A pointer to the bytes following the DNS header in the packet or NULL if the header was malformed.
 */
const unsigned char* display_dns(const unsigned char* bytes, const unsigned char* end_stream, int verbosity);

#endif