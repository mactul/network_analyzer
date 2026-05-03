#ifndef SCTP_DISPLAY_H
#define SCTP_DISPLAY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SCTP_INIT_VALUE {}

struct sctp_reentrant {
    const unsigned char* _end_stream_save;
    int _chunk_count;
    bool data_left;
};

static inline void sctp_reentrant_init(struct sctp_reentrant* sctp_reentrant)
{
    sctp_reentrant->_end_stream_save = NULL;
    sctp_reentrant->_chunk_count = 0;
    sctp_reentrant->data_left = 0;
}

/**
 * @brief Take a pointer to the start of a packet and a pointer to a pointer to the end of the packet, display the SCTP header and fill the dest_port and src_port for the upper layer.
 * This function can be reentrant in this case it sets the reentrant pointer and the align_offset pointer and you have to call this function again to get the next data chunk.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to a pointer to the end of the packet.
 * @param dest_port A pointer to a uint16_t that will be filled with the destination port parsed.
 * @param src_port A pointer to a uint16_t that will be filled with the source port parsed.
 * @param verbosity A number between 1 and 3.
 * @param reentrant This should point to a NULL pointer in the first place. In case their is multiple data chunks in the sctp header, this is set to a non-NULL value and this function should be called again.
 * @param align_offset This should point to a 0 integer in the first place. It will be set alongside the reentrant pointer.
 * @return A pointer to the start of the application layer in the packet or NULL if the header was malformed.
 */
const unsigned char* display_sctp(const unsigned char* bytes, const unsigned char** end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity, struct sctp_reentrant* reentrant, int* align_offset);

#endif