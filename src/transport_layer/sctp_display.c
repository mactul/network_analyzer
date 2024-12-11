#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#include "lib/common.h"
#include "sctp_display.h"

#define NEXT_MULTIPLE(x, m) ((((x)+((m)-1)) / (m)) * (m))

struct sctphdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verif_tag;
    uint32_t checksum;
};

struct sctp_chunk_hdr {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
};

struct sctp_init_hdr {
    uint32_t initiate_tag;
    uint32_t a_rwnd;
    uint16_t outbound_streams_nb;
    uint16_t inbound_streams_nb;
    uint32_t initial_tsn;
};

struct sctp_data_hdr {
    uint32_t tsn;
    uint16_t stream_id;
    uint16_t stream_sequence_nb;
    uint32_t payload_protocol_id;
};

struct sctp_sack_hdr {
    uint32_t cumulative_tsn_ack;
    uint32_t a_rwnd;
    uint16_t gap_ack_blocks_nb;
    uint16_t duplicate_tsn_nb;
};

enum SCTP_TYPES {
    SCTP_DATA = 0,
    SCTP_INIT = 1,
    SCTP_INIT_ACK = 2,
    SCTP_SACK = 3,
    SCTP_HEARTBEAT = 4,
    SCTP_HEARTBEAT_ACK = 5,
    SCTP_ABORT = 6,
    SCTP_SHUTDOWN = 7,
    SCTP_SHUTDOWN_ACK = 8,
    SCTP_OPERATION_ERROR = 9,
    SCTP_COOKIE_ECHO = 10,
    SCTP_COOKIE_ACK = 11,
    SCTP_SHUTDOWN_COMPLETE = 14,
    SCTP_TYPES_NB
};

enum SCTP_TLV_TYPES {
    SCTP_TLV_IPV4_ADDRESS = 5,
    SCTP_TLV_IPV6_ADDRESS = 6,
    SCTP_TLV_STATE_COOKIE = 7,
};

const char* sctp_types_lookup[] = {"DATA", "INIT", "INIT ACK", "SACK", "HEARTBEAT", "HEARTBEAT ACK", "ABORT", "SHUTDOWN", "SHUTDOWN ACK", "OPERATION ERROR", "COOKIE ECHO", "COOKIE ACK", "ECNE", "CWR", "SHUTDOWN COMPLETE"};


bool display_chunk_tlv(const unsigned char* bytes, const unsigned char* end_stream)
{
    while(bytes < end_stream)
    {
        if(bytes + 2 * sizeof(uint16_t) > end_stream)
        {
            return false;
        }
        uint16_t type = ntohs(*((uint16_t*)bytes));
        bytes += sizeof(uint16_t);
        uint16_t length = ntohs(*((uint16_t*)bytes));
        bytes += sizeof(uint16_t);

        if(length < 2 * sizeof(uint16_t))
        {
            return false;
        }
        length -= 2 * (uint16_t)sizeof(uint16_t);
        uint16_t rounded_length = (uint16_t)NEXT_MULTIPLE(length, 4);

        if(bytes + rounded_length > end_stream)
        {
            return false;
        }
        printf("\t\t\tType: %d", type);
        switch(type)
        {
            case SCTP_TLV_STATE_COOKIE:
                printf(" (State Cookie)");
                break;
            case SCTP_TLV_IPV4_ADDRESS:
                printf(" (IPv4 Address)");
                break;
            case SCTP_TLV_IPV6_ADDRESS:
                printf(" (IPv6 Address)");
                break;
        }
        printf("\n\t\t\tLength: %d\n", length);
        printf("\t\t\tValue:");
        switch(type)
        {
            char buffer[INET6_ADDRSTRLEN];

            case SCTP_TLV_IPV4_ADDRESS:
                if(length != 4)
                    return false;
                printf(" %s\n", inet_ntop(AF_INET, bytes, buffer, INET_ADDRSTRLEN));
                break;

            case SCTP_TLV_IPV6_ADDRESS:
                if(length != 16)
                    return false;
                printf(" %s\n", inet_ntop(AF_INET6, bytes, buffer, INET6_ADDRSTRLEN));
                break;

            default:
                putchar('\n');
                display_generic_bytes(bytes, length, 4);
        }

        bytes += rounded_length;
    }

    if(bytes != end_stream)
    {
        return false;
    }

    return true;
}


static const unsigned char* display_sctp_data(const unsigned char* bytes, const unsigned char** end_stream, uint16_t rounded_chunk_length, uint16_t chunk_length, int verbosity, const unsigned char** reentrant, int* align_offset)
{
    if(rounded_chunk_length < sizeof(struct sctp_data_hdr) + sizeof(struct sctp_chunk_hdr))
    {
        return NULL;
    }
    if(verbosity > 2)
    {
        const struct sctp_data_hdr* sctp_data = (const struct sctp_data_hdr*)(bytes + sizeof(struct sctp_chunk_hdr));
        printf("\t\tTSN: 0x%08x\n", ntohl(sctp_data->tsn));
        printf("\t\tStream Identifier: 0x%04x\n", ntohs(sctp_data->stream_id));
        printf("\t\tStream Sequence Number: %d\n", ntohs(sctp_data->stream_sequence_nb));
        // According to the RFC, this field isn't touched by the sctp implementation and is not necessary big endian. https://datatracker.ietf.org/doc/html/rfc4960#section-3.3.1
        printf("\t\tPayload Protocol Identifier: big_endian: 0x%08x untouched: 0x%08x\n", ntohl(sctp_data->payload_protocol_id), sctp_data->payload_protocol_id);
    }
    bytes += sizeof(struct sctp_data_hdr) + sizeof(struct sctp_chunk_hdr);
    uint16_t data_length = rounded_chunk_length - (uint16_t)sizeof(struct sctp_data_hdr) - (uint16_t)sizeof(struct sctp_chunk_hdr);
    if(*end_stream < bytes + data_length)
    {
        return NULL;
    }
    if(*end_stream > bytes + data_length)
    {
        // There is some data left, maybe their is multiple data chunk, we need to treat this packet then re-enter into this function.
        *reentrant = *end_stream;
    }
    *end_stream = bytes + chunk_length - (uint16_t)sizeof(struct sctp_data_hdr) - (uint16_t)sizeof(struct sctp_chunk_hdr);
    *align_offset = rounded_chunk_length - chunk_length;
    return bytes;
}


static const unsigned char* display_sctp_init(const unsigned char* bytes, uint16_t chunk_length, int verbosity)
{
    if(chunk_length < sizeof(struct sctp_init_hdr) + sizeof(struct sctp_chunk_hdr))
    {
        return NULL;
    }
    if(verbosity > 2)
    {
        const struct sctp_init_hdr* sctp_init = (const struct sctp_init_hdr*)(bytes + sizeof(struct sctp_chunk_hdr));
        printf("\t\tInitiate Tag: 0x%08x\n", ntohl(sctp_init->initiate_tag));
        printf("\t\tAdvertised Receiver Window Credit: %u\n", ntohl(sctp_init->a_rwnd));
        printf("\t\tNumber of outbound streams: %d\n", ntohs(sctp_init->outbound_streams_nb));
        printf("\t\tNumber of inbound streams: %d\n", ntohs(sctp_init->inbound_streams_nb));
        printf("\t\tInitial TSN: 0x%08x\n", ntohl(sctp_init->initial_tsn));
        if(chunk_length > sizeof(struct sctp_init_hdr) + sizeof(struct sctp_chunk_hdr))
        {
            printf("\t\tTLV parameters:\n");
            if(!display_chunk_tlv(bytes + sizeof(struct sctp_chunk_hdr) + sizeof(struct sctp_init_hdr), bytes + chunk_length - (uint16_t)sizeof(struct sctp_init_hdr)))
            {
                return NULL;
            }
        }
    }
    return bytes;
}


static const unsigned char* display_sctp_heartbeat(const unsigned char* bytes, uint16_t chunk_length, int verbosity)
{
    if(verbosity > 2)
    {
        if(chunk_length > sizeof(struct sctp_chunk_hdr))
        {
            printf("\t\tTLV parameters:\n");
            if(!display_chunk_tlv(bytes + sizeof(struct sctp_chunk_hdr), bytes + chunk_length))
            {
                return NULL;
            }
        }
    }
    return bytes;
}


static const unsigned char* display_sctp_sack(const unsigned char* bytes, uint16_t chunk_length, int verbosity)
{
    if(chunk_length < sizeof(struct sctp_sack_hdr) + sizeof(struct sctp_chunk_hdr))
    {
        return NULL;
    }
    const struct sctp_sack_hdr* sctp_sack = (const struct sctp_sack_hdr*)(bytes + sizeof(struct sctp_chunk_hdr));
    uint16_t gap_ack_blocks_nb = ntohs(sctp_sack->gap_ack_blocks_nb);
    uint16_t duplicate_tsn_nb = ntohs(sctp_sack->duplicate_tsn_nb);
    if(chunk_length < sizeof(struct sctp_sack_hdr) + sizeof(struct sctp_chunk_hdr) + sizeof(uint32_t) * (gap_ack_blocks_nb + duplicate_tsn_nb))
    {
        return NULL;
    }
    if(verbosity > 2)
    {
        printf("\t\tCumulative TSN Ack: 0x%08x\n", ntohl(sctp_sack->cumulative_tsn_ack));
        printf("\t\tAdvertised Receiver Window Credit: %u\n", ntohl(sctp_sack->a_rwnd));
        printf("\t\tNumber of Gap Ack Blocks: %d\n", gap_ack_blocks_nb);
        printf("\t\tNumber of Duplicate TSNs: %d\n", duplicate_tsn_nb);
        const uint8_t* gap_bytes = bytes + sizeof(struct sctp_chunk_hdr) + sizeof(struct sctp_sack_hdr);
        for(int i = 0; i < gap_ack_blocks_nb; i++)
        {
            printf("\t\tGap Ack Block %d Start: %d\n", i+1, ntohs(*((uint16_t*)gap_bytes)));
            gap_bytes += sizeof(uint16_t);
            printf("\t\tGap Ack Block %d End: %d\n", i+1, ntohs(*((uint16_t*)gap_bytes)));
            gap_bytes += sizeof(uint16_t);
        }
        for(int i = 0; i < duplicate_tsn_nb; i++)
        {
            printf("\t\tDuplicate TSN %d: 0x%08x\n", i+1, ntohl(*((uint32_t*)gap_bytes)));
            gap_bytes += sizeof(uint32_t);
        }
    }
    return bytes;
}


const unsigned char* display_sctp(const unsigned char* bytes, const unsigned char** end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity, const unsigned char** reentrant, int* align_offset)
{
    static int chunk_count = 0;
    if(*reentrant)
    {
        bytes = *end_stream + *align_offset;
        *end_stream = *reentrant;
        *reentrant = NULL;
        goto READ_CHUNKS;
    }
    if(bytes + sizeof(struct sctphdr) + sizeof(struct sctp_chunk_hdr) > *end_stream)
    {
        return NULL;
    }

    const struct sctphdr* sctp = (const struct sctphdr*)bytes;
    *dest_port = ntohs(sctp->dst_port);
    *src_port = ntohs(sctp->src_port);

    if(verbosity <= 2)
    {
        printf("SCTP: src_port=%d dst_port=%d", *src_port, *dest_port);
        if(verbosity <= 1)
        {
            printf("    ");
        }
        else
        {
            putchar('\n');
        }
    }
    else
    {
        printf("SCTP:\n");
        printf("\tSource port: %d\n", *src_port);
        printf("\tDestination port: %d\n", *dest_port);
        printf("\tVerification tag: 0x%08x\n", ntohl(sctp->verif_tag));
        printf("\tChecksum: 0x%08x\n", ntohl(sctp->checksum));
    }

    bytes += sizeof(struct sctphdr);

    chunk_count = 0;
READ_CHUNKS:
    *align_offset = 0;
    while(bytes < *end_stream)
    {
        if(bytes + sizeof(struct sctp_chunk_hdr) > *end_stream)
        {
            return NULL;
        }
        const struct sctp_chunk_hdr* chunk = (const struct sctp_chunk_hdr*)bytes;
        uint16_t chunk_length = ntohs(chunk->length);
        uint16_t rounded_chunk_length = (uint16_t)NEXT_MULTIPLE(chunk_length, 4);
        if(rounded_chunk_length == 0)
        {
            return NULL;
        }
        if(bytes + rounded_chunk_length > *end_stream)
        {
            return NULL;
        }
        if(verbosity > 2)
        {
            chunk_count++;
            printf("\tChunk %d:\n", chunk_count);
            if(chunk->type < SCTP_TYPES_NB)
            {
                printf("\t\tType: %d (%s)\n", chunk->type, sctp_types_lookup[chunk->type]);
            }
            else
            {
                printf("\t\tType: %d\n", chunk->type);
            }
            printf("\t\tFlags: %02x\n", chunk->flags);
            printf("\t\tLength: %d\n", ntohs(chunk->length));
        }
        switch(chunk->type)
        {
            case SCTP_DATA:
                return display_sctp_data(bytes, end_stream, rounded_chunk_length, chunk_length, verbosity, reentrant, align_offset);

            case SCTP_INIT:
            case SCTP_INIT_ACK:
                if((bytes = display_sctp_init(bytes, chunk_length, verbosity)) == NULL)
                {
                    return NULL;
                }
                break;

            case SCTP_SACK:
                if((bytes = display_sctp_sack(bytes, chunk_length, verbosity)) == NULL)
                {
                    return NULL;
                }
                break;

            case SCTP_COOKIE_ECHO:
                if(verbosity > 2)
                {
                    printf("\t\tState Cookie:\n");
                    display_generic_bytes(bytes + sizeof(struct sctp_chunk_hdr), chunk_length - (uint16_t)sizeof(struct sctp_chunk_hdr), 3);
                }
                break;

            case SCTP_HEARTBEAT:
            case SCTP_HEARTBEAT_ACK:
                if((bytes = display_sctp_heartbeat(bytes, chunk_length, verbosity)) == NULL)
                {
                    return NULL;
                }
                break;

            case SCTP_SHUTDOWN:
                if(chunk_length != sizeof(struct sctp_chunk_hdr) + sizeof(uint32_t))
                {
                    return NULL;
                }
                if(verbosity > 2)
                {
                    printf("\t\tCumulative TSN Ack: 0x%08x\n", ntohl(*((uint32_t*)(bytes + sizeof(struct sctp_chunk_hdr)))));
                }
                break;

            default:
                if(verbosity > 2 && chunk_length > sizeof(struct sctp_chunk_hdr))
                {
                    printf("\t\tData:\n");
                    display_generic_bytes(bytes + sizeof(struct sctp_chunk_hdr), chunk_length - (uint16_t)sizeof(struct sctp_chunk_hdr), 3);
                }
        }
        bytes += rounded_chunk_length;
    }

    if(bytes != *end_stream)
    {
        return NULL;
    }

    return bytes;
}
