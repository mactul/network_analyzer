#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "common.h"
#include "transport_display.h"

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

const char* sctp_types_lookup[] = {"DATA", "INIT", "INIT ACK", "SACK", "HEARTBEAT", "HEARTBEAT_ACK", "ABORT", "SHUTDOWN", "SHUTDOWN ACK", "OPERATION ERROR", "COOKIE ECHO", "COOKIE ACK", "ECNE", "CWR", "SHUTDOWN COMPLETE"};


const unsigned char* display_udp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity)
{
    if(bytes + sizeof(struct udphdr) > end_stream)
    {
        return NULL;
    }

    const struct udphdr* udp = (const struct udphdr*)bytes;
    *dest_port = ntohs(udp->uh_dport);
    *src_port = ntohs(udp->uh_sport);
    if(verbosity <= 2)
    {
        printf("UDP: src_port=%d dst_port=%d", *src_port, *dest_port);
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
        printf("UDP:\n");
        printf("\tSource port: %u\n", *src_port);
        printf("\tDestination port: %u\n", *dest_port);
        printf("\tLength: %u\n", ntohs(udp->uh_ulen));
        printf("\tChecksum: 0x%04x\n", ntohs(udp->uh_sum));
    }
    return bytes + sizeof(struct udphdr);
}

const unsigned char* display_tcp(const unsigned char* bytes, const unsigned char* end_stream, uint16_t* dest_port, uint16_t* src_port, int verbosity)
{
    if(bytes + sizeof(struct tcphdr) > end_stream)
    {
        return NULL;
    }

    const struct tcphdr* tcp = (const struct tcphdr*)bytes;

    if(bytes + 4 * tcp->th_off > end_stream)
    {
        return NULL;
    }

    *dest_port = ntohs(tcp->th_dport);
    *src_port = ntohs(tcp->th_sport);

    if(verbosity <= 2)
    {
        printf("TCP: src_port=%d dst_port=%d", *src_port, *dest_port);
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
        printf("TCP:\n");
        printf("\tSource port: %u\n", *src_port);
        printf("\tDestination port: %u\n", *dest_port);
        printf("\tSequence Number: 0x%08x\n", ntohl(tcp->th_seq));
        if(tcp->ack)
            printf("\tAck Number: 0x%08x\n", ntohl(tcp->th_ack));
        printf("\tData Offset: %d\n", tcp->th_off);
        printf("\tFlags: %d (CWR=%d ECE=%d URG=%d ACK=%d PSH=%d RST=%d SYN=%d FIN=%d)\n", tcp->th_flags, tcp->res2 >> 1, tcp->res2 & 0x1, tcp->urg, tcp->ack, tcp->psh, tcp->rst, tcp->syn, tcp->fin);
        printf("\tWindow: %d\n", ntohs(tcp->th_win));
        printf("\tChecksum: 0x%04x\n", ntohs(tcp->th_sum));
        printf("\tUrgent Pointer: %d\n", ntohs(tcp->th_urp));
    }

    return bytes + tcp->th_off * 4;
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

            case SCTP_INIT:
            case SCTP_INIT_ACK:
                if(rounded_chunk_length < sizeof(struct sctp_init_hdr) + sizeof(struct sctp_chunk_hdr))
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
                    if(rounded_chunk_length > sizeof(struct sctp_init_hdr))
                    {
                        printf("\t\tTLV parameters:\n");
                        display_generic_bytes(bytes + sizeof(struct sctp_chunk_hdr) + sizeof(struct sctp_init_hdr), rounded_chunk_length - (uint16_t)sizeof(struct sctp_init_hdr), 3);
                    }
                }
                bytes += rounded_chunk_length;
                break;

            case SCTP_SACK:
                if(rounded_chunk_length < sizeof(struct sctp_sack_hdr) + sizeof(struct sctp_chunk_hdr))
                {
                    return NULL;
                }
                {
                    const struct sctp_sack_hdr* sctp_sack = (const struct sctp_sack_hdr*)(bytes + sizeof(struct sctp_chunk_hdr));
                    uint16_t gap_ack_blocks_nb = ntohs(sctp_sack->gap_ack_blocks_nb);
                    uint16_t duplicate_tsn_nb = ntohs(sctp_sack->duplicate_tsn_nb);
                    if(rounded_chunk_length < sizeof(struct sctp_sack_hdr) + sizeof(struct sctp_chunk_hdr) + sizeof(uint32_t) * (gap_ack_blocks_nb + duplicate_tsn_nb))
                    {
                        return NULL;
                    }
                    if(verbosity > 2)
                    {
                        printf("\t\tCumulative TSN Ack: 0x%08x\n", ntohl(sctp_sack->cumulative_tsn_ack));
                        printf("\t\tAdvertised Receiver Window Credit: %u\n", ntohl(sctp_sack->a_rwnd));
                        printf("\t\tNumber of Gap Ack Blocks: %d\n", gap_ack_blocks_nb);
                        printf("\t\tNumber of Duplicate TSNs: %d\n", duplicate_tsn_nb);
                    }
                }
                bytes += rounded_chunk_length;
                break;

            default:
                if(verbosity > 2)
                {
                    printf("\tUnknown SCTP chunk - skipping\n");
                }
                bytes += rounded_chunk_length;
        }
    }

    if(bytes != *end_stream)
    {
        return NULL;
    }

    return bytes;
}


const unsigned char* display_icmp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    if(bytes + 4 > end_stream)
    {
        return NULL;
    }

    const struct icmphdr* icmp = (const struct icmphdr*)bytes;

    printf("ICMP");
    if(verbosity <= 1)
    {
        printf("    ");
    }
    else
    {
        if(verbosity > 2)
        {
            putchar(':');
        }
        putchar('\n');
    }

    if(verbosity > 2)
    {
        printf("\tType: %d\n", icmp->type);
        printf("\tCode: %d\n", icmp->code);
        printf("\tChecksum: 0x%04x\n", icmp->checksum);
    }

    return bytes + 4;
}