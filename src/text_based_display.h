#ifndef TEXT_BASED_DISPLAY_H
#define TEXT_BASED_DISPLAY_H

#include <stdint.h>

const unsigned char* display_text_protocol(const char* name, const unsigned char* bytes, const unsigned char* end_stream, int verbosity);

static inline const unsigned char* display_http(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("HTTP", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_https(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("HTTPS", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_smtp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("SMTP", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_smtps(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("SMTPS", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_pop(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("POP", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_imap(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("IMAP", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_imaps(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("IMAPS", bytes, end_stream, verbosity);
}

static inline const unsigned char* display_telnet(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("Telnet", bytes, end_stream, verbosity);
}

#endif