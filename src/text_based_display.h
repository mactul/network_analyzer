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

#endif