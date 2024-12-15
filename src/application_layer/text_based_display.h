#ifndef TEXT_BASED_DISPLAY_H
#define TEXT_BASED_DISPLAY_H

#include <stdint.h>

/**
 * @brief Display a text based protocol.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
const unsigned char* display_text_protocol(const char* name, const unsigned char* bytes, const unsigned char* end_stream, int verbosity);


/**
 * @brief Display a HTTP packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_http(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("HTTP", bytes, end_stream, verbosity);
}


/**
 * @brief Display a HTTPS packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_https(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("HTTPS", bytes, end_stream, verbosity);
}


/**
 * @brief Display a SMTP packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_smtp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("SMTP", bytes, end_stream, verbosity);
}


/**
 * @brief Display a SMTPS packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_smtps(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("SMTPS", bytes, end_stream, verbosity);
}


/**
 * @brief Display a POP packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_pop(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("POP", bytes, end_stream, verbosity);
}


/**
 * @brief Display an IMAP packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_imap(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("IMAP", bytes, end_stream, verbosity);
}


/**
 * @brief Display an IMAPS packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_imaps(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("IMAPS", bytes, end_stream, verbosity);
}


/**
 * @brief Display a FTP packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_ftp(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("FTP", bytes, end_stream, verbosity);
}


/**
 * @brief Display a FTPS packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_ftps(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("FTPS", bytes, end_stream, verbosity);
}


/**
 * @brief Display a Telnet packet.
 * 
 * @param bytes A pointer to the start of the packet.
 * @param end_stream A pointer to the end of the packet.
 * @param verbosity A number between 1 and 3.
 * @return end_stream or NULL if the header was malformed.
 */
static inline const unsigned char* display_telnet(const unsigned char* bytes, const unsigned char* end_stream, int verbosity)
{
    return display_text_protocol("Telnet", bytes, end_stream, verbosity);
}

#endif