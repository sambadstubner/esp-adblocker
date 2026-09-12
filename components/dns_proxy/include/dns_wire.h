#pragma once

// Minimal DNS wire-format helpers. Deliberately dependency-free (no ESP-IDF,
// no FreeRTOS) so this can be compiled and unit-tested on the host, same as
// bloom_filter - this is where a subtle off-by-one would otherwise hide.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DNS_WIRE_HEADER_LEN 12
#define DNS_WIRE_MAX_NAME_LEN 255
// Classic DNS-over-UDP message size limit. No EDNS0 support - messages
// larger than this are rejected rather than mishandled.
#define DNS_WIRE_MAX_MSG_LEN 512

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_SERVFAIL 2
#define DNS_RCODE_NXDOMAIN 3

#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28

typedef struct {
    uint16_t txid;
    uint16_t qtype;
    uint16_t qclass;
    size_t question_end; // byte offset just past QCLASS - end of Header+Question, before any OPT/other records
    char qname[DNS_WIRE_MAX_NAME_LEN]; // dotted, lowercased, NUL-terminated
} dns_wire_question_t;

/** Reads the 16-bit transaction ID from the start of a DNS message. Caller must ensure len >= 2. */
uint16_t dns_wire_get_txid(const uint8_t *buf, size_t len);

/** Overwrites the 16-bit transaction ID in place. Caller must ensure len >= 2. */
void dns_wire_set_txid(uint8_t *buf, size_t len, uint16_t txid);

/**
 * Parses the header and first question of a DNS message (for logging/blocking
 * decisions - does not modify buf). Returns false if the message is too short,
 * has no question, or the name uses a compression pointer (invalid this early
 * in a message, and query messages should never need one).
 */
bool dns_wire_parse_question(const uint8_t *buf, size_t len, dns_wire_question_t *out);

/**
 * Turns a query message into a minimal response, in place: sets the QR bit,
 * clears AA/TC, sets RA, and writes rcode into the RCODE field. Leaves the
 * question section (and length) untouched, so the response correctly echoes
 * the original question. ANCOUNT is not touched - callers producing a
 * with-answer response must additionally patch ANCOUNT and append records.
 */
void dns_wire_make_error_response(uint8_t *buf, size_t len, uint8_t rcode);

/**
 * Turns a query message into a minimal "zero address" answer response
 * (0.0.0.0 for an A query, :: for AAAA), in place: truncates the message to
 * Header+Question (dropping any OPT/other records that followed the question
 * - e.g. an EDNS0 pseudo-record - since leaving them in place after inserting
 * an answer would put the Answer section after Additional, an invalid wire
 * layout), appends the answer via a standard name-compression pointer back to
 * the question, and flips the header into a NOERROR response with ANCOUNT=1,
 * NSCOUNT=0, ARCOUNT=0. question_end (from dns_wire_parse_question) is the
 * offset to truncate to. Returns the new total message length, or 0 if qtype
 * is something other than A/AAAA (nothing sensible to zero-answer) or buf_cap
 * is too small - callers should fall back to dns_wire_make_error_response()
 * with DNS_RCODE_NXDOMAIN in that case.
 */
size_t dns_wire_make_zero_answer(uint8_t *buf, size_t question_end, size_t buf_cap, uint16_t qtype);

#ifdef __cplusplus
}
#endif
