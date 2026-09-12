// Host-only test: gcc -o /tmp/test_dns_wire dns_wire.c test/test_dns_wire.c && /tmp/test_dns_wire
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/dns_wire.h"

// A real "A? example.com" query captured on the wire: txid 0x1234, standard
// query, RD=1, one question, QNAME=example.com, QTYPE=A(1), QCLASS=IN(1).
static const uint8_t kQueryExampleComA[] = {
    0x12, 0x34, // txid
    0x01, 0x00, // flags: RD=1
    0x00, 0x01, // qdcount=1
    0x00, 0x00, // ancount
    0x00, 0x00, // nscount
    0x00, 0x00, // arcount
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    3, 'c', 'o', 'm',
    0x00,       // end of name
    0x00, 0x01, // qtype A
    0x00, 0x01, // qclass IN
};

static void test_txid_roundtrip(void)
{
    uint8_t buf[4] = {0, 0, 0, 0};
    dns_wire_set_txid(buf, sizeof(buf), 0xBEEF);
    assert(dns_wire_get_txid(buf, sizeof(buf)) == 0xBEEF);
    assert(buf[0] == 0xBE && buf[1] == 0xEF);
}

static void test_parse_question_basic(void)
{
    dns_wire_question_t q;
    bool ok = dns_wire_parse_question(kQueryExampleComA, sizeof(kQueryExampleComA), &q);
    assert(ok);
    assert(q.txid == 0x1234);
    assert(q.qtype == 1);
    assert(q.qclass == 1);
    assert(strcmp(q.qname, "example.com") == 0);
}

static void test_parse_question_lowercases(void)
{
    uint8_t buf[sizeof(kQueryExampleComA)];
    memcpy(buf, kQueryExampleComA, sizeof(buf));
    // uppercase the 'e' in "example" (byte 12 is the label-length prefix, 13 is 'e')
    buf[13] = 'E';
    dns_wire_question_t q;
    assert(dns_wire_parse_question(buf, sizeof(buf), &q));
    assert(strcmp(q.qname, "example.com") == 0);
}

static void test_parse_question_truncated_rejected(void)
{
    dns_wire_question_t q;
    // cut off mid-label
    assert(!dns_wire_parse_question(kQueryExampleComA, 15, &q));
    // cut off right before qtype/qclass
    assert(!dns_wire_parse_question(kQueryExampleComA, 20, &q));
}

static void test_parse_question_no_question_rejected(void)
{
    uint8_t buf[DNS_WIRE_HEADER_LEN] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    dns_wire_question_t q;
    assert(!dns_wire_parse_question(buf, sizeof(buf), &q));
}

static void test_parse_question_rejects_compression_pointer(void)
{
    uint8_t buf[DNS_WIRE_HEADER_LEN + 2] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x0C, // a compression pointer where a label length was expected
    };
    dns_wire_question_t q;
    assert(!dns_wire_parse_question(buf, sizeof(buf), &q));
}

static void test_make_error_response_sets_qr_and_rcode(void)
{
    uint8_t buf[sizeof(kQueryExampleComA)];
    memcpy(buf, kQueryExampleComA, sizeof(buf));
    dns_wire_make_error_response(buf, sizeof(buf), DNS_RCODE_SERVFAIL);
    assert((buf[2] & 0x80) != 0);      // QR set
    assert((buf[2] & 0x01) != 0);      // RD preserved
    assert((buf[3] & 0x0F) == DNS_RCODE_SERVFAIL);
    // question section (and txid) must be untouched so the response echoes the query
    assert(memcmp(buf, kQueryExampleComA, DNS_WIRE_HEADER_LEN) != 0); // flags byte changed...
    assert(memcmp(buf + DNS_WIRE_HEADER_LEN, kQueryExampleComA + DNS_WIRE_HEADER_LEN,
                   sizeof(buf) - DNS_WIRE_HEADER_LEN) == 0); // ...but not the question
    assert(dns_wire_get_txid(buf, sizeof(buf)) == 0x1234);
}

static void test_zero_answer_a_record(void)
{
    uint8_t buf[64];
    memcpy(buf, kQueryExampleComA, sizeof(kQueryExampleComA));
    size_t new_len = dns_wire_make_zero_answer(buf, sizeof(kQueryExampleComA), sizeof(buf), DNS_TYPE_A);
    assert(new_len == sizeof(kQueryExampleComA) + 2 + 2 + 2 + 4 + 2 + 4);
    assert((buf[2] & 0x80) != 0);              // QR set
    assert((buf[3] & 0x0F) == DNS_RCODE_NOERROR);
    assert(buf[6] == 0x00 && buf[7] == 0x01);  // ANCOUNT = 1
    // answer record: name ptr, type, class, ttl(4), rdlength, 4 zero bytes
    const uint8_t *ans = buf + sizeof(kQueryExampleComA);
    assert(ans[0] == 0xC0 && ans[1] == 0x0C);
    assert(ans[2] == 0x00 && ans[3] == 0x01);  // type A
    assert(ans[4] == 0x00 && ans[5] == 0x01);  // class IN
    assert(ans[10] == 0x00 && ans[11] == 0x04); // rdlength = 4
    assert(ans[12] == 0 && ans[13] == 0 && ans[14] == 0 && ans[15] == 0); // 0.0.0.0
}

static void test_zero_answer_rejects_unsupported_qtype(void)
{
    uint8_t buf[64];
    memcpy(buf, kQueryExampleComA, sizeof(kQueryExampleComA));
    // qtype 16 = TXT, not A/AAAA - should refuse rather than fabricate an answer
    assert(dns_wire_make_zero_answer(buf, sizeof(kQueryExampleComA), sizeof(buf), 16) == 0);
}

static void test_zero_answer_rejects_insufficient_buffer(void)
{
    uint8_t buf[sizeof(kQueryExampleComA)];
    memcpy(buf, kQueryExampleComA, sizeof(buf));
    assert(dns_wire_make_zero_answer(buf, sizeof(buf), sizeof(buf), DNS_TYPE_A) == 0);
}

int main(void)
{
    test_txid_roundtrip();
    test_parse_question_basic();
    test_parse_question_lowercases();
    test_parse_question_truncated_rejected();
    test_parse_question_no_question_rejected();
    test_parse_question_rejects_compression_pointer();
    test_make_error_response_sets_qr_and_rcode();
    test_zero_answer_a_record();
    test_zero_answer_rejects_unsupported_qtype();
    test_zero_answer_rejects_insufficient_buffer();
    printf("all dns_wire tests passed\n");
    return 0;
}
