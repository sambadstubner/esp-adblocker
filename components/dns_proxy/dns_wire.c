#include "dns_wire.h"

#include <string.h>

uint16_t dns_wire_get_txid(const uint8_t *buf, size_t len)
{
    (void)len;
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

void dns_wire_set_txid(uint8_t *buf, size_t len, uint16_t txid)
{
    (void)len;
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid & 0xFF);
}

bool dns_wire_parse_question(const uint8_t *buf, size_t len, dns_wire_question_t *out)
{
    if (len < DNS_WIRE_HEADER_LEN) {
        return false;
    }
    uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
    if (qdcount == 0) {
        return false;
    }

    size_t pos = DNS_WIRE_HEADER_LEN;
    size_t name_len = 0;
    out->qname[0] = '\0';

    for (;;) {
        if (pos >= len) {
            return false;
        }
        uint8_t label_len = buf[pos];
        if (label_len == 0) {
            pos += 1;
            break;
        }
        if ((label_len & 0xC0) != 0) {
            return false; // compression pointer: invalid this early, unsupported
        }
        pos += 1;
        if (pos + label_len > len) {
            return false;
        }
        if (name_len > 0) {
            if (name_len + 1 >= DNS_WIRE_MAX_NAME_LEN) {
                return false;
            }
            out->qname[name_len++] = '.';
        }
        for (uint8_t i = 0; i < label_len; i++) {
            if (name_len + 1 >= DNS_WIRE_MAX_NAME_LEN) {
                return false;
            }
            uint8_t c = buf[pos + i];
            if (c >= 'A' && c <= 'Z') {
                c = (uint8_t)(c - 'A' + 'a');
            }
            out->qname[name_len++] = (char)c;
        }
        pos += label_len;
    }
    out->qname[name_len] = '\0';

    if (pos + 4 > len) {
        return false;
    }
    out->qtype = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
    pos += 2;
    out->qclass = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
    pos += 2;
    out->question_end = pos;
    out->txid = dns_wire_get_txid(buf, len);

    return true;
}

void dns_wire_make_error_response(uint8_t *buf, size_t len, uint8_t rcode)
{
    if (len < DNS_WIRE_HEADER_LEN) {
        return;
    }
    // byte 2: QR(0x80) OPCODE(0x78) AA(0x04) TC(0x02) RD(0x01)
    // set QR, clear AA+TC, preserve OPCODE+RD as echoed from the query
    buf[2] = (uint8_t)((buf[2] | 0x80) & ~0x06);
    // byte 3: RA(0x80) Z(0x40) AD(0x20) CD(0x10) RCODE(0x0F)
    buf[3] = (uint8_t)(0x80 | (rcode & 0x0F));
}

size_t dns_wire_make_zero_answer(uint8_t *buf, size_t question_end, size_t buf_cap, uint16_t qtype)
{
    size_t rdlength;
    if (qtype == DNS_TYPE_A) {
        rdlength = 4;
    } else if (qtype == DNS_TYPE_AAAA) {
        rdlength = 16;
    } else {
        return 0;
    }

    size_t answer_len = 2 /* name ptr */ + 2 /* type */ + 2 /* class */ + 4 /* ttl */ + 2 /* rdlength */ + rdlength;
    if (question_end + answer_len > buf_cap) {
        return 0;
    }

    // Truncate to Header+Question, dropping any OPT/other records that
    // followed it in the original query - otherwise the answer we're about
    // to append would land after Additional instead of before it.
    size_t pos = question_end;
    buf[pos++] = 0xC0;
    buf[pos++] = 0x0C; // compression pointer to offset 12: the question's QNAME
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)(qtype & 0xFF);
    buf[pos++] = 0x00;
    buf[pos++] = 0x01; // class IN
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0x3C; // TTL = 60s
    buf[pos++] = (uint8_t)(rdlength >> 8);
    buf[pos++] = (uint8_t)(rdlength & 0xFF);
    memset(buf + pos, 0, rdlength);
    pos += rdlength;

    buf[2] = (uint8_t)((buf[2] | 0x80) & ~0x06); // QR=1, clear AA+TC, keep RD
    buf[3] = 0x80;                               // RA=1, RCODE=NOERROR
    buf[6] = 0x00;
    buf[7] = 0x01; // ANCOUNT = 1
    buf[8] = 0x00;
    buf[9] = 0x00; // NSCOUNT = 0
    buf[10] = 0x00;
    buf[11] = 0x00; // ARCOUNT = 0 - any OPT from the query was dropped above

    return pos;
}
