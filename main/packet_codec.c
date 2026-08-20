#include "packet_codec.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>

#include "miniz.h"

#include "bitchat_ble.h"
#include "bitle_hash.h"
#include "conformance_vectors.h"

static const char *TAG = "packet_codec";

/* Apple's COMPRESSION_ZLIB emits raw DEFLATE (RFC 1951). The decoder also
 * accepts RFC 1950 zlib wrappers for read compatibility. */
static tinfl_decompressor s_inflator;

static uint8_t *inflate_payload_mode(const uint8_t *in, size_t in_len, size_t out_len,
                                     bool parse_zlib)
{
    uint8_t *out = heap_caps_malloc(out_len, MALLOC_CAP_8BIT);
    if (!out) {
        return NULL;
    }
    tinfl_init(&s_inflator);
    size_t consumed = in_len;
    size_t produced = out_len;
    uint32_t flags = TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF |
                     TINFL_FLAG_HAS_MORE_INPUT;
    if (parse_zlib) {
        flags |= TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32;
    }
    tinfl_status status = tinfl_decompress(&s_inflator, in, &consumed, out, out, &produced, flags);
    if (status != TINFL_STATUS_DONE || produced != out_len || consumed != in_len) {
        heap_caps_free(out);
        return NULL;
    }
    return out;
}

static uint8_t *inflate_payload(const uint8_t *in, size_t in_len, size_t out_len)
{
    bool looks_zlib = in_len >= 2 && (in[0] & 0x0f) == 8 &&
                      ((((uint16_t)in[0] << 8) | in[1]) % 31) == 0;
    uint8_t *out = looks_zlib ? inflate_payload_mode(in, in_len, out_len, true) : NULL;
    return out ? out : inflate_payload_mode(in, in_len, out_len, false);
}

static uint8_t read_u8(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 1 > len) {
        *ok = false;
        return 0;
    }
    return data[(*offset)++];
}

static uint16_t read_u16_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 2 > len) {
        *ok = false;
        return 0;
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += 2;
    return value;
}

static uint32_t read_u32_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 4 > len) {
        *ok = false;
        return 0;
    }
    uint32_t value = ((uint32_t)data[*offset] << 24) |
                     ((uint32_t)data[*offset + 1] << 16) |
                     ((uint32_t)data[*offset + 2] << 8) |
                     data[*offset + 3];
    *offset += 4;
    return value;
}

static uint64_t read_u64_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 8 > len) {
        *ok = false;
        return 0;
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | data[*offset + i];
    }
    *offset += 8;
    return value;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static bool decode_hex_fixture(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t length = strlen(hex);
    if ((length & 1) != 0 || length / 2 > out_cap) {
        return false;
    }
    for (size_t i = 0; i < length; i += 2) {
        int high = hex_nibble(hex[i]);
        int low = hex_nibble(hex[i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        out[i / 2] = (uint8_t)((high << 4) | low);
    }
    *out_len = length / 2;
    return true;
}

static size_t relay_wire_len(const uint8_t *data, size_t len)
{
    if (!data || len < 22) {
        return 0;
    }
    uint8_t version = data[0];
    uint8_t flags = data[11];
    size_t header_len;
    size_t payload_len;
    if (version == 1) {
        header_len = 22;
        payload_len = ((size_t)data[12] << 8) | data[13];
    } else if (version == 2 && len >= 24) {
        header_len = 24;
        payload_len = ((size_t)data[12] << 24) |
                      ((size_t)data[13] << 16) |
                      ((size_t)data[14] << 8) |
                      data[15];
    } else {
        return 0;
    }
    size_t wire_len = header_len;
    if (flags & 0x01) {
        wire_len += 8;
    }
    if (version == 2 && (flags & 0x08)) {
        if (wire_len >= len) {
            return 0;
        }
        size_t route_len = 1 + (size_t)data[wire_len] * 8;
        if (route_len > len - wire_len) {
            return 0;
        }
        wire_len += route_len;
    }
    if (wire_len > len) {
        return 0;
    }
    size_t trailer_len = (flags & 0x02) ? 64 : 0;
    if (payload_len > len - wire_len ||
        trailer_len > len - wire_len - payload_len) {
        return 0;
    }
    wire_len += payload_len + trailer_len;
    return wire_len;
}

bool bitchat_relay_fingerprint(const uint8_t *data, size_t len, uint8_t out[16])
{
    size_t canonical_len = relay_wire_len(data, len);
    if (canonical_len < 12 || !out) {
        return false;
    }
    bitle_sha256_ctx_t ctx;
    bitle_sha256_begin(&ctx);
    bitle_sha256_update(&ctx, data, 2);
    const uint8_t zero = 0;
    bitle_sha256_update(&ctx, &zero, 1);
    bitle_sha256_update(&ctx, data + 3, 8);
    const uint8_t canonical_flags = data[11] & (uint8_t)~0x10;
    bitle_sha256_update(&ctx, &canonical_flags, 1);
    if (canonical_len > 12) {
        bitle_sha256_update(&ctx, data + 12, canonical_len - 12);
    }
    uint8_t digest[32];
    bitle_sha256_finish(&ctx, digest);
    memcpy(out, digest, 16);
    return true;
}

bool bitchat_packet_decode(const uint8_t *data, size_t len, bitchat_packet_t *out_packet)
{
    if (!data || !out_packet || len == 0) {
        return false;
    }
    memset(out_packet, 0, sizeof(*out_packet));
    size_t offset = 0;
    bool ok = true;

    out_packet->version = read_u8(data, len, &offset, &ok);
    out_packet->type = read_u8(data, len, &offset, &ok);
    out_packet->ttl = read_u8(data, len, &offset, &ok);
    out_packet->timestamp_ms = read_u64_be(data, len, &offset, &ok);
    uint8_t flags = read_u8(data, len, &offset, &ok);
    uint32_t payload_len = 0;
    if (out_packet->version == 1) {
        payload_len = read_u16_be(data, len, &offset, &ok);
    } else if (out_packet->version == 2) {
        payload_len = read_u32_be(data, len, &offset, &ok);
        out_packet->opaque_only = true;
    } else {
        ok = false;
    }

    if (!ok || payload_len > UINT16_MAX) {
        ESP_LOGW(TAG, "Invalid packet header");
        return false;
    }

    if (offset + sizeof(out_packet->sender_id) > len) {
        ESP_LOGW(TAG, "Missing sender id bytes");
        return false;
    }
    memcpy(out_packet->sender_id, data + offset, sizeof(out_packet->sender_id));
    offset += 8;

    /* zlib-compressed payload (flag 0x04): we cannot inflate it locally, but
     * the header and raw bytes stay usable for time sync and relaying. */
    out_packet->is_compressed = (flags & 0x04) != 0;
    out_packet->is_rsr = (flags & 0x10) != 0;

    if (flags & 0x01) {
        out_packet->has_recipient = true;
        if (offset + sizeof(out_packet->recipient_id) > len) {
            ESP_LOGW(TAG, "Missing recipient id bytes");
            return false;
        }
        memcpy(out_packet->recipient_id, data + offset, sizeof(out_packet->recipient_id));
        offset += 8;
    }

    if (out_packet->version == 2 && (flags & 0x08)) {
        uint8_t route_count = read_u8(data, len, &offset, &ok);
        size_t route_len = (size_t)route_count * 8;
        if (!ok || route_len > len - offset) {
            ESP_LOGW(TAG, "Invalid v2 route");
            return false;
        }
        offset += route_len;
    }

    if (offset + payload_len > len) {
        ESP_LOGW(TAG, "Payload length exceeds buffer");
        return false;
    }

    if (payload_len > 0) {
        out_packet->payload = heap_caps_malloc(payload_len, MALLOC_CAP_8BIT);
        if (!out_packet->payload) {
            ESP_LOGE(TAG, "Failed to allocate payload");
            return false;
        }
        memcpy(out_packet->payload, data + offset, payload_len);
    }
    out_packet->payload_len = (uint16_t)payload_len;
    offset += payload_len;

    /* Compressed payload (v1): [2-byte original size BE][raw deflate].
     * Wrapped zlib is accepted for read compatibility. Every stream must end
     * exactly at the declared input and output boundaries. */
    if (out_packet->is_compressed && !out_packet->opaque_only && payload_len > 2) {
        uint16_t original_len = ((uint16_t)out_packet->payload[0] << 8) | out_packet->payload[1];
        if (original_len > 0) {
            uint8_t *inflated = inflate_payload(out_packet->payload + 2, payload_len - 2, original_len);
            if (inflated) {
                heap_caps_free(out_packet->payload);
                out_packet->payload = inflated;
                out_packet->payload_len = original_len;
                out_packet->is_compressed = false;
            } else {
                ESP_LOGW(TAG, "Failed to inflate payload (%u -> %u)", payload_len, original_len);
                bitchat_packet_free(out_packet);
                return false;
            }
        } else {
            bitchat_packet_free(out_packet);
            return false;
        }
    } else if (out_packet->is_compressed && !out_packet->opaque_only) {
        bitchat_packet_free(out_packet);
        return false;
    }

    if (flags & 0x02) {
        out_packet->has_signature = true;
        if (offset + 64 > len) {
            ESP_LOGW(TAG, "Missing signature bytes");
            bitchat_packet_free(out_packet);
            return false;
        }
        memcpy(out_packet->signature, data + offset, 64);
        offset += 64;
    }

    if (offset < len) {
        size_t padding_len = len - offset;
        uint8_t padding = data[len - 1];
        if (padding == 0 || padding != padding_len) {
            bitchat_packet_free(out_packet);
            return false;
        }
        for (size_t i = offset; i < len; ++i) {
            if (data[i] != padding) {
                bitchat_packet_free(out_packet);
                return false;
            }
        }
    }

    return true;
}

bool bitchat_packet_encode(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len)
{
    if (!packet || !out_buf || !out_len || packet->version != 1) {
        return false;
    }
    size_t offset = 0;

    size_t header_len = 1 /*version*/ + 1 /*type*/ + 1 /*ttl*/ + 8 /*timestamp*/ + 1 /*flags*/ + 2 /*payload len*/ + 8 /*sender*/
                        + (packet->has_recipient ? 8 : 0);
    size_t total_len = header_len + packet->payload_len + (packet->has_signature ? 64 : 0);
    if (total_len > max_len) {
        return false;
    }

    out_buf[offset++] = packet->version;
    out_buf[offset++] = packet->type;
    out_buf[offset++] = packet->ttl;

    for (int i = 7; i >= 0; --i) {
        out_buf[offset++] = (packet->timestamp_ms >> (i * 8)) & 0xFF;
    }

    uint8_t flags = 0;
    if (packet->has_recipient) {
        flags |= 0x01;
    }
    if (packet->has_signature) {
        flags |= 0x02;
    }
    if (packet->is_rsr) {
        flags |= 0x10;
    }
    out_buf[offset++] = flags;

    out_buf[offset++] = (packet->payload_len >> 8) & 0xFF;
    out_buf[offset++] = packet->payload_len & 0xFF;

    memcpy(out_buf + offset, packet->sender_id, 8);
    offset += 8;

    if (packet->has_recipient) {
        memcpy(out_buf + offset, packet->recipient_id, 8);
        offset += 8;
    }

    if (packet->payload_len > 0) {
        if (!packet->payload) {
            return false;
        }
        memcpy(out_buf + offset, packet->payload, packet->payload_len);
        offset += packet->payload_len;
    }

    if (packet->has_signature) {
        memcpy(out_buf + offset, packet->signature, 64);
        offset += 64;
    }

    *out_len = offset;
    return true;
}

void bitchat_packet_free(bitchat_packet_t *packet)
{
    if (packet->payload) {
        heap_caps_free(packet->payload);
    }
    memset(packet, 0, sizeof(*packet));
}

bool packet_codec_self_test(void)
{
    const uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t recipient[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint8_t signature[64] = {
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
        0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
        0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
        0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1,
        0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
    };

    bitchat_packet_t packet = {0};
    packet.version = 1;
    packet.type = BITCHAT_MSG_NOISE_ENCRYPTED;
    packet.ttl = 7;
    packet.timestamp_ms = 0x0102030405060708ULL;
    memcpy(packet.sender_id, (uint8_t[]){0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27}, sizeof(packet.sender_id));
    memcpy(packet.recipient_id, recipient, sizeof(packet.recipient_id));
    packet.has_recipient = true;
    packet.payload = (uint8_t *)payload;
    packet.payload_len = sizeof(payload);
    memcpy(packet.signature, signature, sizeof(packet.signature));
    packet.has_signature = true;

    uint8_t encoded[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t encoded_len = sizeof(encoded);
    if (!bitchat_packet_encode(&packet, encoded, &encoded_len, sizeof(encoded))) {
        return false;
    }

    bitchat_packet_t decoded;
    if (!bitchat_packet_decode(encoded, encoded_len, &decoded)) {
        return false;
    }

    bool ok = decoded.version == packet.version &&
              decoded.type == packet.type &&
              decoded.ttl == packet.ttl &&
              decoded.timestamp_ms == packet.timestamp_ms &&
              decoded.has_recipient == packet.has_recipient &&
              decoded.payload_len == packet.payload_len &&
              decoded.has_signature == packet.has_signature &&
              memcmp(decoded.sender_id, packet.sender_id, sizeof(packet.sender_id)) == 0 &&
              memcmp(decoded.recipient_id, packet.recipient_id, sizeof(packet.recipient_id)) == 0 &&
              memcmp(decoded.payload, packet.payload, packet.payload_len) == 0 &&
              memcmp(decoded.signature, packet.signature, sizeof(packet.signature)) == 0;

    bitchat_packet_free(&decoded);
    if (!ok) {
        return false;
    }

    for (size_t i = 0; i < CONFORMANCE_PACKET_VECTOR_COUNT; ++i) {
        const conformance_packet_vector_t *vector = &CONFORMANCE_PACKET_VECTORS[i];
        size_t fixture_len = 0;
        if (!decode_hex_fixture(vector->hex, encoded, sizeof(encoded), &fixture_len)) {
            ESP_LOGE(TAG, "Invalid conformance fixture encoding: %s", vector->id);
            return false;
        }
        bitchat_packet_t fixture_packet;
        bool decoded_ok = bitchat_packet_decode(encoded, fixture_len, &fixture_packet);
        if (decoded_ok != vector->valid) {
            if (decoded_ok) {
                bitchat_packet_free(&fixture_packet);
            }
            ESP_LOGE(TAG, "Conformance fixture disagrees: %s", vector->id);
            return false;
        }
        if (decoded_ok) {
            if (strcmp(vector->id, "packet.v1.message") == 0 &&
                (fixture_packet.payload_len != 3 ||
                 memcmp(fixture_packet.payload, "abc", 3) != 0)) {
                bitchat_packet_free(&fixture_packet);
                return false;
            }
            if ((strcmp(vector->id, "packet.v1.raw_deflate") == 0 ||
                 strcmp(vector->id, "packet.v1.zlib_read") == 0) &&
                fixture_packet.payload_len != 180) {
                bitchat_packet_free(&fixture_packet);
                return false;
            }
            if (strcmp(vector->id, "packet.v2.route_signed") == 0 &&
                (!fixture_packet.opaque_only ||
                 fixture_packet.version != 2 ||
                 fixture_packet.payload_len != 8 ||
                 memcmp(fixture_packet.payload, "route-v2", 8) != 0)) {
                bitchat_packet_free(&fixture_packet);
                return false;
            }
            bitchat_packet_free(&fixture_packet);
        }
    }
    for (size_t i = 0; i < CONFORMANCE_FINGERPRINT_VECTOR_COUNT; ++i) {
        const conformance_fingerprint_vector_t *vector =
            &CONFORMANCE_FINGERPRINT_VECTORS[i];
        size_t fixture_len = 0;
        uint8_t expected[16];
        size_t expected_len = 0;
        uint8_t actual[16];
        if (!decode_hex_fixture(vector->hex, encoded, sizeof(encoded), &fixture_len) ||
            !decode_hex_fixture(vector->expected, expected, sizeof(expected), &expected_len) ||
            expected_len != sizeof(expected) ||
            !bitchat_relay_fingerprint(encoded, fixture_len, actual) ||
            memcmp(actual, expected, sizeof(expected)) != 0) {
            ESP_LOGE(TAG, "Fingerprint conformance disagrees: %s", vector->id);
            return false;
        }
    }
    return true;
}

