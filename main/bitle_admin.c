#include "bitle_admin.h"

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"

#include "bitchat_time.h"
#include "bitle_hash.h"
#include "bitle_link.h"
#include "bitle_metrics.h"
#include "bitle_store.h"
#include "nickname_manager.h"

#define ADMIN_NVS_NAMESPACE "admin"
#define ADMIN_SALT_KEY "salt"
#define ADMIN_VERIFIER_KEY "verifier"
#define ADMIN_FAILED_KEY "failed"
#define ADMIN_LOCK_UNTIL_KEY "lock_until"

#define ADMIN_HEADER_LEN 6
#define ADMIN_RESPONSE_HEADER_LEN 7
#define ADMIN_PROOF_LEN 32
#define ADMIN_CHALLENGE_TTL_MS 30000ULL
#define ADMIN_MAX_CHALLENGES (BITLE_LINK_MAX * 2)
#define ADMIN_MAX_FAILED_BEFORE_LOCK 5u
#define ADMIN_RESTART_DELAY_MS 750ULL

typedef struct {
    bool in_use;
    uint16_t conn_handle;
    uint32_t request_id;
    uint8_t nonce[BITLE_ADMIN_NONCE_LEN];
    uint64_t expires_uptime_ms;
} admin_challenge_t;

typedef enum {
    CHALLENGE_VALID,
    CHALLENGE_MISSING,
    CHALLENGE_EXPIRED,
} challenge_result_t;

static const char *TAG = "bitle_admin";
static uint8_t s_salt[BITLE_ADMIN_SALT_LEN];
static uint8_t s_verifier[BITLE_ADMIN_VERIFIER_LEN];
static bool s_claimed;
static uint32_t s_failed_attempts;
static uint64_t s_lock_until_ms;
static admin_challenge_t s_challenges[ADMIN_MAX_CHALLENGES];
static portMUX_TYPE s_action_lock = portMUX_INITIALIZER_UNLOCKED;
static bool s_restart_scheduled;
static bool s_factory_reset_scheduled;
static uint64_t s_restart_at_uptime_ms;

static uint64_t uptime_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static uint16_t read_u16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           p[3];
}

static void put_u16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static void put_u32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void put_u64(uint8_t *p, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)value;
        value >>= 8;
    }
}

static bool secure_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t difference = 0;
    for (size_t i = 0; i < len; ++i) {
        difference |= a[i] ^ b[i];
    }
    return difference == 0;
}

static bool hmac_sha256(const uint8_t key[BITLE_ADMIN_VERIFIER_LEN],
                        const uint8_t *data,
                        size_t data_len,
                        uint8_t output[ADMIN_PROOF_LEN])
{
    bitle_hmac_sha256(key, BITLE_ADMIN_VERIFIER_LEN, data, data_len, output);
    return true;
}

static esp_err_t persist_security_state(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ADMIN_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u32(handle, ADMIN_FAILED_KEY, s_failed_attempts);
    if (err == ESP_OK) {
        err = nvs_set_u64(handle, ADMIN_LOCK_UNTIL_KEY, s_lock_until_ms);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err;
}

static esp_err_t persist_verifier(const uint8_t verifier[BITLE_ADMIN_VERIFIER_LEN])
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ADMIN_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(handle, ADMIN_VERIFIER_KEY, verifier, BITLE_ADMIN_VERIFIER_LEN);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err == ESP_OK) {
        memcpy(s_verifier, verifier, sizeof(s_verifier));
        s_claimed = true;
    }
    return err;
}

static uint32_t retry_after_seconds(void)
{
    uint64_t now = bitchat_time_now_ms();
    if (!now || s_lock_until_ms <= now) {
        return 0;
    }
    uint64_t remaining = (s_lock_until_ms - now + 999ULL) / 1000ULL;
    return remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
}

static void record_auth_failure(void)
{
    if (s_failed_attempts < UINT32_MAX) {
        s_failed_attempts++;
    }
    if (s_failed_attempts >= ADMIN_MAX_FAILED_BEFORE_LOCK) {
        uint32_t exponent = s_failed_attempts - ADMIN_MAX_FAILED_BEFORE_LOCK;
        if (exponent > 7) {
            exponent = 7;
        }
        uint64_t lock_seconds = 30ULL << exponent;
        if (lock_seconds > 3600ULL) {
            lock_seconds = 3600ULL;
        }
        uint64_t now = bitchat_time_now_ms();
        s_lock_until_ms = now + lock_seconds * 1000ULL;
    }
    if (persist_security_state() != ESP_OK) {
        ESP_LOGW(TAG, "Failed to persist authentication backoff");
    }
}

static void record_auth_success(void)
{
    if (s_failed_attempts == 0 && s_lock_until_ms == 0) {
        return;
    }
    s_failed_attempts = 0;
    s_lock_until_ms = 0;
    if (persist_security_state() != ESP_OK) {
        ESP_LOGW(TAG, "Failed to clear authentication backoff");
    }
}

static admin_challenge_t *challenge_slot(uint16_t conn_handle, uint32_t request_id)
{
    admin_challenge_t *free_slot = NULL;
    admin_challenge_t *oldest = &s_challenges[0];
    for (size_t i = 0; i < ADMIN_MAX_CHALLENGES; ++i) {
        admin_challenge_t *slot = &s_challenges[i];
        if (slot->in_use && slot->conn_handle == conn_handle &&
            slot->request_id == request_id) {
            return slot;
        }
        if (!slot->in_use && !free_slot) {
            free_slot = slot;
        }
        if (slot->expires_uptime_ms < oldest->expires_uptime_ms) {
            oldest = slot;
        }
    }
    return free_slot ? free_slot : oldest;
}

static void issue_challenge(uint16_t conn_handle,
                            uint32_t request_id,
                            uint8_t nonce[BITLE_ADMIN_NONCE_LEN])
{
    admin_challenge_t *slot = challenge_slot(conn_handle, request_id);
    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->conn_handle = conn_handle;
    slot->request_id = request_id;
    esp_fill_random(slot->nonce, sizeof(slot->nonce));
    memcpy(nonce, slot->nonce, sizeof(slot->nonce));
    slot->expires_uptime_ms = uptime_ms() + ADMIN_CHALLENGE_TTL_MS;
}

static challenge_result_t consume_challenge(uint16_t conn_handle,
                                            uint32_t request_id,
                                            const uint8_t nonce[BITLE_ADMIN_NONCE_LEN])
{
    for (size_t i = 0; i < ADMIN_MAX_CHALLENGES; ++i) {
        admin_challenge_t *slot = &s_challenges[i];
        if (!slot->in_use || slot->conn_handle != conn_handle ||
            slot->request_id != request_id) {
            continue;
        }
        bool expired = uptime_ms() > slot->expires_uptime_ms;
        bool matches = secure_equal(slot->nonce, nonce, sizeof(slot->nonce));
        memset(slot, 0, sizeof(*slot));
        if (expired) {
            return CHALLENGE_EXPIRED;
        }
        return matches ? CHALLENGE_VALID : CHALLENGE_MISSING;
    }
    return CHALLENGE_MISSING;
}

static size_t response_header(uint8_t command,
                              const uint8_t request_id[4],
                              bitle_admin_status_t status,
                              uint8_t *response,
                              size_t capacity)
{
    if (capacity < ADMIN_RESPONSE_HEADER_LEN) {
        return 0;
    }
    response[0] = BITLE_ADMIN_PROTOCOL_VERSION;
    response[1] = command | 0x80;
    memcpy(response + 2, request_id, 4);
    response[6] = (uint8_t)status;
    return ADMIN_RESPONSE_HEADER_LEN;
}

static bool append_bytes(uint8_t *response,
                         size_t capacity,
                         size_t *offset,
                         const void *data,
                         size_t len)
{
    if (*offset > capacity || len > capacity - *offset) {
        return false;
    }
    memcpy(response + *offset, data, len);
    *offset += len;
    return true;
}

static bool build_status(const char *nickname,
                         uint8_t *response,
                         size_t capacity,
                         size_t *offset)
{
    bitle_metrics_snapshot_t metrics;
    bitle_metrics_snapshot(&metrics);
    size_t nickname_len = nickname ? strnlen(nickname, 31) : 0;
    uint8_t fixed[1 + 4 + 4 + (8 * 10) + 2 + 2 + 3 + 1];
    uint8_t heap[8];
    size_t p = 0;
    fixed[p++] = s_claimed ? 1 : 0;
    put_u32(fixed + p, metrics.firmware_version); p += 4;
    put_u32(fixed + p, metrics.protocol_version); p += 4;
    put_u64(fixed + p, metrics.uptime_ms); p += 8;
    put_u64(fixed + p, metrics.boot_count); p += 8;
    put_u64(fixed + p, metrics.packets_received); p += 8;
    put_u64(fixed + p, metrics.packets_forwarded); p += 8;
    put_u64(fixed + p, metrics.packets_stored); p += 8;
    put_u64(fixed + p, metrics.packets_delivered); p += 8;
    put_u64(fixed + p, metrics.packets_deduplicated); p += 8;
    put_u64(fixed + p, metrics.packets_expired); p += 8;
    put_u64(fixed + p, metrics.packets_rejected); p += 8;
    put_u64(fixed + p, metrics.last_activity_uptime_ms); p += 8;
    put_u16(fixed + p, (uint16_t)metrics.courier_store_used); p += 2;
    put_u16(fixed + p, (uint16_t)metrics.courier_store_capacity); p += 2;
    fixed[p++] = metrics.mailbox_available ? 1 : 0;
    fixed[p++] = bitchat_time_is_valid() ? 1 : 0;
    fixed[p++] = bitchat_time_is_authoritative() ? 1 : 0;
    fixed[p++] = (uint8_t)nickname_len;
    put_u32(heap, esp_get_free_heap_size());
    put_u32(heap + 4, esp_get_minimum_free_heap_size());
    return append_bytes(response, capacity, offset, fixed, p) &&
           append_bytes(response, capacity, offset, nickname, nickname_len) &&
           append_bytes(response, capacity, offset, heap, sizeof(heap));
}

static bool verify_request(uint16_t conn_handle,
                           const uint8_t *request,
                           size_t request_len,
                           const uint8_t verifier[BITLE_ADMIN_VERIFIER_LEN],
                           bitle_admin_status_t *status)
{
    if (request_len < ADMIN_HEADER_LEN + BITLE_ADMIN_NONCE_LEN + ADMIN_PROOF_LEN) {
        *status = BITLE_ADMIN_ERR_MALFORMED;
        return false;
    }
    challenge_result_t challenge = consume_challenge(
        conn_handle,
        read_u32(request + 2),
        request + ADMIN_HEADER_LEN);
    if (challenge != CHALLENGE_VALID) {
        *status = challenge == CHALLENGE_EXPIRED
            ? BITLE_ADMIN_ERR_EXPIRED
            : BITLE_ADMIN_ERR_AUTH;
        return false;
    }
    if (retry_after_seconds() > 0) {
        *status = BITLE_ADMIN_ERR_LOCKED;
        return false;
    }
    uint8_t expected[ADMIN_PROOF_LEN];
    size_t signed_len = request_len - ADMIN_PROOF_LEN;
    if (!hmac_sha256(verifier, request, signed_len, expected) ||
        !secure_equal(expected, request + signed_len, ADMIN_PROOF_LEN)) {
        *status = BITLE_ADMIN_ERR_AUTH;
        record_auth_failure();
        return false;
    }
    record_auth_success();
    return true;
}

void bitle_admin_schedule_restart(bool factory_reset)
{
    portENTER_CRITICAL(&s_action_lock);
    s_restart_scheduled = true;
    s_factory_reset_scheduled = factory_reset;
    s_restart_at_uptime_ms = uptime_ms() + ADMIN_RESTART_DELAY_MS;
    portEXIT_CRITICAL(&s_action_lock);
}

static esp_err_t erase_namespace(const char *name)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(name, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;
    }
    err = nvs_erase_all(handle);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err;
}

esp_err_t bitle_admin_init(void)
{
    memset(s_challenges, 0, sizeof(s_challenges));
    nvs_handle_t handle;
    esp_err_t err = nvs_open(ADMIN_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return err;
    }

    size_t salt_len = sizeof(s_salt);
    err = nvs_get_blob(handle, ADMIN_SALT_KEY, s_salt, &salt_len);
    if (err == ESP_ERR_NVS_NOT_FOUND || salt_len != sizeof(s_salt)) {
        esp_fill_random(s_salt, sizeof(s_salt));
        err = nvs_set_blob(handle, ADMIN_SALT_KEY, s_salt, sizeof(s_salt));
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
    }
    if (err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    size_t verifier_len = sizeof(s_verifier);
    err = nvs_get_blob(handle, ADMIN_VERIFIER_KEY, s_verifier, &verifier_len);
    s_claimed = err == ESP_OK && verifier_len == sizeof(s_verifier);
    if (!s_claimed && err != ESP_ERR_NVS_NOT_FOUND) {
        memset(s_verifier, 0, sizeof(s_verifier));
    }
    if (!s_claimed && err != ESP_ERR_NVS_NOT_FOUND && err != ESP_OK) {
        nvs_close(handle);
        return err;
    }

    if (nvs_get_u32(handle, ADMIN_FAILED_KEY, &s_failed_attempts) != ESP_OK) {
        s_failed_attempts = 0;
    }
    if (nvs_get_u64(handle, ADMIN_LOCK_UNTIL_KEY, &s_lock_until_ms) != ESP_OK) {
        s_lock_until_ms = 0;
    }
    nvs_close(handle);
    ESP_LOGI(TAG, "Admin channel ready (%s)", s_claimed ? "claimed" : "unclaimed");
    return ESP_OK;
}

bool bitle_admin_handle(uint16_t conn_handle,
                        const uint8_t *request,
                        size_t request_len,
                        const char *nickname,
                        uint8_t *response,
                        size_t response_capacity,
                        size_t *response_len,
                        bitle_admin_result_t *result)
{
    if (!request || !response || !response_len || !result ||
        request_len < ADMIN_HEADER_LEN) {
        return false;
    }
    memset(result, 0, sizeof(*result));
    uint8_t command = request[1];
    size_t offset = response_header(command, request + 2, BITLE_ADMIN_OK,
                                    response, response_capacity);
    if (!offset) {
        return false;
    }
    if (request[0] != BITLE_ADMIN_PROTOCOL_VERSION) {
        response[6] = BITLE_ADMIN_ERR_UNSUPPORTED;
        *response_len = offset;
        return true;
    }

    if (command == BITLE_ADMIN_STATUS_GET) {
        if (request_len != ADMIN_HEADER_LEN ||
            !build_status(nickname, response, response_capacity, &offset)) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
            offset = ADMIN_RESPONSE_HEADER_LEN;
        }
        *response_len = offset;
        return true;
    }

    if (command == BITLE_ADMIN_CHALLENGE_GET) {
        if (request_len != ADMIN_HEADER_LEN ||
            response_capacity - offset < 1 + BITLE_ADMIN_SALT_LEN +
                                         BITLE_ADMIN_NONCE_LEN + 4 + 4) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
            *response_len = ADMIN_RESPONSE_HEADER_LEN;
            return true;
        }
        uint8_t nonce[BITLE_ADMIN_NONCE_LEN];
        issue_challenge(conn_handle, read_u32(request + 2), nonce);
        response[offset++] = s_claimed ? 1 : 0;
        append_bytes(response, response_capacity, &offset, s_salt, sizeof(s_salt));
        append_bytes(response, response_capacity, &offset, nonce, sizeof(nonce));
        put_u32(response + offset, BITLE_ADMIN_PBKDF2_ITERATIONS); offset += 4;
        put_u32(response + offset, retry_after_seconds()); offset += 4;
        *response_len = offset;
        return true;
    }

    bitle_admin_status_t auth_status = BITLE_ADMIN_OK;
    size_t data_offset = ADMIN_HEADER_LEN + BITLE_ADMIN_NONCE_LEN;
    size_t data_len = request_len >= data_offset + ADMIN_PROOF_LEN
        ? request_len - data_offset - ADMIN_PROOF_LEN
        : 0;

    if (command == BITLE_ADMIN_SET_PASSWORD) {
        if (s_claimed) {
            response[6] = BITLE_ADMIN_ERR_ALREADY_CLAIMED;
        } else if (data_len != BITLE_ADMIN_VERIFIER_LEN) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
        } else if (!verify_request(conn_handle, request, request_len,
                                   request + data_offset, &auth_status)) {
            response[6] = auth_status;
        } else if (persist_verifier(request + data_offset) != ESP_OK) {
            response[6] = BITLE_ADMIN_ERR_INTERNAL;
        }
        *response_len = offset;
        return true;
    }

    if (!s_claimed) {
        response[6] = BITLE_ADMIN_ERR_NOT_CLAIMED;
        *response_len = offset;
        return true;
    }
    if (!verify_request(conn_handle, request, request_len, s_verifier, &auth_status)) {
        response[6] = auth_status;
        *response_len = offset;
        return true;
    }

    switch (command) {
    case BITLE_ADMIN_CHANGE_PASSWORD:
        if (data_len != BITLE_ADMIN_VERIFIER_LEN) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
        } else if (persist_verifier(request + data_offset) != ESP_OK) {
            response[6] = BITLE_ADMIN_ERR_INTERNAL;
        }
        break;
    case BITLE_ADMIN_RENAME: {
        if (data_len < 2 || request[data_offset] == 0 ||
            request[data_offset] > 31 ||
            data_len != (size_t)request[data_offset] + 1) {
            response[6] = BITLE_ADMIN_ERR_INVALID_VALUE;
            break;
        }
        char renamed[32] = {0};
        memcpy(renamed, request + data_offset + 1, request[data_offset]);
        if (nickname_set(renamed) != ESP_OK) {
            response[6] = BITLE_ADMIN_ERR_INVALID_VALUE;
            break;
        }
        result->nickname_changed = true;
        strlcpy(result->nickname, renamed, sizeof(result->nickname));
        break;
    }
    case BITLE_ADMIN_REBOOT:
        if (data_len != 0) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
        } else {
            result->restart_requested = true;
        }
        break;
    case BITLE_ADMIN_FACTORY_RESET:
        if (data_len != 0) {
            response[6] = BITLE_ADMIN_ERR_MALFORMED;
        } else {
            result->restart_requested = true;
            result->factory_reset_requested = true;
        }
        break;
    default:
        response[6] = BITLE_ADMIN_ERR_UNSUPPORTED;
        break;
    }
    *response_len = offset;
    return true;
}

void bitle_admin_poll(void)
{
    bool restart = false;
    bool factory_reset = false;
    uint64_t now = uptime_ms();
    portENTER_CRITICAL(&s_action_lock);
    if (s_restart_scheduled && now >= s_restart_at_uptime_ms) {
        restart = true;
        factory_reset = s_factory_reset_scheduled;
        s_restart_scheduled = false;
        s_factory_reset_scheduled = false;
    }
    portEXIT_CRITICAL(&s_action_lock);
    if (!restart) {
        return;
    }

    if (factory_reset) {
        ESP_LOGW(TAG, "Performing authenticated factory reset");
        bitle_store_clear();
        static const char *namespaces[] = {
            ADMIN_NVS_NAMESPACE,
            "noise",
            "bitle_metrics",
            "bitleota",
            "lora",
        };
        for (size_t i = 0; i < sizeof(namespaces) / sizeof(namespaces[0]); ++i) {
            esp_err_t err = erase_namespace(namespaces[i]);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to erase NVS namespace %s: %s",
                         namespaces[i], esp_err_to_name(err));
            }
        }
    } else {
        ESP_LOGI(TAG, "Performing authenticated restart");
    }
    esp_restart();
}

bool bitle_admin_self_test(void)
{
    uint8_t key[BITLE_ADMIN_VERIFIER_LEN];
    uint8_t data[12];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < sizeof(data); ++i) {
        data[i] = (uint8_t)(0xA0 + i);
    }
    uint8_t first[ADMIN_PROOF_LEN];
    uint8_t second[ADMIN_PROOF_LEN];
    if (!hmac_sha256(key, data, sizeof(data), first) ||
        !hmac_sha256(key, data, sizeof(data), second) ||
        !secure_equal(first, second, sizeof(first))) {
        return false;
    }
    data[0] ^= 1;
    if (!hmac_sha256(key, data, sizeof(data), second) ||
        secure_equal(first, second, sizeof(first))) {
        return false;
    }
    uint8_t encoded[8];
    put_u16(encoded, 0x1234);
    put_u32(encoded + 2, 0x89ABCDEF);
    if (read_u16(encoded) != 0x1234 ||
        read_u32(encoded + 2) != 0x89ABCDEF) {
        return false;
    }

    uint8_t request[ADMIN_HEADER_LEN] = {
        BITLE_ADMIN_PROTOCOL_VERSION,
        BITLE_ADMIN_STATUS_GET,
        0x12, 0x34, 0x56, 0x78,
    };
    uint8_t response[BITLE_ADMIN_MAX_RESPONSE];
    size_t response_len = 0;
    bitle_admin_result_t result;
    if (!bitle_admin_handle(0xFFFF, request, sizeof(request), "Bitle-test",
                            response, sizeof(response), &response_len, &result)) {
        return false;
    }
    return response_len > ADMIN_RESPONSE_HEADER_LEN &&
           response[0] == BITLE_ADMIN_PROTOCOL_VERSION &&
           response[1] == (BITLE_ADMIN_STATUS_GET | 0x80) &&
           memcmp(response + 2, request + 2, 4) == 0 &&
           response[6] == BITLE_ADMIN_OK &&
           !result.nickname_changed;
}
