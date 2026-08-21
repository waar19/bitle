#ifndef BITLE_ADMIN_H
#define BITLE_ADMIN_H

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITLE_ADMIN_PROTOCOL_VERSION 0x01
#define BITLE_ADMIN_NOISE_PAYLOAD    0x31
#define BITLE_ADMIN_PBKDF2_ITERATIONS 120000u
#define BITLE_ADMIN_VERIFIER_LEN     32
#define BITLE_ADMIN_SALT_LEN         16
#define BITLE_ADMIN_NONCE_LEN        16
#define BITLE_ADMIN_MAX_RESPONSE     192

typedef enum {
    BITLE_ADMIN_STATUS_GET = 0x01,
    BITLE_ADMIN_CHALLENGE_GET = 0x02,
    BITLE_ADMIN_SET_PASSWORD = 0x03,
    BITLE_ADMIN_CHANGE_PASSWORD = 0x04,
    BITLE_ADMIN_RENAME = 0x05,
    BITLE_ADMIN_REBOOT = 0x06,
    BITLE_ADMIN_FACTORY_RESET = 0x07,
} bitle_admin_command_t;

typedef enum {
    BITLE_ADMIN_OK = 0x00,
    BITLE_ADMIN_ERR_MALFORMED = 0x01,
    BITLE_ADMIN_ERR_UNSUPPORTED = 0x02,
    BITLE_ADMIN_ERR_NOT_CLAIMED = 0x03,
    BITLE_ADMIN_ERR_ALREADY_CLAIMED = 0x04,
    BITLE_ADMIN_ERR_AUTH = 0x05,
    BITLE_ADMIN_ERR_LOCKED = 0x06,
    BITLE_ADMIN_ERR_EXPIRED = 0x07,
    BITLE_ADMIN_ERR_INVALID_VALUE = 0x08,
    BITLE_ADMIN_ERR_INTERNAL = 0x09,
} bitle_admin_status_t;

typedef struct {
    bool nickname_changed;
    bool restart_requested;
    bool factory_reset_requested;
    char nickname[32];
} bitle_admin_result_t;

esp_err_t bitle_admin_init(void);

/* Handles one admin request after Noise decryption. response excludes the
 * outer Noise payload type; the caller encrypts it as type 0x31. */
bool bitle_admin_handle(uint16_t conn_handle,
                        const uint8_t *request,
                        size_t request_len,
                        const char *nickname,
                        uint8_t *response,
                        size_t response_capacity,
                        size_t *response_len,
                        bitle_admin_result_t *result);

/* Executes delayed destructive actions after their encrypted response had
 * time to leave the NimBLE queue. */
void bitle_admin_poll(void);
void bitle_admin_schedule_restart(bool factory_reset);

/* Pure cryptographic/framing checks; does not mutate NVS. */
bool bitle_admin_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_ADMIN_H */
