#ifndef BITLE_METRICS_H
#define BITLE_METRICS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BITLE_METRIC_PACKETS_RECEIVED = 0,
    BITLE_METRIC_PACKETS_FORWARDED,
    BITLE_METRIC_PACKETS_STORED,
    BITLE_METRIC_PACKETS_DELIVERED,
    BITLE_METRIC_PACKETS_DEDUPLICATED,
    BITLE_METRIC_PACKETS_EXPIRED,
    BITLE_METRIC_PACKETS_REJECTED,
    BITLE_METRIC_COUNT,
} bitle_metric_counter_t;

typedef struct {
    uint64_t uptime_ms;
    uint64_t boot_count;
    uint64_t packets_received;
    uint64_t packets_forwarded;
    uint64_t packets_stored;
    uint64_t packets_delivered;
    uint64_t packets_deduplicated;
    uint64_t packets_expired;
    uint64_t packets_rejected;
    size_t courier_store_used;
    size_t courier_store_capacity;
    uint64_t last_activity_uptime_ms;
    uint32_t firmware_version;
    uint32_t protocol_version;
    bool mailbox_available;
} bitle_metrics_snapshot_t;

/* Call after nvs_flash_init() and before transports can receive traffic.
 * NVS failures are non-fatal; counters continue with an in-RAM boot count. */
esp_err_t bitle_metrics_init(void);

/* Saturating, task-safe increment. Also advances last_activity_uptime_ms. */
void bitle_metrics_increment(bitle_metric_counter_t counter);

void bitle_metrics_snapshot(bitle_metrics_snapshot_t *snapshot);
void bitle_metrics_log(void);

/* Pure local-state checks for increment, snapshot copy, and saturation. */
bool bitle_metrics_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* BITLE_METRICS_H */
