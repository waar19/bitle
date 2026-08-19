#include "bitle_metrics.h"

#include <limits.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "nvs.h"

#include "bitle_courier.h"
#include "bitle_ota.h"
#include "bitle_store.h"

#define METRICS_NVS_NAMESPACE "bitle_metrics"
#define METRICS_NVS_BOOT_KEY  "boot_count"
#define BITLE_PROTOCOL_VERSION 1

typedef struct {
    uint64_t boot_count;
    uint64_t counters[BITLE_METRIC_COUNT];
    uint64_t last_activity_uptime_ms;
} metrics_state_t;

static const char *TAG = "bitle_metrics";
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static metrics_state_t s_state;

static uint64_t uptime_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static void counter_state_increment(metrics_state_t *state,
                                    bitle_metric_counter_t counter,
                                    uint64_t activity_uptime_ms)
{
    if (!state || (unsigned)counter >= BITLE_METRIC_COUNT) {
        return;
    }
    if (state->counters[counter] < UINT64_MAX) {
        state->counters[counter]++;
    }
    if (activity_uptime_ms > state->last_activity_uptime_ms) {
        state->last_activity_uptime_ms = activity_uptime_ms;
    }
}

static void snapshot_from_state(const metrics_state_t *state,
                                bitle_metrics_snapshot_t *snapshot)
{
    snapshot->boot_count = state->boot_count;
    snapshot->packets_received = state->counters[BITLE_METRIC_PACKETS_RECEIVED];
    snapshot->packets_forwarded = state->counters[BITLE_METRIC_PACKETS_FORWARDED];
    snapshot->packets_stored = state->counters[BITLE_METRIC_PACKETS_STORED];
    snapshot->packets_delivered = state->counters[BITLE_METRIC_PACKETS_DELIVERED];
    snapshot->packets_deduplicated = state->counters[BITLE_METRIC_PACKETS_DEDUPLICATED];
    snapshot->packets_expired = state->counters[BITLE_METRIC_PACKETS_EXPIRED];
    snapshot->packets_rejected = state->counters[BITLE_METRIC_PACKETS_REJECTED];
    snapshot->last_activity_uptime_ms = state->last_activity_uptime_ms;
}

esp_err_t bitle_metrics_init(void)
{
    uint64_t previous_boot_count = 0;
    nvs_handle_t handle;
    esp_err_t err = nvs_open(METRICS_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_get_u64(handle, METRICS_NVS_BOOT_KEY, &previous_boot_count);
        bool can_persist = true;
        if (err == ESP_ERR_NVS_NOT_FOUND) {
            previous_boot_count = 0;
        } else if (err != ESP_OK) {
            previous_boot_count = 0;
            can_persist = false;
            ESP_LOGW(TAG, "Boot count read failed (%s); using RAM value",
                     esp_err_to_name(err));
        }

        uint64_t current_boot_count = previous_boot_count;
        if (current_boot_count < UINT64_MAX) {
            current_boot_count++;
        }
        if (can_persist) {
            esp_err_t write_err = nvs_set_u64(handle, METRICS_NVS_BOOT_KEY,
                                              current_boot_count);
            if (write_err == ESP_OK) {
                write_err = nvs_commit(handle);
            }
            if (write_err != ESP_OK) {
                ESP_LOGW(TAG, "Boot count persist failed (%s); continuing in RAM",
                         esp_err_to_name(write_err));
            }
        }
        nvs_close(handle);
        previous_boot_count = current_boot_count;
    } else {
        ESP_LOGW(TAG, "Boot count NVS open failed (%s); continuing in RAM",
                 esp_err_to_name(err));
        previous_boot_count = 1;
    }

    portENTER_CRITICAL(&s_lock);
    memset(&s_state, 0, sizeof(s_state));
    s_state.boot_count = previous_boot_count;
    portEXIT_CRITICAL(&s_lock);
    return ESP_OK;
}

void bitle_metrics_increment(bitle_metric_counter_t counter)
{
    uint64_t now_ms = uptime_ms();
    portENTER_CRITICAL(&s_lock);
    counter_state_increment(&s_state, counter, now_ms);
    portEXIT_CRITICAL(&s_lock);
}

void bitle_metrics_snapshot(bitle_metrics_snapshot_t *snapshot)
{
    if (!snapshot) {
        return;
    }
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->uptime_ms = uptime_ms();
    snapshot->firmware_version = BITLE_FW_VERSION;
    snapshot->protocol_version = BITLE_PROTOCOL_VERSION;

    portENTER_CRITICAL(&s_lock);
    snapshot_from_state(&s_state, snapshot);
    portEXIT_CRITICAL(&s_lock);

    snapshot->mailbox_available = bitle_courier_is_available();
    if (snapshot->mailbox_available) {
        snapshot->courier_store_used = bitle_store_count();
        snapshot->courier_store_capacity = BITLE_COURIER_MAX_ENVELOPES;
    }
}

void bitle_metrics_log(void)
{
    bitle_metrics_snapshot_t snapshot;
    bitle_metrics_snapshot(&snapshot);
    ESP_LOGI(TAG,
             "HBIT_METRICS uptime_ms=%llu boot_count=%llu packets_received=%llu "
             "packets_forwarded=%llu packets_stored=%llu packets_delivered=%llu "
             "packets_deduplicated=%llu packets_expired=%llu packets_rejected=%llu "
             "courier_store_used=%u courier_store_capacity=%u "
             "last_activity_uptime_ms=%llu firmware_version=%lu protocol_version=%lu "
             "mailbox_available=%s",
             (unsigned long long)snapshot.uptime_ms,
             (unsigned long long)snapshot.boot_count,
             (unsigned long long)snapshot.packets_received,
             (unsigned long long)snapshot.packets_forwarded,
             (unsigned long long)snapshot.packets_stored,
             (unsigned long long)snapshot.packets_delivered,
             (unsigned long long)snapshot.packets_deduplicated,
             (unsigned long long)snapshot.packets_expired,
             (unsigned long long)snapshot.packets_rejected,
             (unsigned)snapshot.courier_store_used,
             (unsigned)snapshot.courier_store_capacity,
             (unsigned long long)snapshot.last_activity_uptime_ms,
             (unsigned long)snapshot.firmware_version,
             (unsigned long)snapshot.protocol_version,
             snapshot.mailbox_available ? "true" : "false");
}

bool bitle_metrics_self_test(void)
{
    metrics_state_t state = {.boot_count = 7};
    bitle_metrics_snapshot_t snapshot = {0};

    counter_state_increment(&state, BITLE_METRIC_PACKETS_RECEIVED, 10);
    counter_state_increment(&state, BITLE_METRIC_PACKETS_RECEIVED, 9);
    state.counters[BITLE_METRIC_PACKETS_REJECTED] = UINT64_MAX;
    counter_state_increment(&state, BITLE_METRIC_PACKETS_REJECTED, 11);
    snapshot_from_state(&state, &snapshot);

    return snapshot.boot_count == 7 &&
           snapshot.packets_received == 2 &&
           snapshot.packets_rejected == UINT64_MAX &&
           snapshot.last_activity_uptime_ms == 11;
}
