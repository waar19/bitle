#include "bitle_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "bitle_link";

typedef struct {
    bool in_use;
    bitle_link_t adapter;
    bitle_link_send_fn_t legacy_send_fn;
} link_entry_t;

static link_entry_t s_links[BITLE_LINK_MAX];
static SemaphoreHandle_t s_lock;

esp_err_t bitle_link_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    if (!s_lock) {
        return ESP_ERR_NO_MEM;
    }
    return bitle_link_contract_self_test();
}

static link_entry_t *find_locked(uint16_t handle)
{
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use && s_links[i].adapter.capabilities.id == handle) {
            return &s_links[i];
        }
    }
    return NULL;
}

static bool capabilities_valid(const bitle_link_capabilities_t *capabilities)
{
    return capabilities &&
           capabilities->id != BITLE_LINK_NONE &&
           capabilities->mtu > 0 &&
           (capabilities->broadcast || capabilities->unicast) &&
           capabilities->max_connections > 0;
}

static const char *kind_name(bitle_link_type_t kind)
{
    switch (kind) {
    case BITLE_LINK_BLE:
        return "ble";
    case BITLE_LINK_LORA:
        return "lora";
    case BITLE_LINK_IN_MEMORY:
        return "in-memory";
    default:
        return "unknown";
    }
}

static esp_err_t register_locked(const bitle_link_t *adapter, bitle_link_send_fn_t legacy_send_fn)
{
    link_entry_t *e = find_locked(adapter->capabilities.id);
    if (!e) {
        for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
            if (!s_links[i].in_use) {
                e = &s_links[i];
                break;
            }
        }
    }
    if (!e) {
        ESP_LOGW(TAG, "link table full; cannot register id=%u", adapter->capabilities.id);
        return ESP_ERR_NO_MEM;
    }
    e->in_use = true;
    e->adapter = *adapter;
    e->legacy_send_fn = legacy_send_fn;
    return ESP_OK;
}

esp_err_t bitle_link_register_adapter(const bitle_link_t *link)
{
    if (!link || !capabilities_valid(&link->capabilities) ||
        !link->vtable || !link->vtable->send) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t result = register_locked(link, NULL);
    xSemaphoreGive(s_lock);
    if (result == ESP_OK) {
        ESP_LOGI(TAG, "link up id=%u kind=%s mtu=%u cost=%u",
                 link->capabilities.id, kind_name(link->capabilities.kind),
                 link->capabilities.mtu, link->capabilities.cost);
    }
    return result;
}

esp_err_t bitle_link_register(uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn)
{
    if (!send_fn || handle == BITLE_LINK_NONE) {
        return ESP_ERR_INVALID_ARG;
    }
    bitle_link_t adapter = {
        .capabilities = {
            .id = handle,
            .kind = type,
            .mtu = BITLE_LINK_LEGACY_MTU,
            .broadcast = type == BITLE_LINK_LORA || handle >= BITLE_LINK_BROADCAST_BASE,
            .unicast = type != BITLE_LINK_LORA,
            .reliability = type == BITLE_LINK_LORA
                               ? BITLE_LINK_ACKNOWLEDGED
                               : BITLE_LINK_BEST_EFFORT,
            .background = true,
            .max_connections = type == BITLE_LINK_BLE ? BITLE_LINK_MAX : 1,
            .cost = type == BITLE_LINK_BLE ? 10 : 50,
        },
        .vtable = NULL,
        .context = NULL,
    };
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t result = register_locked(&adapter, send_fn);
    xSemaphoreGive(s_lock);
    if (result == ESP_OK) {
        ESP_LOGI(TAG, "link up id=%u kind=%s mtu=%u cost=%u",
                 handle, kind_name(type), adapter.capabilities.mtu,
                 adapter.capabilities.cost);
    }
    return result;
}

void bitle_link_unregister(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (e) {
        memset(e, 0, sizeof(*e));
    }
    xSemaphoreGive(s_lock);
}

bool bitle_link_ready(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool ready = find_locked(handle) != NULL;
    xSemaphoreGive(s_lock);
    return ready;
}

bool bitle_link_get_capabilities(uint16_t handle, bitle_link_capabilities_t *out)
{
    if (!out) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (e) {
        *out = e->adapter.capabilities;
    }
    xSemaphoreGive(s_lock);
    return e != NULL;
}

bool bitle_link_is_broadcast(uint16_t handle)
{
    bitle_link_capabilities_t capabilities;
    if (bitle_link_get_capabilities(handle, &capabilities)) {
        return capabilities.broadcast;
    }
    return handle >= BITLE_LINK_BROADCAST_BASE;
}

static int entry_send(const link_entry_t *entry, const uint8_t *data, uint16_t len)
{
    if (!data || len == 0 || len > entry->adapter.capabilities.mtu) {
        return -1;
    }
    if (entry->legacy_send_fn) {
        return entry->legacy_send_fn(entry->adapter.capabilities.id, data, len);
    }
    return entry->adapter.vtable->send(&entry->adapter, data, len);
}

esp_err_t bitle_link_send(uint16_t handle, const uint8_t *data, uint16_t len)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    link_entry_t target = {0};
    if (e) {
        target = *e;
    }
    xSemaphoreGive(s_lock);
    if (!target.in_use) {
        return ESP_ERR_INVALID_STATE;
    }
    /* Send outside the lock: transport sends may block briefly. */
    return entry_send(&target, data, len) == 0 ? ESP_OK : ESP_FAIL;
}

int bitle_link_broadcast(uint16_t exclude_handle, const uint8_t *data, uint16_t len)
{
    /* Snapshot under the lock, send outside it. */
    link_entry_t targets[BITLE_LINK_MAX];
    size_t n = 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use &&
            s_links[i].adapter.capabilities.id != exclude_handle) {
            targets[n++] = s_links[i];
        }
    }
    xSemaphoreGive(s_lock);

    int sent = 0;
    for (size_t i = 0; i < n; ++i) {
        int rc = entry_send(&targets[i], data, len);
        if (rc == 0) {
            sent++;
        } else {
            ESP_LOGW(TAG, "broadcast send failed id=%u rc=%d",
                     targets[i].adapter.capabilities.id, rc);
        }
    }
    return sent;
}

static int memory_send(const bitle_link_t *link, const uint8_t *frame, uint16_t len)
{
    bitle_link_memory_state_t *state = (bitle_link_memory_state_t *)link->context;
    if (!state || !state->storage || !frame || len == 0 ||
        len > state->capacity || len > link->capabilities.mtu) {
        return -1;
    }
    memcpy(state->storage, frame, len);
    state->frame_len = len;
    state->send_count++;
    return 0;
}

static const bitle_link_vtable_t s_memory_vtable = {
    .send = memory_send,
};

esp_err_t bitle_link_memory_adapter(
    bitle_link_t *out,
    bitle_link_memory_state_t *state,
    const bitle_link_capabilities_t *capabilities)
{
    if (!out || !state || !state->storage ||
        !capabilities_valid(capabilities) ||
        capabilities->kind != BITLE_LINK_IN_MEMORY ||
        state->capacity < capabilities->mtu) {
        return ESP_ERR_INVALID_ARG;
    }
    state->frame_len = 0;
    state->send_count = 0;
    *out = (bitle_link_t) {
        .capabilities = *capabilities,
        .vtable = &s_memory_vtable,
        .context = state,
    };
    return ESP_OK;
}

esp_err_t bitle_link_contract_self_test(void)
{
    uint8_t storage[4] = {0};
    const uint8_t expected[4] = {1, 2, 3, 4};
    bitle_link_memory_state_t state = {
        .storage = storage,
        .capacity = sizeof(storage),
    };
    bitle_link_capabilities_t capabilities = {
        .id = 1,
        .kind = BITLE_LINK_IN_MEMORY,
        .mtu = sizeof(storage),
        .broadcast = true,
        .unicast = true,
        .reliability = BITLE_LINK_ACKNOWLEDGED,
        .background = true,
        .max_connections = 1,
        .cost = 0,
    };
    bitle_link_t link;
    if (bitle_link_memory_adapter(&link, &state, &capabilities) != ESP_OK ||
        link.vtable->send(&link, expected, sizeof(expected)) != 0 ||
        state.send_count != 1 ||
        state.frame_len != sizeof(expected) ||
        memcmp(storage, expected, sizeof(expected)) != 0 ||
        link.vtable->send(&link, expected, sizeof(expected) + 1) == 0) {
        ESP_LOGE(TAG, "in-memory link contract self-test failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}
