#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PAGEKITE_TEXT_MAX_LEN 128
// Called on the worker task with method GET/POST and a path without query.
// Return NULL to deny, or an origin path that stays valid until the next call.
// Returned paths must be valid origin-form paths, with no CR/LF characters.
typedef const char *(*pagekite_route_fn)(const char *method, const char *path);
typedef struct {
    bool enabled;
    char domain[PAGEKITE_TEXT_MAX_LEN];
    char secret[PAGEKITE_TEXT_MAX_LEN];
    char custom_domain[PAGEKITE_TEXT_MAX_LEN];
    uint16_t local_port; // Loopback origin only; zero means 80.
    pagekite_route_fn route;
} pagekite_config_t;

typedef enum {
    PAGEKITE_STATUS_DISABLED,
    PAGEKITE_STATUS_CONNECTING,
    PAGEKITE_STATUS_CONNECTED,
    PAGEKITE_STATUS_AUTH_ERROR,
    PAGEKITE_STATUS_NETWORK_ERROR,
} pagekite_status_state_t;
typedef struct {
    pagekite_status_state_t state;
    uint32_t retry_in_s;
} pagekite_status_t;

// Copies configuration; starts the singleton worker or requests a reconnect.
// Call only from task context and serialize calls in the application.
// Disable with .enabled=false; the worker sleeps but is not destroyed.
// Configuration changes during a connection apply after a response grace period.
esp_err_t pagekite_tunnel_start(const pagekite_config_t *config);
void pagekite_tunnel_get_status(pagekite_status_t *status);

#ifdef __cplusplus
}
#endif
