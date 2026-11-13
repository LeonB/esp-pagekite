#include <string.h>
#include "pagekite_tunnel.h"

static const char *public_route(const char *method, const char *path) {
    if (!strcmp(method, "GET") && !strcmp(path, "/")) return "/";
    return NULL;
}

void app_main(void) {
    // Integrate networking, SNTP and an authenticated HTTP server first.
    // Load the domain/secret privately from your application's provisioning.
    pagekite_config_t config = {.enabled = false, .local_port = 80, .route = public_route};
    ESP_ERROR_CHECK(pagekite_tunnel_start(&config));
}
