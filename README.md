# esp-pagekite

A native C [PageKite](https://pagekite.net/) HTTP tunnel client for ESP-IDF.
The ESP32 establishes an outbound, certificate-verified TLS connection to a
PageKite frontend and multiplexes public requests onto a loopback HTTP server.
No Python runtime or separate tunnel host runs on the device.

Independently implemented for [Flue Monitor](https://github.com/LeonB/flue-monitor),
then extracted into a standalone component. It is not the official PageKite library.

## Use

Requires ESP-IDF 6.0, PSRAM, a PageKite domain/shared secret, working networking,
a synchronized clock, and the mbedTLS certificate bundle. Copy this repository
into `components/esp-pagekite` (or use a Git submodule). Enable PSRAM and the
certificate bundle; see `examples/minimal/sdkconfig.defaults`.

```c
#include <string.h>
#include "pagekite_tunnel.h"

static const char *public_route(const char *method, const char *path) {
    if (!strcmp(method, "GET") && !strcmp(path, "/")) return "/";
    return NULL; // Deny everything else, including OTA and Wi-Fi setup.
}

// After networking, SNTP and the local web server are ready:
pagekite_config_t config = {
    .enabled = true,
    .local_port = 80,
    .route = public_route,
};
// Copy your privately provisioned strings into config.domain / config.secret.
// An optional custom_domain must be a configured CNAME alias for this kite.
ESP_ERROR_CHECK(pagekite_tunnel_start(&config));
```

Configuration is copied, not persisted. Keep credentials out of source control;
the application owns provisioning/NVS. Domain names must be lowercase.
Serialize configuration calls from your application. Call the same API with a
new configuration to reconnect, or `.enabled=false` to disable. The singleton
worker remains allocated while disabled. `pagekite_tunnel_get_status()` returns
the connection state and retry delay. A connected state is not a public HTTP probe.

The route callback runs on the tunnel task. It can allow or remap a path; return
only trusted origin-form paths without CR/LF. All other paths are denied. The
origin is always `127.0.0.1` on your configured port. The optional original
Flue Monitor policy is in `examples/flue_dashboard/routes.h`; its remapped
endpoints are application-specific and must exist on the origin.

## How it works

1. Resolve `frontends.b5p.us`, probe verified TLS frontends and select the fastest.
2. Update **this kite's public DNS** through PageKite's signed HTTPS DDNS endpoint.
3. Authenticate with the CONNECT challenge/signature protocol.
4. Route bounded chunk/SID streams to the loopback origin; stream responses back.
5. Check idle relay health using PING/PONG; reconnect with 2–60 second backoff.

TLS certificate validation stays enabled. Sensitive endpoints still need origin
visitor authentication: the PageKite shared secret authenticates the connector,
not public visitors. Cookie and Origin headers are forwarded. Public HTTP
requests redirect to HTTPS. Backend query strings are retained for non-API
assets; API query strings are currently stripped.

## Bounds and validation

Eight stream slots, two active origin connections, 4 KiB request/frame buffers,
12 KiB task stack. GET and JSON POST only; POST bodies must be smaller than
2048 bytes. WebSocket upgrades, chunked requests and pipelining are rejected.
Data buffers require PSRAM with no internal fallback; TLS allocation policy is
owned by the application. Network timeouts can delay configuration changes.

The source client was used on an ESP32-PICO-V3-02. This standalone extraction
has host protocol tests and an ESP-IDF build check; it has not been re-tested
against the live PageKite service. Run `python3 tests/test_configuration.py` and `python3 tests/test_protocol.py` on macOS
with Clang and ASan/UBSan (the socket fixture uses port 18776).
The minimal example builds disabled and does not configure Wi-Fi or a server.

Apache-2.0. See [LICENSE.txt](LICENSE.txt).
