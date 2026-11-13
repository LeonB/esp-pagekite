#pragma once
#include <string.h>

// Optional original application policy. These endpoints must exist in your origin.
static const char *flue_dashboard_route(const char *method, const char *path) {
    if (!strcmp(method, "POST")) {
        if (!strcmp(path, "/api/settings")) return "/api/tunnel/settings";
        if (!strcmp(path, "/api/bosch")) return "/api/bosch";
        if (!strcmp(path, "/api/event")) return "/api/event";
        if (!strcmp(path, "/api/auth/login") || !strcmp(path, "/api/auth/setup") ||
            !strcmp(path, "/api/auth/password") || !strcmp(path, "/api/auth/logout")) return path;
        return NULL;
    }
    static const char *allowed[] = {
        "/", "/login", "/dashboard.js", "/dashboard.css", "/burn-graph.js",
        "/alpinejs.min.js", "/vendor/uplot.min.js", "/vendor/uplot.min.css",
        "/fonts/caprasimo-400.woff2", "/fonts/figtree-400.woff2",
        "/fonts/figtree-600.woff2", "/fonts/figtree-700.woff2",
        "/api/reading", "/api/history", "/api/events", "/api/devices/wifi", "/api/settings/status",
        "/api/auth/status",
        "/api/pagekite/status", "/api/bosch",
        "/favicon.ico", "/flue-icon-stove.svg", "/apple-touch-icon.png",
        "/icon-192.png", "/icon-512.png", "/site.webmanifest", "/startup.png",
        "/service-worker.js", "/loading.html"
    };
    if (!strcmp(path, "/api/settings")) return "/api/tunnel/settings";
    for (size_t i = 0; i < sizeof allowed / sizeof allowed[0]; i++)
        if (!strcmp(path, allowed[i])) return allowed[i];
    return NULL;
}
