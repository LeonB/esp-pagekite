#pragma once

// Private to the single PageKite worker. Separate fields remain live across
// nested receive -> prepare -> reject calls. Only mutually exclusive connection
// phases overlap. Allocate once in PSRAM so longjmp/reconnect cannot leak it.
typedef struct {
    char path[512], encoding[256], etag[128], request_host[160];
    char cookie[384], origin[256], forwarded_auth[704];
} pagekite_request_buffers_t;

typedef union {
    struct {
        char payload[1024], auth[512], alias_auth[512];
        char request[1500], answers[1200];
    } handshake;
    struct {
        char headers[1024], data[2200], reply[768];
        pagekite_request_buffers_t request;
    } session;
    struct { char payload[320], url[320]; } dns;
} pagekite_buffers_t;
