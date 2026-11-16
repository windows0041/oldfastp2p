#ifndef FASTP2P_GATEWAY_H
#define FASTP2P_GATEWAY_H
#include "protocol.h"
#include "store.h"
#include <libwebsockets.h>
#include <netinet/in.h>
#include <stdio.h>
#define GW_MAX_NODES 256
#define GW_MAX_PROBES 128
#define GW_HTTP_LIMIT (64u * 1024u)
/* An upgrade package may be tens of megabytes; cap it so a bad upload cannot
 * fill the disk. */
#define GW_UPLOAD_LIMIT (128ull * 1024ull * 1024ull)
#define GW_QUEUE_LIMIT (4u * 1024u * 1024u)
#define GW_TOTAL_QUEUED (64u * 1024u * 1024u)
/* Login is deliberately expensive (PBKDF2) and runs on the single service
 * thread, so it must be rate limited before any hash is computed. */
#define GW_LOGIN_SLOTS 64
#define GW_LOGIN_WINDOW_MS 60000u
#define GW_LOGIN_MAX_ATTEMPTS 8u
#define GW_LOGIN_FAIL_LOCK 5u
#define GW_LOGIN_LOCK_MS 300000u
/* DUALSTACK-SPEC §1: address-family capability bitmap. Only the two low bits
 * are defined; a missing field in a legacy frame means "IPv4 only". */
#define GW_FAMILY_V4 1u
#define GW_FAMILY_V6 2u
#define GW_FAMILY_BOTH (GW_FAMILY_V4 | GW_FAMILY_V6)
struct login_attempt {
    /* The key used to be a bare network-order IPv4. Login throttling must cover
     * IPv6 sources too, so the key is now the family plus the address bytes
     * (IPv4 in the first four). family 0 means the slot is unused. */
    unsigned char address[16];
    unsigned family;              /* AF_INET / AF_INET6, 0 = unused */
    uint64_t window_start;
    uint64_t locked_until;
    unsigned attempts, failures;
};
struct packet {
    struct packet *next;
    size_t length, offset;
    unsigned char data[];
};
struct connection {
    struct lws *wsi;
    int slot, registered, closing, config_supported;
    char node[32], ip[64], ipv6[128], os[128], mac[128], lan[64], version[64];
    uint64_t id, last_rx, relay_time, active_wall;
    uint64_t last_seen_wall, next_store;
    char hostname[256];
    /* families is the gateway-side view of DUALSTACK-SPEC §1: the observed WSS
     * family is hard evidence, the client-reported bitmap may add the other. */
    unsigned nat, bandwidth, has_ipv4, has_upnp, public_port, major, families, has_ipv6;
    /* Full NAT1..NAT4 level from the inbound-filtering refinement (0 unknown,
     * 5 = cone with untestable filtering). Kept apart from `nat`, which stays a
     * pure mapping observation for the relay filter and for old peers. */
    unsigned nat_level;
    unsigned observed_family; /* GW_FAMILY_V4 / GW_FAMILY_V6 of this socket */
    unsigned tcp_nat, tcp_nat_samples, tcp_nat_ips;
    unsigned nat6, tcp_nat6, tcp_nat6_samples, tcp_nat6_ips;
    struct packet *head, *tail;
    size_t queued, count;
    unsigned char *rx;
    size_t rx_length, rx_capacity;
    /* HTTP transactions share the protocol allocation, never the WS role. */
    char uri[256];
    int post, deleting, authorized, status, headers_sent, handled;
    int put;
    int upload_cache_lock; /* fd + 1, so a zero-initialized connection owns none */
    /* Upgrade packages are far larger than the in-memory HTTP limit, so an
     * upload streams straight to a temporary file while its digest is computed. */
    FILE *upload;
    void *upload_digest;
    uint64_t upload_size;
    char upload_tmp[640], upload_platform[16], upload_version[32];
    uint64_t auth_generation;
    unsigned char *request, *response;
    const char *response_type;
    size_t request_length, response_length, response_offset;
    uint64_t deadline, relay_log_ms;
    struct connection *request_node, *pending_http;
};
struct probe {
    int fd;
    /* Dual-stack: the accepted peer may be AF_INET or AF_INET6, so storage that
     * fits either plus its length is required (the old sockaddr_in truncated a
     * v6 peer address). */
    struct sockaddr_storage peer;
    socklen_t peer_length;
    uint64_t deadline;
    char output[128];
    size_t length, offset;
};
struct nat_state {
    int udp[4], tcp[2];
    /* One independent set per family (SPEC §2). Only populated when the gateway
     * was given an IPv6 bind address. */
    int udp6[4], tcp6[2];
    struct probe probes[GW_MAX_PROBES];
    uint64_t second;
    unsigned packets;
};
struct gateway {
    struct lws_context *context;
    struct lws_vhost *ws_vhost, *api_vhost;
    /* A second WSS listener, typically 443: mobile carriers reset TLS to
     * non-standard ports, so the same gateway is reachable on both. */
    struct lws_vhost *ws_alt_vhost;
    unsigned alt_ws_port;
    /* Per-family vhosts: created only when --bind6 / --apibind6 were given, so a
     * v4-only configuration behaves exactly as before. */
    struct lws_vhost *ws_vhost6, *api_vhost6, *ws_alt_vhost6;
    unsigned alt_ws6_port;
    lws_sorted_usec_list_t tick;
    struct connection *nodes[GW_MAX_NODES];
    uint64_t grants[GW_MAX_NODES][GW_MAX_NODES];
    size_t queued, rx_allocated;
    unsigned max_nodes, timeout, ws_port, api_port, run_seconds;
    char bind[64], api_bind[64], bind6[64], api_bind6[64];
    const char *cert, *key, *user, *password;
    char secret[2048];
    struct gw_admin admin;
    uint64_t auth_generation;
    uint64_t token;
    int reset_admin;
    uint64_t started_ms;
    sqlite3 *db;
    const char *database;
    const char *public_host, *enrollment_ca_file;
    char enrollment_ca[16385];
    /* Upgrade packages live next to the database so a backup covers both. */
    char update_dir[512];
    struct login_attempt logins[GW_LOGIN_SLOTS];
    struct nat_state nat;
};
/* bind6 may be NULL or empty: then no IPv6 probe sockets are created. */
int gw_nat_start(struct nat_state *state, const char *bind, const char *bind6);
void gw_nat_step(struct nat_state *state);
void gw_nat_stop(struct nat_state *state);
#endif
