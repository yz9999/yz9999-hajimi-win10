#ifndef HAJIMI_ENGINE_CAPI_H
#define HAJIMI_ENGINE_CAPI_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && defined(HAJIMI_ENGINE_SHARED_BUILD)
#define HAJIMI_ENGINE_API __declspec(dllexport)
#elif defined(_WIN32) && defined(HAJIMI_ENGINE_SHARED_IMPORT)
#define HAJIMI_ENGINE_API __declspec(dllimport)
#elif defined(__GNUC__) || defined(__clang__)
#define HAJIMI_ENGINE_API __attribute__((visibility("default")))
#else
#define HAJIMI_ENGINE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Outbound routing modes */
#define HAJIMI_MODE_RULE   0
#define HAJIMI_MODE_GLOBAL 1
#define HAJIMI_MODE_DIRECT 2

/* Return status codes */
#define HAJIMI_ENGINE_OK                  0
#define HAJIMI_ENGINE_ERR_INVALID_ARG    -1
#define HAJIMI_ENGINE_ERR_PARSE          -2
#define HAJIMI_ENGINE_ERR_IO             -3
#define HAJIMI_ENGINE_ERR_STATE          -4
#define HAJIMI_ENGINE_ERR_OWNERSHIP_LOST -5
#define HAJIMI_ENGINE_ERR_NOT_FOUND      -6
#define HAJIMI_ENGINE_ERR_BUFFER_SMALL   -7

typedef struct HJEngineOpaque *HJEngineRef;

typedef struct HJEngineListenerConfig {
    const char *bind_host;        /* Default "127.0.0.1" */
    uint16_t http_port;           /* 0 = disabled, or port (e.g. 7890) */
    uint16_t socks_port;          /* 0 = disabled, or port (e.g. 7891) */
    uint16_t controller_port;     /* 0 = disabled, or REST controller port (e.g. 9090) */
    uint16_t dns_listen_port;     /* 0 = disabled, or local UDP DNS port */
    const char *controller_key;   /* Optional X-Key / Bearer secret */
    const char *outbound_if_name; /* Optional physical egress interface alias/GUID */
} HJEngineListenerConfig;

/* =========================================================================
 * Engine Lifecycle & Profile Management
 * ========================================================================= */
HAJIMI_ENGINE_API const char *hajimi_engine_version(void);

HAJIMI_ENGINE_API HJEngineRef hajimi_engine_create(void);
HAJIMI_ENGINE_API void hajimi_engine_destroy(HJEngineRef engine);

/* Loads Surge .conf, Clash YAML, or Base64/line share-link subscription text. */
HAJIMI_ENGINE_API int hajimi_engine_load_profile_text(
    HJEngineRef engine,
    const char *profile_text,
    size_t text_len,
    char *err_buf,
    size_t err_cap);

/* Loads profile from a UTF-8 file path (safe for Chinese/Unicode Windows user dirs). */
HAJIMI_ENGINE_API int hajimi_engine_load_profile_file(
    HJEngineRef engine,
    const char *utf8_path,
    char *err_buf,
    size_t err_cap);

/* Starts inbound HTTP/SOCKS5/ExternalController/DNS listeners. */
HAJIMI_ENGINE_API int hajimi_engine_start(
    HJEngineRef engine,
    const HJEngineListenerConfig *config,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API void hajimi_engine_stop(HJEngineRef engine);

/* Query actual bound ports (useful when port 0 ephemeral binding is requested). */
HAJIMI_ENGINE_API uint16_t hajimi_engine_bound_http_port(HJEngineRef engine);
HAJIMI_ENGINE_API uint16_t hajimi_engine_bound_socks_port(HJEngineRef engine);
HAJIMI_ENGINE_API uint16_t hajimi_engine_bound_controller_port(HJEngineRef engine);
HAJIMI_ENGINE_API uint16_t hajimi_engine_bound_dns_port(HJEngineRef engine);

/* =========================================================================
 * Policy Groups, Auto-Probing, RULE-SET & Node Provider Hot Update
 * ========================================================================= */
HAJIMI_ENGINE_API int hajimi_engine_set_outbound_mode(HJEngineRef engine, int mode);
HAJIMI_ENGINE_API int hajimi_engine_get_outbound_mode(HJEngineRef engine);

HAJIMI_ENGINE_API int hajimi_engine_select_policy_group(
    HJEngineRef engine,
    const char *group_name,
    const char *selected_member);

/* Sets or queries the elected leaf proxy node used exclusively in HAJIMI_MODE_GLOBAL
 * ("__AUTO_FASTEST__", "DIRECT", or an exact leaf proxy node name).
 * Strictly independent of HAJIMI_MODE_RULE policy group selections. */
HAJIMI_ENGINE_API int hajimi_engine_set_global_node(
    HJEngineRef engine,
    const char *node_name);

HAJIMI_ENGINE_API int hajimi_engine_get_global_node(
    HJEngineRef engine,
    char *out_node,
    size_t out_cap);

/* Evaluates routing decision for a target host/port/process/protocol. */
HAJIMI_ENGINE_API int hajimi_engine_evaluate_route(
    HJEngineRef engine,
    const char *host,
    uint16_t dst_port,
    const char *protocol_name,
    const char *process_path_or_name,
    char *out_policy,
    size_t out_cap);

/* Measures TCP/protocol handshake RTT in milliseconds, or -1 on timeout/error. */
HAJIMI_ENGINE_API int32_t hajimi_engine_probe_node_latency_ms(
    HJEngineRef engine,
    const char *node_name,
    uint32_t timeout_ms);

/* Concurrently probes all nodes in the loaded profile and automatically updates
 * url-test, fallback, and smart policy groups. Returns count of healthy nodes. */
HAJIMI_ENGINE_API int32_t hajimi_engine_probe_all_nodes(
    HJEngineRef engine,
    uint32_t timeout_ms);

/* Returns JSON array of external RULE-SET / DOMAIN-SET / GEOSITE / GEOIP references.
 * Caller frees via hajimi_engine_free_string. */
HAJIMI_ENGINE_API char *hajimi_engine_get_rulesets_json(HJEngineRef engine);

/* Injects or refreshes an external RULE-SET or GEOIP:CN CIDR payload and hot-recompiles
 * the active routing table without dropping active connections. */
HAJIMI_ENGINE_API int hajimi_engine_update_ruleset(
    HJEngineRef engine,
    const char *key_or_url,
    const char *content_utf8,
    size_t content_len);

/* Returns JSON array of external Clash `proxy-providers` / Surge `policy-path` references.
 * Caller frees via hajimi_engine_free_string. */
HAJIMI_ENGINE_API char *hajimi_engine_get_node_providers_json(HJEngineRef engine);

/* Injects or refreshes an external proxy-provider subscription payload and recomputes
 * dynamic policy groups (`use:`, `include-all-proxies`, regex filters). */
HAJIMI_ENGINE_API int hajimi_engine_update_node_provider(
    HJEngineRef engine,
    const char *key_or_url,
    const char *content_utf8,
    size_t content_len);

/* Returns JSON summary of parsed routing rules, final policy, and active DNS settings.
 * Caller frees via hajimi_engine_free_string. */
HAJIMI_ENGINE_API char *hajimi_engine_get_rules_json(HJEngineRef engine);

/* Notifies transport runtime of Wi-Fi/NIC switch or Modern Standby resume. */
HAJIMI_ENGINE_API void hajimi_engine_notify_network_change(
    HJEngineRef engine,
    const char *new_outbound_if_name);

/* =========================================================================
 * Encrypted DNS & Fake-IP (198.19.0.0/16)
 * ========================================================================= */
HAJIMI_ENGINE_API int hajimi_engine_allocate_fakeip(
    HJEngineRef engine,
    const char *domain,
    char *out_ipv4,
    size_t out_cap);

HAJIMI_ENGINE_API int hajimi_engine_lookup_fakeip_domain(
    HJEngineRef engine,
    const char *ipv4_str,
    char *out_domain,
    size_t out_cap);

HAJIMI_ENGINE_API size_t hajimi_engine_resolve_dns_wire(
    HJEngineRef engine,
    const uint8_t *query_wire,
    size_t query_len,
    uint8_t *resp_buf,
    size_t resp_cap);

HAJIMI_ENGINE_API void hajimi_engine_flush_dns_cache(HJEngineRef engine);
HAJIMI_ENGINE_API void hajimi_engine_flush_fakeip(HJEngineRef engine);

/* =========================================================================
 * Userspace TUN & 16 MiB SPSC Shared Memory Ring Bridge
 * ========================================================================= */
HAJIMI_ENGINE_API int hajimi_engine_attach_shm_tunnel(
    HJEngineRef engine,
    void *shm_base_address,
    uintptr_t rx_event_handle,
    uintptr_t tx_event_handle,
    uint32_t frame_prefix_len);

HAJIMI_ENGINE_API void hajimi_engine_detach_tunnel(HJEngineRef engine);

/* Attaches a BSD `utun` (macOS, frame_prefix_len = 4) or POSIX TUN fd directly to the engine's
 * 64-packet batched `kqueue`/`epoll` userspace tunnel worker. */
HAJIMI_ENGINE_API int hajimi_engine_attach_utun_fd(
    HJEngineRef engine,
    int utun_fd,
    uint32_t frame_prefix_len);

HAJIMI_ENGINE_API void hajimi_engine_detach_utun_fd(HJEngineRef engine);

HAJIMI_ENGINE_API int hajimi_engine_ingest_tunnel_packet(
    HJEngineRef engine,
    const uint8_t *packet,
    size_t packet_len,
    uint32_t frame_prefix_len);

HAJIMI_ENGINE_API size_t hajimi_engine_poll_tunnel_egress(
    HJEngineRef engine,
    uint8_t *out_packet,
    size_t out_cap);

/* =========================================================================
 * Telemetry, Active Connections, Streaming Logs & 5-Stage Network Diagnostics
 * (Caller frees returned strings via hajimi_engine_free_string)
 * ========================================================================= */
HAJIMI_ENGINE_API char *hajimi_engine_get_status_json(HJEngineRef engine);
HAJIMI_ENGINE_API char *hajimi_engine_get_connections_json(HJEngineRef engine);

/* Force-closes a single active connection by `connection_id`, or closes ALL active
 * connections when `connection_id == 0`. Returns count of closed connections. */
HAJIMI_ENGINE_API int32_t hajimi_engine_close_connection(
    HJEngineRef engine,
    uint64_t connection_id);

/* Returns JSON object `{"nextSeq":N,"logs":[{"seq":...,"time":"...","level":"...","msg":"..."}]}`
 * containing structured log entries strictly newer than `since_seq`. */
HAJIMI_ENGINE_API char *hajimi_engine_get_logs_json(
    HJEngineRef engine,
    uint64_t since_seq);

HAJIMI_ENGINE_API char *hajimi_engine_run_diagnostics_json(HJEngineRef engine);
HAJIMI_ENGINE_API void hajimi_engine_free_string(char *heap_str);

/* =========================================================================
 * Windows System Proxy (WinINet + Snapshot Ownership Verification) & Local Process Lookup
 * ========================================================================= */
HAJIMI_ENGINE_API int hajimi_win_sysproxy_enable(
    const char *snapshot_dir_utf8,
    const char *proxy_host,
    uint16_t proxy_port,
    const char *bypass_semicolon_list,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_win_sysproxy_repoint(
    const char *snapshot_dir_utf8,
    const char *new_proxy_host,
    uint16_t new_proxy_port,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_win_sysproxy_disable(
    const char *snapshot_dir_utf8,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_win_sysproxy_is_owned(const char *snapshot_dir_utf8);

/* Cross-platform System Proxy APIs (WinINet on Windows, networksetup/SCDynamicStore on macOS) */
HAJIMI_ENGINE_API int hajimi_sysproxy_enable(
    const char *snapshot_dir_utf8,
    const char *proxy_host,
    uint16_t proxy_port,
    const char *bypass_semicolon_list,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_sysproxy_repoint(
    const char *snapshot_dir_utf8,
    const char *new_proxy_host,
    uint16_t new_proxy_port,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_sysproxy_disable(
    const char *snapshot_dir_utf8,
    char *err_buf,
    size_t err_cap);

HAJIMI_ENGINE_API int hajimi_sysproxy_is_owned(const char *snapshot_dir_utf8);

HAJIMI_ENGINE_API int hajimi_local_process_lookup(
    int is_udp,
    const char *local_ip,
    uint16_t local_port,
    char *out_exe_path,
    size_t out_cap);

HAJIMI_ENGINE_API int hajimi_engine_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* HAJIMI_ENGINE_CAPI_H */
