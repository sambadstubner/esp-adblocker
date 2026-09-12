#include "dns_proxy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "app_config.h"
#include "bloom_filter.h"
#include "dns_wire.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "sd_storage.h"

static const char *TAG = "dns_proxy";

_Static_assert(DNS_PROXY_QUERY_LOG_NAME_LEN == DNS_WIRE_MAX_NAME_LEN,
               "query log qname buffer should match dns_wire's - keep these in sync");

// Embedded fallback seed filter (see blocklist/bloom.bin), used only when the
// active bloom_a/bloom_b flash partition is empty or fails to parse - e.g. a
// brand new device that hasn't completed its first blocklist_updater run yet.
extern const uint8_t bloom_bin_start[] asm("_binary_bloom_bin_start");
extern const uint8_t bloom_bin_end[] asm("_binary_bloom_bin_end");

static bloom_filter_t s_bloom;
static bool s_bloom_ready = false;
static bool s_bloom_from_seed = false;
static esp_partition_mmap_handle_t s_bloom_mmap_handle;
static bool s_bloom_mmap_active = false;

typedef struct {
    bool in_use;
    struct sockaddr_in client_addr;
    uint16_t client_txid;
    int64_t sent_at_us;
    size_t query_len;
    uint8_t query_buf[DNS_WIRE_MAX_MSG_LEN];
} pending_query_t;

static pending_query_t s_pending[CONFIG_DNS_PROXY_MAX_PENDING];
static int s_listen_sock = -1;
static int s_upstream_sock = -1;
static uint8_t s_upstream_index = 0; // 0 -> upstream1, 1 -> upstream2
static int s_consecutive_timeouts = 0;
static dns_proxy_stats_t s_stats;

// User-managed allowlist (see app_config_get/set_allowlist). Small and rarely
// checked (only on a bloom-positive), so a plain linear scan is plenty fast -
// no need for the sorted-array/bsearch treatment sd_storage uses for the
// much larger exact block list.
static char *s_allowlist_buf = NULL;
static char **s_allowlist_entries = NULL;
static size_t s_allowlist_count = 0;

// Recent-query ring buffer for the web UI's query log.
static dns_proxy_query_log_entry_t s_query_log[CONFIG_DNS_PROXY_QUERY_LOG_SIZE];
static size_t s_query_log_next = 0;  // index the *next* logged entry will occupy
static size_t s_query_log_count = 0; // valid entries so far, caps at array size
static SemaphoreHandle_t s_query_log_mutex = NULL;

static uint32_t current_upstream_ip(void)
{
    return s_upstream_index == 0 ? app_config_get_upstream1() : app_config_get_upstream2();
}

static esp_err_t connect_upstream_socket(void)
{
    if (s_upstream_sock >= 0) {
        close(s_upstream_sock);
    }
    s_upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ESP_RETURN_ON_FALSE(s_upstream_sock >= 0, ESP_FAIL, TAG, "upstream socket() failed: errno %d", errno);

    struct sockaddr_in upstream_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = current_upstream_ip(),
    };
    // connect() on a UDP socket fixes the peer: recv() then only accepts datagrams
    // from this address (cheap anti-spoofing) and we can use send()/recv() on it.
    if (connect(s_upstream_sock, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) != 0) {
        ESP_LOGE(TAG, "connect() to upstream failed: errno %d", errno);
        close(s_upstream_sock);
        s_upstream_sock = -1;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "upstream resolver set to %s", inet_ntoa(upstream_addr.sin_addr));
    return ESP_OK;
}

static void fail_over_upstream(void)
{
    s_upstream_index = (s_upstream_index == 0) ? 1 : 0;
    s_consecutive_timeouts = 0;
    ESP_LOGW(TAG, "too many consecutive upstream timeouts, failing over to upstream index %d", s_upstream_index);
    connect_upstream_socket();
}

static int find_free_slot(void)
{
    for (int i = 0; i < CONFIG_DNS_PROXY_MAX_PENDING; i++) {
        if (!s_pending[i].in_use) {
            return i;
        }
    }
    return -1;
}

static void send_error_to_client(const struct sockaddr_in *to, uint8_t *buf, size_t len, uint8_t rcode)
{
    dns_wire_make_error_response(buf, len, rcode);
    sendto(s_listen_sock, buf, len, 0, (const struct sockaddr *)to, sizeof(*to));
}

static bool try_load_bloom_from_partition(uint8_t slot)
{
    const char *label = slot == 0 ? "bloom_a" : "bloom_b";
    const esp_partition_t *part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, label);
    if (part == NULL) {
        ESP_LOGW(TAG, "partition %s not found", label);
        return false;
    }

    if (s_bloom_mmap_active) {
        esp_partition_munmap(s_bloom_mmap_handle);
        s_bloom_mmap_active = false;
    }

    const void *mapped = NULL;
    esp_partition_mmap_handle_t handle;
    esp_err_t err = esp_partition_mmap(part, 0, part->size, ESP_PARTITION_MMAP_DATA, &mapped, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mmap of %s failed: %s", label, esp_err_to_name(err));
        return false;
    }

    if (!bloom_filter_init((const uint8_t *)mapped, part->size, &s_bloom)) {
        esp_partition_munmap(handle);
        return false; // blank (freshly-erased) or corrupt slot
    }

    s_bloom_mmap_handle = handle;
    s_bloom_mmap_active = true;
    return true;
}

/**
 * (Re)loads the bloom filter from the currently-active flash slot, falling
 * back to the embedded seed filter if that slot is empty/invalid. Call this
 * at startup and again after blocklist_updater successfully activates a new
 * slot, so an update takes effect without a reboot.
 */
void dns_proxy_reload_bloom_filter(void)
{
    uint8_t active = app_config_get_bloom_active_slot();
    if (try_load_bloom_from_partition(active)) {
        s_bloom_ready = true;
        s_bloom_from_seed = false;
        ESP_LOGI(TAG, "bloom filter loaded from flash (slot %u): %llu domains, %llu bits, k=%u", active,
                 (unsigned long long)s_bloom.header->n_domains,
                 (unsigned long long)s_bloom.header->m_bits,
                 (unsigned)s_bloom.header->k_hashes);
        return;
    }

    size_t len = (size_t)(bloom_bin_end - bloom_bin_start);
    if (bloom_filter_init(bloom_bin_start, len, &s_bloom)) {
        s_bloom_ready = true;
        s_bloom_from_seed = true;
        ESP_LOGW(TAG, "flash slot %u empty/invalid - using embedded seed filter: "
                       "%llu domains, %llu bits, k=%u", active,
                 (unsigned long long)s_bloom.header->n_domains,
                 (unsigned long long)s_bloom.header->m_bits,
                 (unsigned)s_bloom.header->k_hashes);
    } else {
        s_bloom_ready = false;
        ESP_LOGE(TAG, "embedded seed bloom.bin also failed to parse - blocking disabled");
    }
}

void dns_proxy_reload_allowlist(void)
{
    if (s_allowlist_buf != NULL) {
        free(s_allowlist_buf);
        s_allowlist_buf = NULL;
    }
    if (s_allowlist_entries != NULL) {
        free(s_allowlist_entries);
        s_allowlist_entries = NULL;
    }
    s_allowlist_count = 0;

    char *buf = malloc(APP_CONFIG_ALLOWLIST_MAX_LEN);
    if (buf == NULL) {
        ESP_LOGE(TAG, "no memory for allowlist buffer");
        return;
    }
    if (app_config_get_allowlist(buf, APP_CONFIG_ALLOWLIST_MAX_LEN) != ESP_OK || buf[0] == '\0') {
        free(buf);
        return; // no allowlist configured - not an error
    }

    size_t line_count = 1;
    for (const char *p = buf; *p != '\0'; p++) {
        if (*p == '\n') {
            line_count++;
        }
    }

    char **entries = malloc(line_count * sizeof(char *));
    if (entries == NULL) {
        ESP_LOGE(TAG, "no memory for allowlist entries");
        free(buf);
        return;
    }

    size_t count = 0;
    char *line_start = buf;
    for (char *p = buf;; p++) {
        if (*p == '\n' || *p == '\0') {
            bool at_end = (*p == '\0');
            *p = '\0';
            if (line_start[0] != '\0') {
                entries[count++] = line_start;
            }
            line_start = p + 1;
            if (at_end) {
                break;
            }
        }
    }

    s_allowlist_buf = buf;
    s_allowlist_entries = entries;
    s_allowlist_count = count;
    ESP_LOGI(TAG, "allowlist loaded: %zu domain(s)", count);
}

static bool is_allowlisted(const char *qname)
{
    for (size_t i = 0; i < s_allowlist_count; i++) {
        if (strcmp(qname, s_allowlist_entries[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void log_query(uint32_t client_ip, const char *qname, uint16_t qtype, dns_proxy_query_result_t result)
{
    if (s_query_log_mutex == NULL || xSemaphoreTake(s_query_log_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return; // diagnostic-only feature - never worth blocking the hot path over
    }
    dns_proxy_query_log_entry_t *e = &s_query_log[s_query_log_next];
    e->time_us = esp_timer_get_time();
    e->client_ip = client_ip;
    e->qtype = qtype;
    e->result = result;
    strncpy(e->qname, qname, sizeof(e->qname) - 1);
    e->qname[sizeof(e->qname) - 1] = '\0';

    s_query_log_next = (s_query_log_next + 1) % CONFIG_DNS_PROXY_QUERY_LOG_SIZE;
    if (s_query_log_count < CONFIG_DNS_PROXY_QUERY_LOG_SIZE) {
        s_query_log_count++;
    }
    xSemaphoreGive(s_query_log_mutex);
}

size_t dns_proxy_get_query_log(dns_proxy_query_log_entry_t *out, size_t max_entries)
{
    if (s_query_log_mutex == NULL || xSemaphoreTake(s_query_log_mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return 0;
    }
    size_t count = s_query_log_count < max_entries ? s_query_log_count : max_entries;
    for (size_t i = 0; i < count; i++) {
        // s_query_log_next is the slot the *next* write will use, so the most
        // recently written entry is one behind it; walk backward from there.
        size_t idx = (s_query_log_next + CONFIG_DNS_PROXY_QUERY_LOG_SIZE - 1 - i) % CONFIG_DNS_PROXY_QUERY_LOG_SIZE;
        out[i] = s_query_log[idx];
    }
    xSemaphoreGive(s_query_log_mutex);
    return count;
}

/**
 * Returns true if the query was blocked (and a response was already sent to
 * the client) - caller must not forward the query upstream in that case.
 */
static bool try_block(const struct sockaddr_in *client_addr, uint8_t *buf, size_t n,
                       const dns_wire_question_t *q)
{
    if (!app_config_get_blocking_enabled() || !s_bloom_ready || !bloom_filter_test(&s_bloom, q->qname)) {
        return false;
    }

    if (is_allowlisted(q->qname)) {
        ESP_LOGD(TAG, "allowlisted, overriding block: %s", q->qname);
        return false;
    }

    sd_storage_confirm_t confirm = sd_storage_confirm(q->qname);
    if (confirm == SD_STORAGE_CONFIRM_NOT_BLOCKED) {
        ESP_LOGD(TAG, "bloom false-positive rescued by SD confirm: %s", q->qname);
        return false;
    }
    // confirm is BLOCKED (genuinely in the list) or UNAVAILABLE (SD absent/
    // unmounted) - fail safe in the UNAVAILABLE case by blocking on the
    // bloom result alone rather than silently letting the query through.

    size_t resp_len = n;
    if (app_config_get_block_policy() == APP_CONFIG_BLOCK_ZERO_IP) {
        size_t new_len = dns_wire_make_zero_answer(buf, q->question_end, DNS_WIRE_MAX_MSG_LEN, q->qtype);
        if (new_len > 0) {
            resp_len = new_len;
        } else {
            dns_wire_make_error_response(buf, n, DNS_RCODE_NXDOMAIN); // qtype has no sensible zero-answer
        }
    } else {
        dns_wire_make_error_response(buf, n, DNS_RCODE_NXDOMAIN);
    }
    sendto(s_listen_sock, buf, resp_len, 0, (const struct sockaddr *)client_addr, sizeof(*client_addr));
    ESP_LOGI(TAG, "blocked %s (sd_confirm=%d)", q->qname, (int)confirm);
    return true;
}

static void handle_client_datagram(void)
{
    uint8_t buf[DNS_WIRE_MAX_MSG_LEN];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int n = recvfrom(s_listen_sock, buf, sizeof(buf), 0, (struct sockaddr *)&client_addr, &addr_len);
    if (n <= 0) {
        return;
    }
    s_stats.queries_total++;

    dns_wire_question_t q;
    bool have_question = dns_wire_parse_question(buf, (size_t)n, &q);
    if (have_question) {
        ESP_LOGD(TAG, "query from %s: %s type=%u", inet_ntoa(client_addr.sin_addr), q.qname, q.qtype);
        if (try_block(&client_addr, buf, (size_t)n, &q)) {
            s_stats.queries_blocked++;
            log_query(client_addr.sin_addr.s_addr, q.qname, q.qtype, DNS_PROXY_RESULT_BLOCKED);
            return; // blocked - do not forward upstream
        }
    }

    uint16_t client_txid = dns_wire_get_txid(buf, (size_t)n);

    int slot = find_free_slot();
    if (slot < 0) {
        ESP_LOGW(TAG, "pending table full, replying SERVFAIL immediately");
        send_error_to_client(&client_addr, buf, (size_t)n, DNS_RCODE_SERVFAIL);
        s_stats.queries_servfail++;
        if (have_question) {
            log_query(client_addr.sin_addr.s_addr, q.qname, q.qtype, DNS_PROXY_RESULT_SERVFAIL);
        }
        return;
    }

    pending_query_t *p = &s_pending[slot];
    p->client_addr = client_addr;
    p->client_txid = client_txid;
    p->sent_at_us = esp_timer_get_time();
    p->query_len = (size_t)n;
    memcpy(p->query_buf, buf, (size_t)n);

    // Rewrite the txid to this slot's index: with many clients multiplexed through
    // one upstream socket, the txid is the only correlation key on the way back.
    dns_wire_set_txid(p->query_buf, p->query_len, (uint16_t)slot);
    if (send(s_upstream_sock, p->query_buf, p->query_len, 0) < 0) {
        ESP_LOGW(TAG, "send() to upstream failed: errno %d", errno);
    }
    p->in_use = true;
    s_stats.queries_forwarded++;
    if (have_question) {
        log_query(client_addr.sin_addr.s_addr, q.qname, q.qtype, DNS_PROXY_RESULT_FORWARDED);
    }
}

static void handle_upstream_datagram(void)
{
    uint8_t buf[DNS_WIRE_MAX_MSG_LEN];
    int n = recv(s_upstream_sock, buf, sizeof(buf), 0);
    if (n <= 0) {
        return;
    }
    uint16_t slot_txid = dns_wire_get_txid(buf, (size_t)n);
    if (slot_txid >= CONFIG_DNS_PROXY_MAX_PENDING || !s_pending[slot_txid].in_use) {
        ESP_LOGD(TAG, "dropping unmatched/late upstream reply (txid=%u)", slot_txid);
        return;
    }
    pending_query_t *p = &s_pending[slot_txid];
    dns_wire_set_txid(buf, (size_t)n, p->client_txid);
    sendto(s_listen_sock, buf, (size_t)n, 0, (const struct sockaddr *)&p->client_addr, sizeof(p->client_addr));
    p->in_use = false;
    s_consecutive_timeouts = 0;
}

static void sweep_timeouts(void)
{
    int64_t now = esp_timer_get_time();
    int64_t timeout_us = (int64_t)CONFIG_DNS_PROXY_UPSTREAM_TIMEOUT_MS * 1000;
    for (int i = 0; i < CONFIG_DNS_PROXY_MAX_PENDING; i++) {
        pending_query_t *p = &s_pending[i];
        if (!p->in_use || (now - p->sent_at_us) < timeout_us) {
            continue;
        }
        ESP_LOGW(TAG, "upstream timeout for txid=%u", p->client_txid);
        dns_wire_set_txid(p->query_buf, p->query_len, p->client_txid);
        send_error_to_client(&p->client_addr, p->query_buf, p->query_len, DNS_RCODE_SERVFAIL);
        dns_wire_question_t q;
        if (dns_wire_parse_question(p->query_buf, p->query_len, &q)) {
            log_query(p->client_addr.sin_addr.s_addr, q.qname, q.qtype, DNS_PROXY_RESULT_SERVFAIL);
        }
        p->in_use = false;
        s_stats.queries_servfail++;
        s_consecutive_timeouts++;
        if (s_consecutive_timeouts >= CONFIG_DNS_PROXY_UPSTREAM_FAIL_THRESHOLD) {
            fail_over_upstream();
        }
    }
}

static void dns_proxy_task(void *arg)
{
    (void)arg;
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(s_listen_sock, &rfds);
        FD_SET(s_upstream_sock, &rfds);
        int maxfd = (s_listen_sock > s_upstream_sock) ? s_listen_sock : s_upstream_sock;

        struct timeval tv = { .tv_sec = 0, .tv_usec = 200 * 1000 };
        int ready = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (ready > 0) {
            if (FD_ISSET(s_listen_sock, &rfds)) {
                handle_client_datagram();
            }
            if (FD_ISSET(s_upstream_sock, &rfds)) {
                handle_upstream_datagram();
            }
        }
        sweep_timeouts();
    }
}

void dns_proxy_get_stats(dns_proxy_stats_t *out)
{
    *out = s_stats;
}

void dns_proxy_get_bloom_info(dns_proxy_bloom_info_t *out)
{
    memset(out, 0, sizeof(*out));
    out->ready = s_bloom_ready;
    out->from_embedded_seed = s_bloom_from_seed;
    if (s_bloom_ready) {
        out->n_domains = s_bloom.header->n_domains;
        out->m_bits = s_bloom.header->m_bits;
        out->k_hashes = s_bloom.header->k_hashes;
        out->build_unix_ts = s_bloom.header->build_unix_ts;
    }
}

void dns_proxy_apply_upstream_config(void)
{
    s_upstream_index = 0;
    s_consecutive_timeouts = 0;
    connect_upstream_socket();
}

esp_err_t dns_proxy_start(void)
{
    memset(&s_stats, 0, sizeof(s_stats));
    s_stats.start_time_us = esp_timer_get_time();

    s_query_log_mutex = xSemaphoreCreateMutex();
    ESP_RETURN_ON_FALSE(s_query_log_mutex != NULL, ESP_ERR_NO_MEM, TAG, "query log mutex create failed");

    dns_proxy_reload_bloom_filter();
    dns_proxy_reload_allowlist();

    struct sockaddr_in listen_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_DNS_PROXY_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    s_listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ESP_RETURN_ON_FALSE(s_listen_sock >= 0, ESP_FAIL, TAG, "listen socket() failed: errno %d", errno);
    ESP_RETURN_ON_FALSE(bind(s_listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) == 0,
                         ESP_FAIL, TAG, "bind() failed: errno %d", errno);

    ESP_RETURN_ON_ERROR(connect_upstream_socket(), TAG, "initial upstream connect failed");

    BaseType_t ok = xTaskCreate(dns_proxy_task, "dns_proxy", CONFIG_DNS_PROXY_TASK_STACK, NULL,
                                 CONFIG_DNS_PROXY_TASK_PRIORITY, NULL);
    ESP_RETURN_ON_FALSE(ok == pdPASS, ESP_ERR_NO_MEM, TAG, "xTaskCreate failed");

    ESP_LOGI(TAG, "listening on UDP :%d", CONFIG_DNS_PROXY_PORT);
    return ESP_OK;
}
