#include "dns_proxy.h"

#include <errno.h>
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
#include "freertos/task.h"
#include "sd_storage.h"

static const char *TAG = "dns_proxy";

// Embedded fallback seed filter (see blocklist/bloom.bin), used only when the
// active bloom_a/bloom_b flash partition is empty or fails to parse - e.g. a
// brand new device that hasn't completed its first blocklist_updater run yet.
extern const uint8_t bloom_bin_start[] asm("_binary_bloom_bin_start");
extern const uint8_t bloom_bin_end[] asm("_binary_bloom_bin_end");

static bloom_filter_t s_bloom;
static bool s_bloom_ready = false;
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
        ESP_LOGI(TAG, "bloom filter loaded from flash (slot %u): %llu domains, %llu bits, k=%u", active,
                 (unsigned long long)s_bloom.header->n_domains,
                 (unsigned long long)s_bloom.header->m_bits,
                 (unsigned)s_bloom.header->k_hashes);
        return;
    }

    size_t len = (size_t)(bloom_bin_end - bloom_bin_start);
    if (bloom_filter_init(bloom_bin_start, len, &s_bloom)) {
        s_bloom_ready = true;
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

/**
 * Returns true if the query was blocked (and a response was already sent to
 * the client) - caller must not forward the query upstream in that case.
 */
static bool try_block(const struct sockaddr_in *client_addr, uint8_t *buf, size_t n,
                       const dns_wire_question_t *q)
{
    if (!s_bloom_ready || !bloom_filter_test(&s_bloom, q->qname)) {
        return false;
    }

    sd_storage_confirm_t confirm = sd_storage_confirm(q->qname);
    if (confirm == SD_STORAGE_CONFIRM_NOT_BLOCKED) {
        ESP_LOGD(TAG, "bloom false-positive rescued by SD confirm: %s", q->qname);
        return false;
    }
    // confirm is BLOCKED (genuinely in the list) or UNAVAILABLE (SD absent/
    // unmounted) - fail safe in the UNAVAILABLE case by blocking on the
    // bloom result alone, per PLAN.md's Phase 4 fail-safe design.

    size_t resp_len = n;
    if (app_config_get_block_policy() == APP_CONFIG_BLOCK_ZERO_IP) {
        size_t new_len = dns_wire_make_zero_answer(buf, n, DNS_WIRE_MAX_MSG_LEN, q->qtype);
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

    dns_wire_question_t q;
    bool have_question = dns_wire_parse_question(buf, (size_t)n, &q);
    if (have_question) {
        ESP_LOGD(TAG, "query from %s: %s type=%u", inet_ntoa(client_addr.sin_addr), q.qname, q.qtype);
        if (try_block(&client_addr, buf, (size_t)n, &q)) {
            return; // blocked - do not forward upstream
        }
    }

    uint16_t client_txid = dns_wire_get_txid(buf, (size_t)n);

    int slot = find_free_slot();
    if (slot < 0) {
        ESP_LOGW(TAG, "pending table full, replying SERVFAIL immediately");
        send_error_to_client(&client_addr, buf, (size_t)n, DNS_RCODE_SERVFAIL);
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
        p->in_use = false;
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

esp_err_t dns_proxy_start(void)
{
    dns_proxy_reload_bloom_filter();

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
