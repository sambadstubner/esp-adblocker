#include "web_ui.h"

#include <arpa/inet.h>
#include <string.h>

#include "app_config.h"
#include "blocklist_updater.h"
#include "cJSON.h"
#include "dns_proxy.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "eth_init.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "fw_updater.h"
#include "sd_storage.h"

static const char *TAG = "web_ui";

#define MAX_POST_BODY_LEN 1024
#define MAX_URL_FIELD_LEN 256

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[] asm("_binary_index_html_end");

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    size_t len = (size_t)(index_html_end - index_html_start);
    return httpd_resp_send(req, (const char *)index_html_start, len);
}

static esp_err_t send_json(httpd_req_t *req, cJSON *obj)
{
    char *text = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (text == NULL) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, text, HTTPD_RESP_USE_STRLEN);
    cJSON_free(text);
    return err;
}

static esp_err_t status_get_handler(httpd_req_t *req)
{
    dns_proxy_stats_t stats;
    dns_proxy_get_stats(&stats);
    dns_proxy_bloom_info_t bloom;
    dns_proxy_get_bloom_info(&bloom);

    cJSON *root = cJSON_CreateObject();
    int64_t uptime_s = (esp_timer_get_time() - stats.start_time_us) / 1000000;
    cJSON_AddNumberToObject(root, "uptime_s", (double)uptime_s);
    cJSON_AddNumberToObject(root, "queries_total", stats.queries_total);
    cJSON_AddNumberToObject(root, "queries_blocked", stats.queries_blocked);
    cJSON_AddNumberToObject(root, "queries_forwarded", stats.queries_forwarded);
    cJSON_AddNumberToObject(root, "queries_servfail", stats.queries_servfail);
    cJSON_AddNumberToObject(root, "queries_blocked_24h", stats.queries_blocked_24h);

    cJSON_AddBoolToObject(root, "bloom_ready", bloom.ready);
    cJSON_AddBoolToObject(root, "bloom_from_seed", bloom.from_embedded_seed);
    cJSON_AddNumberToObject(root, "bloom_domains", (double)bloom.n_domains);
    cJSON_AddNumberToObject(root, "bloom_build_unix_ts", (double)bloom.build_unix_ts);
    cJSON_AddNumberToObject(root, "bloom_active_slot", app_config_get_bloom_active_slot());
    cJSON_AddNumberToObject(root, "exact_list_active_slot", app_config_get_exact_list_active_slot());
    cJSON_AddBoolToObject(root, "sd_mounted", sd_storage_is_mounted());

    esp_netif_t *netif = eth_init_get_netif();
    esp_netif_ip_info_t ip_info;
    if (netif != NULL && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        char buf[16];
        cJSON_AddStringToObject(root, "eth_ip", esp_ip4addr_ntoa(&ip_info.ip, buf, sizeof(buf)));
        cJSON_AddStringToObject(root, "eth_mask", esp_ip4addr_ntoa(&ip_info.netmask, buf, sizeof(buf)));
        cJSON_AddStringToObject(root, "eth_gw", esp_ip4addr_ntoa(&ip_info.gw, buf, sizeof(buf)));
    }

    cJSON_AddStringToObject(root, "fw_version", esp_app_get_description()->version);
    cJSON_AddNumberToObject(root, "free_heap", (double)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "free_psram", (double)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));

    return send_json(req, root);
}

static esp_err_t config_get_handler(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    char buf[16];

    cJSON_AddNumberToObject(root, "net_mode", app_config_get_net_mode());
    esp_netif_ip_info_t static_ip;
    if (app_config_get_static_ip(&static_ip) == ESP_OK) {
        cJSON_AddStringToObject(root, "static_ip", esp_ip4addr_ntoa(&static_ip.ip, buf, sizeof(buf)));
        cJSON_AddStringToObject(root, "static_mask", esp_ip4addr_ntoa(&static_ip.netmask, buf, sizeof(buf)));
        cJSON_AddStringToObject(root, "static_gw", esp_ip4addr_ntoa(&static_ip.gw, buf, sizeof(buf)));
    }

    esp_ip4_addr_t u1 = { .addr = app_config_get_upstream1() };
    esp_ip4_addr_t u2 = { .addr = app_config_get_upstream2() };
    cJSON_AddStringToObject(root, "upstream1", esp_ip4addr_ntoa(&u1, buf, sizeof(buf)));
    cJSON_AddStringToObject(root, "upstream2", esp_ip4addr_ntoa(&u2, buf, sizeof(buf)));

    cJSON_AddNumberToObject(root, "block_policy", app_config_get_block_policy());
    cJSON_AddBoolToObject(root, "blocking_enabled", app_config_get_blocking_enabled());

    char url_buf[MAX_URL_FIELD_LEN];
    app_config_get_blocklist_url(url_buf, sizeof(url_buf));
    cJSON_AddStringToObject(root, "blocklist_url", url_buf);
    cJSON_AddNumberToObject(root, "blocklist_refresh_interval_hours", app_config_get_blocklist_refresh_interval_hours());
    app_config_get_fw_update_url(url_buf, sizeof(url_buf));
    cJSON_AddStringToObject(root, "fw_update_url", url_buf);

    return send_json(req, root);
}

static bool read_body(httpd_req_t *req, char *buf, size_t buf_len)
{
    if (req->content_len <= 0 || (size_t)req->content_len >= buf_len) {
        return false;
    }
    int received = 0;
    while (received < req->content_len) {
        int r = httpd_req_recv(req, buf + received, req->content_len - received);
        if (r <= 0) {
            return false;
        }
        received += r;
    }
    buf[received] = '\0';
    return true;
}

static void respond_ok(httpd_req_t *req, bool reboot_required)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", true);
    cJSON_AddBoolToObject(root, "reboot_required", reboot_required);
    send_json(req, root);
}

static void respond_error(httpd_req_t *req, const char *message)
{
    httpd_resp_set_status(req, "400 Bad Request");
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "ok", false);
    cJSON_AddStringToObject(root, "error", message);
    send_json(req, root);
}

static esp_err_t config_post_handler(httpd_req_t *req)
{
    char body[MAX_POST_BODY_LEN];
    if (!read_body(req, body, sizeof(body))) {
        respond_error(req, "request body missing or too large");
        return ESP_OK;
    }

    cJSON *json = cJSON_Parse(body);
    if (json == NULL) {
        respond_error(req, "invalid JSON");
        return ESP_OK;
    }

    bool reboot_required = false;
    bool upstream_changed = false;
    const cJSON *item;

    item = cJSON_GetObjectItem(json, "upstream1");
    if (cJSON_IsString(item)) {
        app_config_set_upstream1(esp_ip4addr_aton(item->valuestring));
        upstream_changed = true;
    }
    item = cJSON_GetObjectItem(json, "upstream2");
    if (cJSON_IsString(item)) {
        app_config_set_upstream2(esp_ip4addr_aton(item->valuestring));
        upstream_changed = true;
    }
    item = cJSON_GetObjectItem(json, "block_policy");
    if (cJSON_IsNumber(item)) {
        app_config_set_block_policy((app_config_block_policy_t)item->valueint);
    }
    item = cJSON_GetObjectItem(json, "blocking_enabled");
    if (cJSON_IsBool(item)) {
        app_config_set_blocking_enabled(cJSON_IsTrue(item));
    }
    item = cJSON_GetObjectItem(json, "blocklist_url");
    if (cJSON_IsString(item)) {
        app_config_set_blocklist_url(item->valuestring);
    }
    item = cJSON_GetObjectItem(json, "blocklist_refresh_interval_hours");
    if (cJSON_IsNumber(item)) {
        app_config_set_blocklist_refresh_interval_hours((uint32_t)item->valuedouble);
    }
    item = cJSON_GetObjectItem(json, "fw_update_url");
    if (cJSON_IsString(item)) {
        app_config_set_fw_update_url(item->valuestring);
    }

    item = cJSON_GetObjectItem(json, "net_mode");
    if (cJSON_IsNumber(item)) {
        app_config_set_net_mode((app_config_net_mode_t)item->valueint);
        reboot_required = true;
    }
    const cJSON *sip = cJSON_GetObjectItem(json, "static_ip");
    const cJSON *smask = cJSON_GetObjectItem(json, "static_mask");
    const cJSON *sgw = cJSON_GetObjectItem(json, "static_gw");
    if (cJSON_IsString(sip) && cJSON_IsString(smask) && cJSON_IsString(sgw)) {
        esp_netif_ip_info_t ip_info = {
            .ip.addr = esp_ip4addr_aton(sip->valuestring),
            .netmask.addr = esp_ip4addr_aton(smask->valuestring),
            .gw.addr = esp_ip4addr_aton(sgw->valuestring),
        };
        app_config_set_static_ip(&ip_info);
        reboot_required = true;
    }

    cJSON_Delete(json);

    if (upstream_changed) {
        dns_proxy_apply_upstream_config();
    }

    respond_ok(req, reboot_required);
    return ESP_OK;
}

static esp_err_t allowlist_get_handler(httpd_req_t *req)
{
    char buf[APP_CONFIG_ALLOWLIST_MAX_LEN];
    app_config_get_allowlist(buf, sizeof(buf));
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "allowlist", buf);
    return send_json(req, root);
}

static esp_err_t allowlist_post_handler(httpd_req_t *req)
{
    char body[APP_CONFIG_ALLOWLIST_MAX_LEN];
    if (!read_body(req, body, sizeof(body))) {
        respond_error(req, "request body missing or too large");
        return ESP_OK;
    }

    cJSON *json = cJSON_Parse(body);
    const cJSON *item = json ? cJSON_GetObjectItem(json, "allowlist") : NULL;
    if (!cJSON_IsString(item)) {
        cJSON_Delete(json);
        respond_error(req, "expected {\"allowlist\": \"domain-per-line string\"}");
        return ESP_OK;
    }

    app_config_set_allowlist(item->valuestring);
    cJSON_Delete(json);
    dns_proxy_reload_allowlist();
    respond_ok(req, false);
    return ESP_OK;
}

static esp_err_t querylog_get_handler(httpd_req_t *req)
{
    // CONFIG_DNS_PROXY_QUERY_LOG_SIZE entries (280 bytes each, ~28KB at the
    // default of 100) would badly overflow the httpd task's 6KB stack as a
    // local array - heap-allocate instead, from PSRAM since it's plentiful
    // and this is a large, short-lived, non-performance-critical buffer.
    dns_proxy_query_log_entry_t *entries = heap_caps_malloc(
        CONFIG_DNS_PROXY_QUERY_LOG_SIZE * sizeof(dns_proxy_query_log_entry_t), MALLOC_CAP_SPIRAM);
    if (entries == NULL) {
        respond_error(req, "out of memory");
        return ESP_OK;
    }

    size_t count = dns_proxy_get_query_log(entries, CONFIG_DNS_PROXY_QUERY_LOG_SIZE);
    int64_t now = esp_timer_get_time();

    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++) {
        cJSON *e = cJSON_CreateObject();
        cJSON_AddStringToObject(e, "qname", entries[i].qname);
        cJSON_AddNumberToObject(e, "qtype", entries[i].qtype);
        cJSON_AddNumberToObject(e, "result", entries[i].result);
        cJSON_AddNumberToObject(e, "seconds_ago", (double)((now - entries[i].time_us) / 1000000));
        struct in_addr client = { .s_addr = entries[i].client_ip };
        cJSON_AddStringToObject(e, "client_ip", inet_ntoa(client));
        cJSON_AddItemToArray(arr, e);
    }
    heap_caps_free(entries);

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "entries", arr);
    return send_json(req, root);
}

static esp_err_t update_blocklist_post_handler(httpd_req_t *req)
{
    char url[MAX_URL_FIELD_LEN];
    app_config_get_blocklist_url(url, sizeof(url));
    if (url[0] == '\0') {
        respond_error(req, "blocklist_url is not configured");
        return ESP_OK;
    }
    blocklist_updater_check_and_apply_async(url);
    respond_ok(req, false);
    return ESP_OK;
}

static esp_err_t update_firmware_post_handler(httpd_req_t *req)
{
    char url[MAX_URL_FIELD_LEN];
    app_config_get_fw_update_url(url, sizeof(url));
    if (url[0] == '\0') {
        respond_error(req, "fw_update_url is not configured");
        return ESP_OK;
    }
    fw_updater_check_and_update_async(url);
    respond_ok(req, false);
    return ESP_OK;
}

static void delayed_reboot_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(500)); // let the HTTP response flush first
    esp_restart();
}

static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    respond_ok(req, false);
    xTaskCreate(delayed_reboot_task, "reboot", 2048, NULL, 4, NULL);
    return ESP_OK;
}

esp_err_t web_ui_start(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.stack_size = 6144; // the allowlist/querylog handlers use larger on-stack buffers than the default 4096 comfortably allows
    config.max_uri_handlers = 12; // default of 8 is too small now that allowlist/querylog routes exist

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return err;
    }

    static const httpd_uri_t routes[] = {
        { .uri = "/", .method = HTTP_GET, .handler = root_get_handler },
        { .uri = "/api/status", .method = HTTP_GET, .handler = status_get_handler },
        { .uri = "/api/config", .method = HTTP_GET, .handler = config_get_handler },
        { .uri = "/api/config", .method = HTTP_POST, .handler = config_post_handler },
        { .uri = "/api/allowlist", .method = HTTP_GET, .handler = allowlist_get_handler },
        { .uri = "/api/allowlist", .method = HTTP_POST, .handler = allowlist_post_handler },
        { .uri = "/api/querylog", .method = HTTP_GET, .handler = querylog_get_handler },
        { .uri = "/api/update/blocklist", .method = HTTP_POST, .handler = update_blocklist_post_handler },
        { .uri = "/api/update/firmware", .method = HTTP_POST, .handler = update_firmware_post_handler },
        { .uri = "/api/reboot", .method = HTTP_POST, .handler = reboot_post_handler },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(server, &routes[i]);
    }

    ESP_LOGI(TAG, "web UI listening on port %d", config.server_port);
    return ESP_OK;
}
