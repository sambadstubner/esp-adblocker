#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Starts the status/config web UI on the existing Ethernet IP, port 80.
 * No authentication (LAN-trust model, per PLAN.md's scope decision) - anyone
 * on the LAN can view status and change settings.
 */
esp_err_t web_ui_start(void);

#ifdef __cplusplus
}
#endif
