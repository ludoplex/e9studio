/*
 * clion_bridge.h
 * CLion IDE integration header
 *
 * Copyright (C) 2024 E9Patch Contributors
 * License: GPLv3+
 */

#ifndef E9_CLION_BRIDGE_H
#define E9_CLION_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize IDE bridge
 * @param port WebSocket server port (default: 9229)
 * @return 0 on success, -1 on error
 */
int e9ide_init(int port);

/*
 * Shutdown IDE bridge
 */
void e9ide_shutdown(void);

/*
 * Add a file to watch for changes
 * @param path Path to source file
 * @return 0 on success, -1 on error
 */
int e9ide_watch_file(const char *path);

/*
 * Send patch result to IDE
 * @param address Address that was patched
 * @param success Whether patch succeeded
 * @param error Error message (if any)
 */
void e9ide_send_patch_result(intptr_t address, int success, const char *error);

#ifdef __cplusplus
}
#endif

#endif /* E9_CLION_BRIDGE_H */
