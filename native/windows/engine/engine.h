/* AntiOS native engine boundary. See ../LICENSE.microsoft for native module licensing. */
#ifndef AO_ENGINE_H
#define AO_ENGINE_H
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#define AO_MAX_FILE_BYTES (32u * 1024u * 1024u)
#define AO_REPLY_LIMIT 4096u
#define AO_SCAN_TIMEOUT_MS 3000u

enum ao_result { AO_UNKNOWN = 0, AO_THREAT = 1, AO_CLEAR = 2, AO_REVIEW = 3 };
typedef int (*ao_cancel_fn)(void *context);
/* Called on each connected socket before any command/content is sent. */
typedef int (*ao_peer_fn)(uintptr_t socket_value, void *context);
struct ao_outcome {
    enum ao_result result;
    int database_current;
    uint64_t database_generation;
    char name[201];
    char detail[160];
};
enum ao_result ao_parse_reply(const char *reply, size_t length, char name[201]);
int ao_database_current(const char *version, time_t now);
uint64_t ao_database_generation(const char *version);
/* Only 127.0.0.1. The service always supplies 3310; tests may use an ephemeral port. */
struct ao_outcome ao_clam_scan(const unsigned char *data, size_t size, unsigned short port,
                              unsigned timeout_ms, ao_cancel_fn cancelled, void *context);
/* Mandatory verifier; unlike the diagnostic API above, NULL is rejected. */
struct ao_outcome ao_clam_scan_verified(const unsigned char *data, size_t size, unsigned short port,
    unsigned timeout_ms, ao_cancel_fn cancelled, void *context, ao_peer_fn verifier, void *peer_context);
uint64_t ao_clam_generation_verified(unsigned short port, unsigned timeout_ms,
    ao_cancel_fn cancelled, void *context, ao_peer_fn verifier, void *peer_context, int *database_current);
#endif
