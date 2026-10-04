/* Deterministic malformed-input corpus for the native protocol parser. */
#include "../windows/engine/engine.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
int main(void) {
    char reply[AO_REPLY_LIMIT + 8];
    struct { unsigned char before; char name[201]; unsigned char after; } output;
    uint32_t random = 0x51aee25u;
    unsigned iteration;
    for (iteration = 0; iteration < 30000; ++iteration) {
        size_t i, length = iteration % sizeof(reply);
        output.before = 0xa5; output.after = 0x5a;
        for (i = 0; i < length; ++i) {
            random = random * 1664525u + 1013904223u;
            reply[i] = (char)(random >> 24);
        }
        if (iteration % 3 == 0 && length >= 8) memcpy(reply, "stream: ", 8);
        ao_parse_reply(reply, length, output.name);
        assert(output.before == 0xa5 && output.after == 0x5a);
        reply[length < sizeof(reply) ? length : sizeof(reply) - 1] = 0;
        ao_database_current(reply, (time_t)1780000000);
    }
    assert(!ao_database_current("ClamAV 1/123/Sun Jan 01 9999999999999:00:00 2026", (time_t)1780000000));
    return 0;
}
