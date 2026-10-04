/* MS-PL. Windows-owned TCP endpoint / SCM process binding, not PPL or attestation. */
#ifndef AO_ENGINE_PEER_H
#define AO_ENGINE_PEER_H
#include <windows.h>
#include <stdint.h>
struct ao_engine_peer { SC_HANDLE manager, service; HANDLE process; DWORD pid; };
DWORD ao_engine_service_name(wchar_t name[81]);
int ao_engine_peer_open(struct ao_engine_peer *peer, const wchar_t *service_name);
int ao_engine_peer_valid(struct ao_engine_peer *peer);
int ao_engine_peer_socket(uintptr_t socket_value, void *context);
void ao_engine_peer_close(struct ao_engine_peer *peer);

#include "../engine/engine.h"
struct ao_outcome ao_engine_scan(const wchar_t *service_name, const void *data, size_t size,
                                unsigned timeout, ao_cancel_fn cancel, void *context);

#endif
