/* AntiOS native broker. Native module licensed under MS-PL; see ../LICENSE.microsoft. */
#ifndef AO_USER_SCAN_H
#define AO_USER_SCAN_H
#include <windows.h>
#define AO_SERVICE_NAME L"AntiOSNative"
typedef void (*ao_log_fn)(WORD level, const wchar_t *message);
/* Owns/join all workers before returning. stop remains owned by the caller. */
DWORD ao_broker_run(HANDLE stop, HANDLE ready, ao_log_fn log);
#endif
