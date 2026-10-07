/* AntiOS AMSI coexistence provider.
 * Independent ClamAV-backed scanning that does not replace or disable Defender.
 * The provider accepts only verdicts from the configured own-process LocalSystem
 * ClamD service through the same SCM/PID/socket verification used by the native
 * minifilter broker.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <objbase.h>
#include <new>
#include <string.h>
#include <wchar.h>
#include "../service/engine_peer.h"
#include "../engine/engine.h"

static const CLSID CLSID_AntiOSAmsiProvider =
{0x8e8a9d7d,0x814f,0x4a83,{0xa1,0x27,0x8c,0x48,0x94,0xe4,0x11,0x21}};

static volatile LONG g_objects = 0;
static volatile LONG g_locks = 0;

static DWORD managed_engine_service_name(wchar_t name[81]) {
    DWORD bytes = 81 * sizeof(wchar_t), error, i;
    ZeroMemory(name, bytes);
    error = RegGetValueW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\AntiOS",
        L"EngineServiceName",
        RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
        NULL,
        name,
        &bytes
    );
    if (error) return error;
    if (!name[0] || name[80]) return ERROR_INVALID_DATA;
    for (i = 0; name[i]; ++i) {
        wchar_t c = name[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'-')) {
            return ERROR_INVALID_DATA;
        }
    }
    return ERROR_SUCCESS;
}

class AntiOSAmsiProvider final : public IAntimalwareProvider {
public:
    AntiOSAmsiProvider() : refs_(1) { InterlockedIncrement(&g_objects); }
    ~AntiOSAmsiProvider() { InterlockedDecrement(&g_objects); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (IsEqualIID(iid, __uuidof(IUnknown)) || IsEqualIID(iid, __uuidof(IAntimalwareProvider))) {
            *object = static_cast<IAntimalwareProvider *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return (ULONG)InterlockedIncrement(&refs_);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG value = InterlockedDecrement(&refs_);
        if (!value) delete this;
        return (ULONG)value;
    }

    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream *stream, AMSI_RESULT *result) override {
        ULONGLONG size = 0, offset = 0;
        ULONG returned = 0;
        unsigned char *buffer = nullptr;
        wchar_t service_name[81];
        struct ao_outcome outcome = {AO_UNKNOWN, 0, "", "not scanned"};

        if (!stream || !result) return E_INVALIDARG;
        *result = AMSI_RESULT_NOT_DETECTED;

        HRESULT hr = stream->GetAttribute(
            AMSI_ATTRIBUTE_CONTENT_SIZE,
            sizeof(size),
            reinterpret_cast<unsigned char *>(&size),
            &returned
        );
        if (FAILED(hr) || returned != sizeof(size) || !size || size > AO_MAX_FILE_BYTES) {
            return S_OK;
        }

        buffer = static_cast<unsigned char *>(
            HeapAlloc(GetProcessHeap(), 0, static_cast<SIZE_T>(size))
        );
        if (!buffer) return S_OK;

        while (offset < size) {
            ULONG requested = (ULONG)((size - offset) > 65536 ? 65536 : (size - offset));
            ULONG read = 0;
            hr = stream->Read(offset, requested, buffer + offset, &read);
            if (FAILED(hr) || !read || read > requested) {
                HeapFree(GetProcessHeap(), 0, buffer);
                return S_OK;
            }
            offset += read;
        }

        if (managed_engine_service_name(service_name) == ERROR_SUCCESS) {
            /* Keep AMSI latency bounded. Unknown/timeout is fail-open so another
               provider, including Defender, remains free to make its own decision. */
            outcome = ao_engine_scan(
                service_name,
                buffer,
                static_cast<size_t>(size),
                1500,
                nullptr,
                nullptr
            );
        }
        HeapFree(GetProcessHeap(), 0, buffer);

        if (outcome.result == AO_THREAT) {
            *result = AMSI_RESULT_DETECTED;
        }
        return S_OK;
    }

    void STDMETHODCALLTYPE CloseSession(ULONGLONG session) override {
        (void)session;
    }

    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR *display_name) override {
        static const wchar_t name[] = L"AntiOS ClamAV Coexistence Provider";
        size_t bytes;
        if (!display_name) return E_INVALIDARG;
        *display_name = nullptr;
        bytes = sizeof(name);
        LPWSTR copy = static_cast<LPWSTR>(CoTaskMemAlloc(bytes));
        if (!copy) return E_OUTOFMEMORY;
        memcpy(copy, name, bytes);
        *display_name = copy;
        return S_OK;
    }

private:
    volatile LONG refs_;
};

class AntiOSClassFactory final : public IClassFactory {
public:
    AntiOSClassFactory() : refs_(1) { InterlockedIncrement(&g_objects); }
    ~AntiOSClassFactory() { InterlockedDecrement(&g_objects); }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (IsEqualIID(iid, __uuidof(IUnknown)) || IsEqualIID(iid, __uuidof(IClassFactory))) {
            *object = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return (ULONG)InterlockedIncrement(&refs_);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG value = InterlockedDecrement(&refs_);
        if (!value) delete this;
        return (ULONG)value;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *outer, REFIID iid, void **object) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        if (!object) return E_POINTER;
        *object = nullptr;
        AntiOSAmsiProvider *provider = new (std::nothrow) AntiOSAmsiProvider();
        if (!provider) return E_OUTOFMEMORY;
        HRESULT hr = provider->QueryInterface(iid, object);
        provider->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&g_locks);
        else InterlockedDecrement(&g_locks);
        return S_OK;
    }

private:
    volatile LONG refs_;
};

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(
    REFCLSID clsid, REFIID iid, void **object
) {
    if (!object) return E_POINTER;
    *object = nullptr;
    if (!IsEqualCLSID(clsid, CLSID_AntiOSAmsiProvider)) return CLASS_E_CLASSNOTAVAILABLE;
    AntiOSClassFactory *factory = new (std::nothrow) AntiOSClassFactory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT hr = factory->QueryInterface(iid, object);
    factory->Release();
    return hr;
}

extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow(void) {
    return (InterlockedCompareExchange(&g_objects, 0, 0) == 0 &&
            InterlockedCompareExchange(&g_locks, 0, 0) == 0) ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
