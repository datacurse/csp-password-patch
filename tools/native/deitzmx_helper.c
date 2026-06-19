/*
 * deitzmx_helper.dll - tiny deferred loader for the de-itzmx Frida engine.
 *
 * Import-injected into CLIPStudioPaint.exe. At process init it does the absolute
 * minimum (schedule a worker thread) so it does NOT initialize the Frida engine
 * during the loader lock - that early presence is what tripped the protector's
 * anti-tamper before (gadget as a static import exited with code 1).
 *
 * The worker thread runs only AFTER process init / loader lock releases, then
 * loads the renamed frida-gadget (deitzmx.dll), which reads deitzmx.config and
 * runs frida_deitzmx.js (the proven password/splash/warning suppression hooks).
 * This reproduces the "late injection" timing that frida.spawn validated.
 */
#include <windows.h>

#define GADGET_NAME L"deitzmx.dll"
/* Fire after the initial loader lock releases but before the splash/password
 * (observed ~2s in). Small delay keeps us clear of the fragile init window. */
#define LOAD_DELAY_MS 250

static HMODULE g_self = NULL;

/* Build an absolute path to a sibling file next to this helper DLL, so the
 * gadget is found regardless of the process working directory. */
static BOOL sibling_path(LPCWSTR name, LPWSTR out, DWORD cch) {
    WCHAR dir[MAX_PATH];
    DWORD n = GetModuleFileNameW(g_self, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return FALSE;
    }
    /* Trim back to the trailing separator (keep it). */
    while (n > 0 && dir[n - 1] != L'\\' && dir[n - 1] != L'/') {
        --n;
    }
    dir[n] = L'\0';

    DWORD i = 0;
    for (DWORD j = 0; dir[j] && i + 1 < cch; ++j) {
        out[i++] = dir[j];
    }
    for (DWORD j = 0; name[j] && i + 1 < cch; ++j) {
        out[i++] = name[j];
    }
    if (i >= cch) {
        return FALSE;
    }
    out[i] = L'\0';
    return TRUE;
}

static DWORD WINAPI worker(LPVOID param) {
    (void)param;
    Sleep(LOAD_DELAY_MS);

#ifndef DEITZMX_NOOP
    WCHAR path[MAX_PATH];
    if (sibling_path(GADGET_NAME, path, MAX_PATH)) {
        LoadLibraryW(path);
    } else {
        LoadLibraryW(GADGET_NAME);
    }
#endif
    return 0;
}

/* Exported so the host's import table can reference a symbol from this DLL.
 * Never actually called; the real work happens in DllMain -> worker. */
__declspec(dllexport) void deitzmx_anchor(void) {
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = (HMODULE)inst;
        DisableThreadLibraryCalls(inst);
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (t) {
            CloseHandle(t);
        }
    }
    return TRUE;
}
