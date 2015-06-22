/*!
 * @file clipboard.h
 * @brief Declarations for clipboard interaction functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_H

DWORD initialise_clipboard();
DWORD request_clipboard_set_data(Remote *remote, Packet *packet);
DWORD request_clipboard_get_data(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_start(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_pause(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_resume(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_stop(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_purge(Remote *remote, Packet *packet);
DWORD request_clipboard_monitor_dump(Remote *remote, Packet *packet);

#endif
