/*!
 * @file clipboard.h
 * @brief Declarations for clipboard interaction functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_H

DWORD request_clipboard_set_data(Remote *remote, Packet *packet);
DWORD request_clipboard_get_data(Remote *remote, Packet *packet);

#endif
