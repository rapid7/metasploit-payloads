/*!
 * @file wmi_interface.h
 * @brief Declarations for functions that deal directly with WMI
 *        via the COM interfaces.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_WMI_INTERFACE_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_WMI_INTERFACE_H

DWORD wmi_query(LPCWSTR lpwDomain, LPWSTR lpwQuery, Packet* response);

#endif
