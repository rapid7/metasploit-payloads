/*!
 * @file adsi_interface.h
 * @brief Declarations for functions that deal directly with ADSI
 *        via the COM interfaces (hence the .cpp extension).
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_ADSI_INTERFACE_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_ADSI_INTERFACE_H

DWORD domain_user_enum(LPCWSTR lpDomain, Packet* response);
DWORD domain_computer_enum(LPCWSTR lpDomain, Packet* response);

#endif
