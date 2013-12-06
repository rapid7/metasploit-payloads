/*!
 * @file adsi.h
 * @brief Declarations for ADSI support.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_ADSI_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_ADSI_H

DWORD request_adsi_user_enum(Remote *remote, Packet *packet);
DWORD request_adsi_computer_enum(Remote *remote, Packet *packet);

#endif
