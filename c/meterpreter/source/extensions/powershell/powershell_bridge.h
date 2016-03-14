/*!
 * @file poweshell_bridge.h
 * @brief Declarations for powershell request handlers (bridged into managed C++)
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BRIDGE_H
#define _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BRIDGE_H

DWORD request_powershell_execute(Remote *remote, Packet *packet);

#endif

