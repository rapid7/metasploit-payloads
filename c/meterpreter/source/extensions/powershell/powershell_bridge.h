/*!
 * @file powershell_bridge.h
 * @brief Declarations for powershell request handlers (bridged into managed C++)
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BRIDGE_H
#define _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BRIDGE_H

DWORD initialize_dotnet_host();
VOID deinitialize_dotnet_host();
DWORD request_powershell_execute(Remote *remote, Packet *packet);
DWORD request_powershell_shell(Remote *remote, Packet *packet);
DWORD request_powershell_session_remove(Remote *remote, Packet *packet);

#endif

