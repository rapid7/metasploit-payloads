#ifndef _METERPRETER_SERVER_REMOTE_DISPATCHER_H
#define _METERPRETER_SERVER_REMOTE_DISPATCHER_H

DWORD request_core_enumextcmd(Remote* pRemote, Packet* pPacket);
DWORD request_core_loadlib(Remote *pRemote, Packet *pPacket);

DWORD load_extension(HMODULE hLibrary, BOOL bLibLoadedReflectivly, Remote* pRemote, Packet* pResponse, Command* pFirstCommand);
DWORD stagelessinit_extension(const char* extensionName, LPBYTE data, DWORD dataSize);

VOID register_dispatch_routines();
VOID deregister_dispatch_routines(Remote * remote);

#endif
