#ifndef _METERPRETER_SERVER_REMOTE_DISPATCHER_H
#define _METERPRETER_SERVER_REMOTE_DISPATCHER_H

DWORD request_core_enumextcmd(Remote* pRemote, Packet* pPacket);
DWORD request_core_loadlib(Remote *pRemote, Packet *pPacket);

DWORD initialise_extension(HMODULE hLibrary, BOOL bLibLoadedReflectivly, Remote* pRemote, Packet* pResponse, Command* pFirstCommand);

VOID register_dispatch_routines();
VOID deregister_dispatch_routines(Remote * remote);

#endif
