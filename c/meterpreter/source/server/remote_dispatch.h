#ifndef _METERPRETER_SERVER_REMOTE_DISPATCHER_H
#define _METERPRETER_SERVER_REMOTE_DISPATCHER_H

DWORD request_core_listextensions(Remote* pRemote, Packet* pPacket);
DWORD request_core_loadlib(Remote *pRemote, Packet *pPacket);


VOID register_dispatch_routines();
VOID deregister_dispatch_routines(Remote * remote);

#endif
