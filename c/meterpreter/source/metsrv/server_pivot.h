#ifndef _METERPRETER_METSRV_SERVER_PIVOT
#define _METERPRETER_METSRV_SERVER_PIVOT

DWORD request_core_pivot_add(Remote* remote, Packet* packet);
DWORD request_core_pivot_remove(Remote* remote, Packet* packet);

#endif