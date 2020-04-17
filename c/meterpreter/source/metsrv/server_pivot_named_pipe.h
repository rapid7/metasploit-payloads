#ifndef _METERPRETER_METSRV_PIVOT_NAMED_PIPE
#define _METERPRETER_METSRV_PIVOT_NAMED_PIPE

typedef struct _NamedPipeContext NamedPipeContext;

DWORD request_core_pivot_add_named_pipe(Remote* remote, Packet* packet);

#endif