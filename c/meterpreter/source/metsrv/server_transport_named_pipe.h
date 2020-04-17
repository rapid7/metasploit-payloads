#ifndef _METERPRETER_METSRV_SERVER_SETUP_NAMED_PIPE
#define _METERPRETER_METSRV_SERVER_SETUP_NAMED_PIPE

void transport_write_named_pipe_config(Transport* transport, MetsrvTransportNamedPipe* config);
Transport* transport_create_named_pipe(MetsrvTransportNamedPipe* config, LPDWORD size);

#endif