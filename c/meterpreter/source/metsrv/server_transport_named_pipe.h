#ifndef _METERPRETER_METSRV_SERVER_SETUP_NAMED_PIPE
#define _METERPRETER_METSRV_SERVER_SETUP_NAMED_PIPE

void transport_write_named_pipe_config(Transport* transport, Packet* packet, Tlv* configTlv);
Transport* transport_create_named_pipe(Packet* packet, Tlv* c2Tlv);

#endif