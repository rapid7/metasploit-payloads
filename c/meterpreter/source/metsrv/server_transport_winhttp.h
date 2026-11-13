#ifndef _METERPRETER_METSRV_TRANSPORT_WINHTTP
#define _METERPRETER_METSRV_TRANSPORT_WINHTTP

void transport_write_http_config(Transport* transport, Packet* packet, Tlv* configTlv);
Transport* transport_create_http(Packet* packet, Tlv* c2Tlv);
BOOL async_http_response_queue_start(Remote* remote);
VOID async_http_response_queue_stop_when_idle(Remote* remote);

#endif
