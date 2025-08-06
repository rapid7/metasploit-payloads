#ifndef _METERPRETER_METSRV_TRANSPORT_WINHTTP
#define _METERPRETER_METSRV_TRANSPORT_WINHTTP

void transport_write_http_config(Transport* transport, Packet* packet, Tlv* configTlv);
Transport* transport_create_http(Packet* packet, Tlv* c2Tlv);

#endif