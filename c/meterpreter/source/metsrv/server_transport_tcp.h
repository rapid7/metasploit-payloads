#ifndef _METERPRETER_METSRV_TRANSPORT_TCP
#define _METERPRETER_METSRV_TRANSPORT_TCP

void transport_write_tcp_config(Transport* transport, Packet* packet, Tlv* configTlv);
Transport* transport_create_tcp(Packet* packet, Tlv* c2Tlv);

#endif