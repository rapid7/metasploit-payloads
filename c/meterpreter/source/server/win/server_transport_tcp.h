#ifndef _METERPRETER_SERVER_TRANSPORT_TCP
#define _METERPRETER_SERVER_TRANSPORT_TCP

void transport_write_tcp_config(Transport* transport, MetsrvTransportTcp* config);
Transport* transport_create_tcp(MetsrvTransportTcp* tcpConfig);

#endif