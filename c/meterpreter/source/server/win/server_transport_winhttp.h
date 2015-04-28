#ifndef _METERPRETER_SERVER_SETUP_WINHTTP
#define _METERPRETER_SERVER_SETUP_WINHTTP

void transport_write_http_config(Transport* transport, MetsrvTransportHttp* config);
Transport* transport_create_http(MetsrvTransportHttp* httpConfig);

#endif