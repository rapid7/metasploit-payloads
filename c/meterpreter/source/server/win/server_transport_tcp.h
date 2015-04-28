#ifndef _METERPRETER_SERVER_SETUP_TCP
#define _METERPRETER_SERVER_SETUP_TCP

Transport* transport_create_tcp(wchar_t* url, TimeoutSettings* timeouts);

#endif