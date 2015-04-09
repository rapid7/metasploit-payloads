#ifndef _METERPRETER_SERVER_SETUP_TCP
#define _METERPRETER_SERVER_SETUP_TCP

Transport* transport_create_tcp(wchar_t* url, int expirationTime, int commsTimeout,
	UINT retryTotal, UINT retryWait);

#endif