#ifndef _METERPRETER_SERVER_SETUP_WINHTTP
#define _METERPRETER_SERVER_SETUP_WINHTTP

Transport* transport_create_http(BOOL ssl, wchar_t* url, wchar_t* ua, wchar_t* proxy,
	wchar_t* proxyUser, wchar_t* proxyPass, PBYTE certHash, TimeoutSettings* timeouts);

#endif