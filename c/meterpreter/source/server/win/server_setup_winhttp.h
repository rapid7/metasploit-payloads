#ifndef _METERPRETER_SERVER_SETUP_WINHTTP
#define _METERPRETER_SERVER_SETUP_WINHTTP

DWORD server_dispatch_http_winhttp(Remote * remote, THREAD* serverThread, int iExpirationTimeout, int iCommTimeout,
	wchar_t* pMetUA, wchar_t* pMetProxy, wchar_t* pMetProxyUser, wchar_t* pMetProxyPass);

#endif