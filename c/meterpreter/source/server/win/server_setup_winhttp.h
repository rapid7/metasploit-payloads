#ifndef _METERPRETER_SERVER_SETUP_WINHTTP
#define _METERPRETER_SERVER_SETUP_WINHTTP

DWORD server_dispatch_http_winhttp(Remote* remote, THREAD* dispatchThread);
BOOL server_init_http_winhttp(Remote* remote, SOCKET fd);
BOOL server_deinit_http_winhttp(Remote* remote);

#endif