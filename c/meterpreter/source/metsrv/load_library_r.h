#include "common.h"
#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6
typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
HANDLE WINAPI load_library_r(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPCSTR cpReflectiveLoaderName, DWORD dwActualReflectiveLoaderOffset, LPVOID lpParameter);