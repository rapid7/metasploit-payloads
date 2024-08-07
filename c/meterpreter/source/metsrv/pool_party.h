#include <windows.h>

#define ERROR_POOLPARTY_VARIANT_FAILED 3
#define ERROR_POOLPARTY_GENERIC 1

#define POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION 0
#define POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION 1

DWORD remote_tp_wait_insertion(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE *hTriggerEvent);
DWORD remote_tp_direct_insertion(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent);