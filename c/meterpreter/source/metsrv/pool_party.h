#include <windows.h>
#define ERROR_POOLPARTY_VARIANT_FAILED					3
#define ERROR_POOLPARTY_GENERIC							1

#define POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION			0
//#define POOLPARTY_TECHNIQUE_TP_WAIT_INSERTION			1
//#define POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE	2

#define POOLPARTY_TECHNIQUE_COUNT						1

typedef struct POOL_PARTY_TECHNIQUE_ITEM {
	BOOL isSystemSupported;
	BOOL isInjectionSupported;
	DWORD(*handler)(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent);
} POOL_PARTY_TECHNIQUE_ITEM;

typedef struct POOLPARTY_INJECTOR {
	BOOL init;
	POOL_PARTY_TECHNIQUE_ITEM variants[POOLPARTY_TECHNIQUE_COUNT];
} POOLPARTY_INJECTOR;

BOOL supports_poolparty_injection(DWORD dwSourceArch, DWORD dwDestinationArch);
POOLPARTY_INJECTOR* GetOrInitPoolParty(DWORD dwSourceArch, DWORD dwDestinationArch);
DWORD remote_tp_direct_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent);
//DWORD remote_tp_wait_insertion(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent);
//DWORD worker_factory_start_routine_overwrite(HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* hTriggerEvent);