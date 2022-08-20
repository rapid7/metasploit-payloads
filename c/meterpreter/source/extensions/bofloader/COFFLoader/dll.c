#include <stdio.h>
#include <windows.h>

//extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD Reason, LPVOID LPV) {
//This one was only necessary if you were using a C++ compiler

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Code to run when the DLL is loaded
        break;

    case DLL_PROCESS_DETACH:
        // Code to run when the DLL is freed
        break;

    case DLL_THREAD_ATTACH:
        // Code to run when a thread is created during the DLL's lifetime
        break;

    case DLL_THREAD_DETACH:
        // Code to run when a thread ends normally.
        break;
    }

    return TRUE;
}