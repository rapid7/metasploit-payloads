/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kuhl_m_standard.h"

const KUHL_M_C kuhl_m_c_standard[] = {
	//{kuhl_m_standard_test,		L"test",	L"Test routine (you don\'t want to see this !)"},
	{kuhl_m_standard_exit,		L"exit",	L"Quit mimikatz"},
	{kuhl_m_standard_cls,		L"cls",		L"Clear screen (doesn\'t work with redirections, like PsExec)"},
	{kuhl_m_standard_answer,	L"answer",	L"Answer to the Ultimate Question of Life, the Universe, and Everything"},
	{kuhl_m_standard_sleep,		L"sleep",	L"Sleep an amount of milliseconds"},
	{kuhl_m_standard_base64,	L"base64",	L"Switch file output/base64 output"},
	{kuhl_m_standard_version,	L"version",	L"Display some version informations"},
};
const KUHL_M kuhl_m_standard = {
	L"standard",	L"Standard module",	L"Basic commands (does not require module name)",
	sizeof(kuhl_m_c_standard) / sizeof(KUHL_M_C), kuhl_m_c_standard, NULL, NULL
};
/*
NTSTATUS kuhl_m_standard_test(int argc, wchar_t * argv[])
{
	return STATUS_SUCCESS;
}
*/
NTSTATUS kuhl_m_standard_exit(int argc, wchar_t * argv[])
{
	kprintf(L"Bye!\n");
	return STATUS_FATAL_APP_EXIT;
}

NTSTATUS kuhl_m_standard_cls(int argc, wchar_t * argv[])
{
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD coord = {0, 0};
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	GetConsoleScreenBufferInfo(hStdOut, &csbi);
	FillConsoleOutputCharacter(hStdOut, L' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(hStdOut, coord);
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_answer(int argc, wchar_t * argv[])
{
	kprintf(L"42.\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_sleep(int argc, wchar_t * argv[])
{
	DWORD dwMilliseconds = argc ? wcstoul(argv[0], NULL, 0) : 1000;
	kprintf(L"Sleep : %u ms... ", dwMilliseconds);
	Sleep(dwMilliseconds);
	kprintf(L"End !\n");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_base64(int argc, wchar_t * argv[])
{
	kprintf(L"isBase64Intercept was : %s\n", isBase64Intercept ? L"true" : L"false");
	isBase64Intercept = !isBase64Intercept;
	kprintf(L"isBase64Intercept is now : %s\n", isBase64Intercept ? L"true" : L"false");
	return STATUS_SUCCESS;
}

NTSTATUS kuhl_m_standard_version(int argc, wchar_t * argv[])
{
	BOOL isWow64;
	HMODULE hModule;
	HRSRC hRsrc;
	HGLOBAL hGlobRsrc;
	LPVOID ptrRsrc;
	UINT size;
	VS_FIXEDFILEINFO * infos;
	OSVERSIONINFOEX osVersionInfos;
	osVersionInfos.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	#ifdef _M_X64
	isWow64 = TRUE;
	#endif
	
	if(
		GetVersionEx((LPOSVERSIONINFO) &osVersionInfos)
		#ifdef _M_IX86
		&& IsWow64Process(GetCurrentProcess(), &isWow64)
		#endif
		)
	{
		kprintf(
			L"\n" MIMIKATZ L" " MIMIKATZ_VERSION L" (arch " MIMIKATZ_ARCH L")\n"
			L"API    -  Windows NT %u.%u build %u service pack %hu.%hu (arch x%s)\n"
			L"NT     -  Windows NT %u.%u build %u\n",
			osVersionInfos.dwMajorVersion, osVersionInfos.dwMinorVersion,
			osVersionInfos.dwBuildNumber, osVersionInfos.wServicePackMajor, osVersionInfos.wServicePackMinor, isWow64 ? L"64" : L"86",
			MIMIKATZ_NT_MAJOR_VERSION, MIMIKATZ_NT_MINOR_VERSION, MIMIKATZ_NT_BUILD_NUMBER
			);
	}
	
	if(hModule = GetModuleHandle(L"msvcrt"))
	{
		if(hRsrc = FindResource(hModule, MAKEINTRESOURCE(VS_VERSION_INFO), RT_VERSION))
		{
			if(hGlobRsrc = LoadResource(hModule, hRsrc))
			{
				if(ptrRsrc = LockResource(hGlobRsrc))
				{
					if(VerQueryValue(ptrRsrc, L"\\", (LPVOID *) &infos, &size))
						kprintf(L"MSVCRT -  %hu.%hu.%hu.%hu\n", ((PUSHORT) &infos->dwFileVersionMS)[1], ((PUSHORT) &infos->dwFileVersionMS)[0], ((PUSHORT) &infos->dwFileVersionLS)[1], ((PUSHORT) &infos->dwFileVersionLS)[0]);
					UnlockResource(ptrRsrc);
				}
				FreeResource(hGlobRsrc);
			}
		}
	}
	return STATUS_SUCCESS;
}
