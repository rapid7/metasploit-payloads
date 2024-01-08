#include "precomp.h"
#include "common_metapi.h"
#include "../tiny-regex-c/re.h"

#ifndef __kernel_entry
#define __kernel_entry
#endif

typedef __kernel_entry NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS) (HANDLE ProcessHandle, DWORD ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef SIZE_T(WINAPI* VIRTUALQUERYEX) (HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

typedef BOOL(WINAPI* CLOSEHANDLE) (HANDLE hObject);

typedef HANDLE(WINAPI* OPENPROCESS) (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

typedef FARPROC(WINAPI* GETPROCADDRESS) (HMODULE hModule, LPCSTR lpProcName);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtReadVirtualMemory.html
// https://ntdoc.m417z.com/ntreadvirtualmemory
typedef NTSTATUS(NTAPI* NTREADVIRTUALMEMORY) (HANDLE ProcessHandle, LPCVOID BaseAddress, LPVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FMEMORY_INFORMATION_CLASS.html
typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

// https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef
VOID
(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved4[104];
	PVOID Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved6[128];
	PVOID Reserved7[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26
} PROCESSINFOCLASS;

/*!
 * @brief Allocates memory in the context of the supplied process.
 * @remark The 
 *     - TLV_TYPE_HANDLE          - The process handle to allocate memory within.
 *     - TLV_TYPE_LENGTH          - The amount of memory to allocate.
 *     - TLV_TYPE_ALLOCATION_TYPE - The type of memory to allocate.
 *     - TLV_TYPE_PROTECTION      - The protection flags to allocate the memory with.
 *     - TLV_TYPE_BASE_ADDRESS    - The address to allocate the memory at.
 */
DWORD request_sys_process_memory_allocate(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;
	DWORD alloc, prot;

	// Snag the TLV values
	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);
	size = (SIZE_T)met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
	alloc = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ALLOCATION_TYPE);
	prot = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROTECTION);

	// Allocate the memory
	if ((base = VirtualAllocEx(handle, base, size, alloc, prot)))
	{
		met_api->packet.add_tlv_qword(response, TLV_TYPE_BASE_ADDRESS, (QWORD)base);
	}
	else
	{
		result = GetLastError();
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Free memory in the context of the supplied process
 *
 * req: TLV_TYPE_HANDLE       - The handle to free memory within.
 * req: TLV_TYPE_BASE_ADDRESS - The base address of the memory to free.
 * opt: TLV_TYPE_LENGTH       - The size, in bytes, to free.
 */
DWORD request_sys_process_memory_free(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);

	// Free the memory
	if (!VirtualFreeEx(handle, base, 0, MEM_RELEASE))
		result = GetLastError();

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Read memory from the context of the supplied process at a given address for a
 * given length
 *
 * req: TLV_TYPE_HANDLE       - The handle of the process to read from.
 * req: TLV_TYPE_BASE_ADDRESS - The address to read from.
 * req: TLV_TYPE_LENGTH       - The number of bytes to read.
 */
DWORD request_sys_process_memory_read(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	LPVOID buffer = NULL;
	HANDLE handle;
	SIZE_T size;
	LPVOID base;
	SIZE_T bytesRead = 0;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);
	size   = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	do
	{
		// No handle, base, or size supplied?
		if ((!handle) ||
		    (!base) ||
		    (!size))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Allocate storage for to read into
		if (!(buffer = malloc(size)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Read the memory from the process...break out on failure
		if ((!ReadProcessMemory(handle, base, buffer, size, &bytesRead)) &&
		    (GetLastError() != ERROR_PARTIAL_COPY))
		{
			result = GetLastError();
			break;
		}

		// Add the raw buffer to the response
		met_api->packet.add_tlv_raw(response, TLV_TYPE_PROCESS_MEMORY, buffer,
				(DWORD)bytesRead);

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	// Free the temporary storage
	if (buffer)
		free(buffer);

	return ERROR_SUCCESS;
}

/*
 * Read memory from the context of the supplied process at a given address for a
 * given length
 *
 * req: TLV_TYPE_HANDLE         - The handle of the process to read from.
 * req: TLV_TYPE_BASE_ADDRESS   - The address to read from.
 * req: TLV_TYPE_PROCESS_MEMORY - The raw memory to write to the address.
 */
DWORD request_sys_process_memory_write(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;
	size_t written = 0;
	Tlv data;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);

	do
	{
		// Invalid handle, base, or data?
		if ((!handle) ||
		    (!base) ||
		    (met_api->packet.get_tlv(packet, TLV_TYPE_PROCESS_MEMORY, &data)) != ERROR_SUCCESS)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Write the memory
		if ((!WriteProcessMemory(handle, base, data.buffer, data.header.length, 
				&written)) &&
		    (GetLastError() != ERROR_PARTIAL_COPY))
		{
			result = GetLastError();
			break;
		}

		// Set the number of bytes actually written on the response
		met_api->packet.add_tlv_uint(response, TLV_TYPE_LENGTH, (DWORD)written);

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Queries an address region for its attributes, such as size and protection
 *
 * req: TLV_TYPE_HANDLE       - The process handle to operate on.
 * req: TLV_TYPE_BASE_ADDRESS - The address to query the attributes of.
 */
DWORD request_sys_process_memory_query(Remote *remote, Packet *packet)
{
	MEMORY_BASIC_INFORMATION info;
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	LPVOID base;
	DWORD result = ERROR_SUCCESS;
	SIZE_T size = 0;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);

	// Zero the info buffer
	memset(&info, 0, sizeof(info));

	do
	{
		// Validate parameters
		if (!handle)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// No bytes returned?  Suck.
		if (!(size = VirtualQueryEx(handle, base, &info, sizeof(info))))
		{
			result = GetLastError();
			break;
		}

		// Pass the parameters back to the requestor
		met_api->packet.add_tlv_qword(response, TLV_TYPE_BASE_ADDRESS,	(QWORD)info.BaseAddress);
		met_api->packet.add_tlv_qword(response, TLV_TYPE_ALLOC_BASE_ADDRESS, (QWORD)info.AllocationBase);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_ALLOC_PROTECTION, info.AllocationProtect);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_LENGTH, (DWORD)info.RegionSize);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_MEMORY_STATE, (DWORD)info.State);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_PROTECTION, info.Protect);
		met_api->packet.add_tlv_uint(response, TLV_TYPE_MEMORY_TYPE, info.Type);

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Changes the protection flags on one or more pages
 *
 * req: TLV_TYPE_HANDLE       - The process handle to operate on
 * req: TLV_TYPE_BASE_ADDRESS - The base address to re-protect
 * req: TLV_TYPE_LENGTH       - The length of the region to re-protect
 * req: TLV_TYPE_PROTECTION   - The new protection mask
 */
DWORD request_sys_process_memory_protect(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	LPVOID base;
	SIZE_T size;
	DWORD prot, old;
	DWORD result = ERROR_SUCCESS;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);
	base   = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);
	size   = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
	prot   = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROTECTION);

	do
	{
		// Validate parameters
		if ((!handle) ||
		    (!base) ||
		    (!size))
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Change the protection mask
		if (!VirtualProtectEx(handle, base, size, prot, &old))
		{
			result = GetLastError();
			break;
		}

		// Return the old protection mask to the requestor
		met_api->packet.add_tlv_uint(response, TLV_TYPE_PROTECTION, old);

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Lock a region of memory in physical memory so that it cannot be swapped 
 * out.
 *
 * req: TLV_TYPE_BASE_ADDRESS - The base address to lock
 * req: TLV_TYPE_LENGTH       - The size of the region to lock
 */
DWORD request_sys_process_memory_lock(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;

	base = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);
	size = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	if (!VirtualLock(base, size))
		result = GetLastError();

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Unlock a region so that it can be swapped to disk.
 *
 * req: TLV_TYPE_BASE_ADDRESS - The base address to lock
 * req: TLV_TYPE_LENGTH       - The size of the region to lock
 */
DWORD request_sys_process_memory_unlock(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	LPVOID base;
	SIZE_T size;
	DWORD result = ERROR_SUCCESS;

	base = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_BASE_ADDRESS);
	size = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LENGTH);

	if (!VirtualUnlock(base, size))
		result = GetLastError();

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

BOOL can_read_memory(DWORD memory_protect)
{
	const int page_execute_read = 0x20;
	const int page_execute_readwrite = 0x40;
	const int page_readonly = 0x02;
	const int page_readwrite = 0x04;

	return memory_protect == page_execute_read ||
		memory_protect == page_execute_readwrite ||
		memory_protect == page_readonly ||
		memory_protect == page_readwrite;
}

typedef struct {
	re_t compiled_regex[MAX_REGEXP_OBJECTS];
	unsigned char buffer[MAX_CHAR_CLASS_LEN]; // Used for character strings when "[]" is used.
} RegexNeedle;

#define NEEDLES_MAX (size_t)5
#define MEMORY_BUFFER_SIZE (size_t)(64 * 1024 * 1024)

/// <summary>
/// Add the needle results to a packet. This automatically inserts each result into a new group. Returns ERROR_SUCCESS on success, or 1 on failure.
/// </summary>
/// <param name="packet">The packet to insert the needle group into</param>
/// <returns>ERROR_SUCCESS on success, else non-zero</returns>
NTSTATUS add_needle_results_to_packet(Packet* packet, const unsigned char* memory_buffer_ptr, size_t match_length, size_t match_address, size_t memory_base_address, size_t memory_region_size)
{
	if (packet == NULL || memory_buffer_ptr == NULL) { return ERROR_INVALID_PARAMETER; }

	dprintf("[MEM SEARCH] Creating results group");
	Packet* search_results = met_api->packet.create_group();
	if (search_results == NULL) { dprintf("[MEM SEARCH] Could not create search result group"); return ERROR_OUTOFMEMORY; }

	dprintf("[MEM SEARCH] Adding results to packet group");
	// Note: This raw data needs to be read from the buffer we copied. Trying to read it from mem.BaseAddress directly will make us crash.
	met_api->packet.add_tlv_raw(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_STR, (LPVOID)memory_buffer_ptr, (DWORD)match_length + 1);
	met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR, match_address);
	met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_START_ADDR, memory_base_address);
	met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_SECT_LEN, memory_region_size);
	met_api->packet.add_tlv_uint(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_LEN, (UINT)match_length);

	met_api->packet.add_group(packet, TLV_TYPE_MEMORY_SEARCH_RESULTS, search_results);

	return ERROR_SUCCESS;
}

static HMODULE hKernel32 = NULL;
static HMODULE hNTDLL = NULL;

static GETPROCADDRESS fGetProcAddress = NULL;
static OPENPROCESS fOpenProcess = NULL;
static CLOSEHANDLE fCloseHandle = NULL;
static VIRTUALQUERYEX fVirtualQueryEx = NULL;
static NTREADVIRTUALMEMORY fNtReadVirtualMemory = NULL;

NTSTATUS setup_handles()
{
	if ((hKernel32 = GetModuleHandleA("kernel32.dll")) == NULL) { dprintf("[MEM SEARCH] Could not get kernel32.dll handle"); return ERROR_INVALID_HANDLE; }

	if ((hNTDLL = GetModuleHandleA("ntdll.dll")) == NULL) { dprintf("[MEM SEARCH] Could not get ntdll.dll handle"); return ERROR_INVALID_HANDLE; }

	if ((fGetProcAddress = (GETPROCADDRESS)GetProcAddress(hKernel32, "GetProcAddress")) == NULL) { dprintf("[MEM SEARCH] Could not get GetProcAddress handle"); return ERROR_INVALID_ADDRESS; }

	if ((fVirtualQueryEx = (VIRTUALQUERYEX)fGetProcAddress(hKernel32, "VirtualQueryEx")) == NULL) { dprintf("[MEM SEARCH] Could not get VirtualQueryEx handle"); return ERROR_INVALID_ADDRESS; }

	if ((fOpenProcess = (OPENPROCESS)fGetProcAddress(hKernel32, "OpenProcess")) == NULL) { dprintf("[MEM SEARCH] Could not get OpenProcess handle"); return ERROR_INVALID_ADDRESS; }

	if ((fCloseHandle = (CLOSEHANDLE)fGetProcAddress(hKernel32, "CloseHandle")) == NULL) { dprintf("[MEM SEARCH] Could not get CloseHandle handle"); return ERROR_INVALID_ADDRESS; }

	if ((fNtReadVirtualMemory = (NTREADVIRTUALMEMORY)fGetProcAddress(hNTDLL, "NtReadVirtualMemory")) == NULL ) { dprintf("[MEM SEARCH] Could not get NtReadVirtualMemory handle"); return ERROR_INVALID_ADDRESS; }

	return ERROR_SUCCESS;
}

/*
 * Read through all of a process's virtual memory in the search for regular expression needles.
 *
 * req: TLV_TYPE_PID                     - The target process ID.
 * req: TLV_TYPE_MEMORY_SEARCH_NEEDLE    - The regular expression needle to search for.
 * req: TLV_TYPE_UINT                    - The minimum length of a match.
 * req: TLV_TYPE_MEMORY_SEARCH_MATCH_LEN - The maximum length of a match.
 */
DWORD request_sys_process_memory_search(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	unsigned char* memory_buffer = NULL;
	size_t needle_enum_index = 0;
	HANDLE process_handle = NULL;
	RegexNeedle regex_needles[NEEDLES_MAX] = { NULL };
	
	dprintf("[MEM SEARCH] Getting PID");
	const DWORD pid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PID);
	if (pid == 0) { result = ERROR_INVALID_PARAMETER; goto done; }
	dprintf("[MEM SEARCH] Searching PID: %lu", pid);

	Tlv needle_tlv = { 0 };
	while (needle_enum_index < NEEDLES_MAX && met_api->packet.enum_tlv(packet, (DWORD)needle_enum_index, TLV_TYPE_MEMORY_SEARCH_NEEDLE, &needle_tlv) == ERROR_SUCCESS)
	{
		dprintf("[MEM SEARCH] Compiling needle regex from TLV");
		const int result = re_compile(needle_tlv.buffer, needle_tlv.header.length - 1, (re_t)&regex_needles[needle_enum_index].compiled_regex, (unsigned char*)&regex_needles[needle_enum_index].buffer);
		if (result != ERROR_SUCCESS)
		{
			dprintf("[MEM SEARCH] Failed to setup compile needle regex from TLV packet");
			goto done;
		}

		needle_enum_index++;
	}

	dprintf("[MEM SEARCH] Getting Match Lengths");
	const size_t min_match_length = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_UINT);
	const size_t max_match_length = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_MEMORY_SEARCH_MATCH_LEN);
	if (min_match_length > max_match_length || max_match_length == 0) { dprintf("[MEM SEARCH] Incorrect min or max match lengths"); result = ERROR_INVALID_PARAMETER; goto done; }
	const size_t current_max_match_length = max_match_length;

	dprintf("[MEM SEARCH] Getting handles & proc addresses");
	if ((result = setup_handles()) != ERROR_SUCCESS)
	{
		dprintf("[MEM SEARCH] Could not set up all necessary handles & proc addresses");
		goto done;
	}

	const DWORD process_vm_read = 0x0010;
	const DWORD process_query_information = 0x0400;
	const DWORD wanted_process_perms = process_vm_read | process_query_information;

	dprintf("[MEM SEARCH] Opening process");
	process_handle = fOpenProcess(wanted_process_perms, FALSE, pid);
	if (process_handle == NULL) { dprintf("[MEM SEARCH] Could not get process handle"); result = ERROR_INVALID_HANDLE; goto done; }

	MEMORY_BASIC_INFORMATION mem = { 0 };
	dprintf("[MEM SEARCH] Allocating buffer for storing process memory");
	memory_buffer = (unsigned char*)malloc(MEMORY_BUFFER_SIZE * sizeof(unsigned char));
	if (memory_buffer == NULL) { dprintf("[MEM SEARCH] Could not allocate memory buffer"); result = ERROR_OUTOFMEMORY; goto done; }

	for (size_t current_ptr = 0; fVirtualQueryEx(process_handle, (LPCVOID)current_ptr, &mem, sizeof(mem)); current_ptr += mem.RegionSize)
	{
		if (!can_read_memory(mem.Protect)) { continue; }

		size_t memory_region_offset = 0;
		// Note: This currently does not support regex'ing over multiple memory regions.
		// e.g.
		// regex = "my_password.*";
		// | ....my_pas | sword.... |
		while (mem.RegionSize > memory_region_offset)
		{
			const size_t leftover_bytes = mem.RegionSize - memory_region_offset;
			const size_t bytes_to_read = min(leftover_bytes, MEMORY_BUFFER_SIZE * sizeof(unsigned char));
			dprintf("[MEM SEARCH] Leftover Bytes count: %llu", leftover_bytes);
			dprintf("[MEM SEARCH] Bytes to read: %llu", bytes_to_read);
			size_t bytes_read = 0;

			const size_t read_address = (size_t)mem.BaseAddress + memory_region_offset;
			// Note: This will read up to a maximum of bytes_to_read OR to the end of the memory region if the end of it has been reached.
			if (fNtReadVirtualMemory(process_handle, (LPCVOID)read_address, memory_buffer, bytes_to_read, &bytes_read) != ERROR_SUCCESS)
			{
				dprintf("[MEM SEARCH] Failed to read some virtual memory for process, skipping %u bytes", bytes_to_read);
				memory_region_offset += bytes_to_read;
				continue;
			}

			dprintf("[MEM SEARCH] Read %llu bytes", bytes_read);
			// Note: Increment the offset so that we aren't stuck in an infinite loop, trying to read zero bytes from the same pointer.
			if (bytes_read == 0) { dprintf("[MEM SEARCH] Read zero bytes from a readable memory region"); memory_region_offset += bytes_to_read; continue; }

			for (size_t current_needle_index = 0; current_needle_index < needle_enum_index; current_needle_index++)
			{
				size_t current_buffer_offset = 0;
				size_t match_length = 0;
				int match_result = -1;

				do
				{
					const unsigned char* current_buffer_ptr = memory_buffer + current_buffer_offset;
					const size_t bytes_to_regex = bytes_read - current_buffer_offset;
					
					match_result = re_matchp((re_t)&regex_needles[current_needle_index].compiled_regex, current_buffer_ptr, bytes_to_regex, current_max_match_length, &match_length);

					if (match_result != -1)
					{
						const size_t match_address = read_address + current_buffer_offset + match_result;
						dprintf("[MEM SEARCH] -- ! FOUND A REGEX MATCH ! --");
						dprintf("[MEM SEARCH] Address: %p", match_address);

						if (match_length < min_match_length)
						{
							dprintf("[MEM SEARCH] Match length was too short, skipping.");
							current_buffer_offset += (match_result + match_length);
							continue;
						}

						const unsigned char* memory_buffer_ptr = memory_buffer + current_buffer_offset + match_result;
						if (add_needle_results_to_packet(response, memory_buffer_ptr, match_length, match_address, (size_t)mem.BaseAddress, mem.RegionSize) != ERROR_SUCCESS)
						{
							dprintf("[MEM SEARCH] Adding search results to packet was not successful");
						}

						current_buffer_offset += (match_result + match_length);
					}
				} while (match_result != -1);
			}

			memory_region_offset += bytes_to_read;
		}
	}

	result = ERROR_SUCCESS;

done:
	dprintf("[MEM SEARCH] Memory Search complete.");
	if (memory_buffer != NULL) { dprintf("[MEM SEARCH] Freeing process memory buffer."); free(memory_buffer); }
	if (process_handle != NULL) { dprintf("[MEM SEARCH] Closing process handle."); fCloseHandle(process_handle); }

	dprintf("[MEM SEARCH] Transmitting response");
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}
