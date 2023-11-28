#include "precomp.h"
#include "common_metapi.h"
#include "../tiny-regex-c/re.h"

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

typedef NTSTATUS* PNTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#ifndef __kernel_entry
    #define __kernel_entry
#endif

typedef __kernel_entry NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS) (HANDLE ProcessHandle, DWORD ProcessInformationClass, LPVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef SIZE_T(WINAPI* VIRTUALQUERYEX) (HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);

typedef BOOL(WINAPI* READPROCESSMEMORY) (HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T mSize, SIZE_T* lpNumberOfBytesRead);

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

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtQueryVirtualMemory.html
typedef __kernel_entry NTSTATUS(NTAPI* NTQUERYVIRTUALMEMORY) (HANDLE ProcessHandle, LPCVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, LPVOID Buffer, SIZE_T Length, PSIZE_T ResultLength);

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

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtOpenProcess.html
// https://ntdoc.m417z.com/ntopenprocess
typedef NTSTATUS(NTAPI* NTOPENPROCESS) (PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

//typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
//{
//	DWORD dwLength;
//	DWORD dwInitialized;
//	LPVOID lpSsHandle;
//	LIST_ENTRY InLoadOrderModuleList;
//	LIST_ENTRY InMemoryOrderModuleList;
//	LIST_ENTRY InInitializationOrderModuleList;
//	LPVOID lpEntryInProgress;
//} PEB_LDR_DATA, * PPEB_LDR_DATA;

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

// In order to be able to regex null-butes, we need to store the length explicitly, so that null-bytes aren't being treated as the end of a string.
struct regex_needle
{
	char* raw_needle_buffer;
	size_t length;
	regex_t* compiled_needle;
};

#define NEEDLES_MAX (size_t)5

DWORD request_sys_process_memory_search(Remote* remote, Packet* packet)
{
	Packet* response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	char* buffer = NULL;
	size_t needle_enum_index = 0;
	HANDLE process_handle = NULL;
	
	dprintf("[MEM SEARCH] Getting PID...");
	const DWORD pid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PID);
	if (pid == 0) { result = ERROR_INVALID_PARAMETER; goto done; }
	dprintf("[MEM SEARCH] Searching PID: %lu", pid);

	// Iterate over all the needles in the packet.
	Tlv needle_buffer_tlv = { 0 };
	struct regex_needle* regex_needles[NEEDLES_MAX];
	while (needle_enum_index < (size_t)NEEDLES_MAX && met_api->packet.enum_tlv(packet, (DWORD)needle_enum_index, TLV_TYPE_MEMORY_SEARCH_NEEDLE, &needle_buffer_tlv) == ERROR_SUCCESS)
	{
		// The header contains a null-terminator which we do not need.
		const size_t needle_length = needle_buffer_tlv.header.length - 1;
		dprintf("[MEM SEARCH] Allocating %u bytes of memory for regex needle", sizeof(struct regex_needle));
		regex_needles[needle_enum_index] = (struct regex_needle*)malloc(sizeof(struct regex_needle));
		if (regex_needles[needle_enum_index] == NULL) { dprintf("[MEM SEARCH] Could not allocate memory for regex needle"); result = ERROR_OUTOFMEMORY; goto done; }

		regex_needles[needle_enum_index]->length = needle_length;
		regex_needles[needle_enum_index]->raw_needle_buffer = (char*)malloc(needle_length * sizeof(char));
		if (regex_needles[needle_enum_index]->raw_needle_buffer == NULL) { dprintf("[MEM SEARCH] Could not allocate memory for raw needle buffer"); result = ERROR_OUTOFMEMORY; goto done; }
		memcpy(regex_needles[needle_enum_index]->raw_needle_buffer, (char*)needle_buffer_tlv.buffer, needle_length);

		dprintf("[MEM SEARCH] Needle %u : %.*s with size (in bytes) %u", needle_enum_index, needle_length, regex_needles[needle_enum_index]->raw_needle_buffer, needle_length);

		dprintf("[MEM SEARCH] Compiling needle: %.*s", needle_length, (char*)needle_buffer_tlv.buffer);
		regex_needles[needle_enum_index]->compiled_needle = re_compile(regex_needles[needle_enum_index]->raw_needle_buffer, regex_needles[needle_enum_index]->length);
		if (regex_needles[needle_enum_index]->compiled_needle == NULL) { dprintf("[MEM SEARCH] Failed to compile needle"); result = ERROR_OUTOFMEMORY; goto done; }

		needle_enum_index++;
	}

	dprintf("[MEM SEARCH] Getting Match Lengths");
	const size_t min_match_length = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_UINT);
	const size_t max_match_length = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_MEMORY_SEARCH_MATCH_LEN);
	if (min_match_length > max_match_length || max_match_length == 0) { dprintf("[MEM SEARCH] Incorrect min or max match lengths"); result = ERROR_INVALID_PARAMETER; goto done; }
	const size_t current_max_match_length = max_match_length;

	dprintf("[MEM SEARCH] Getting handles & proc addresses");
	const HMODULE kernel32_dll = GetModuleHandleA("kernel32.dll");
	if (kernel32_dll == NULL) { dprintf("[MEM SEARCH] Could not get kernel32.dll handle"); result = ERROR_INVALID_HANDLE; goto done; }

	const HMODULE ntdll_dll = GetModuleHandleA("ntdll.dll");
	if (ntdll_dll == NULL) { dprintf("[MEM SEARCH] Could not get ntdll.dll handle"); result = ERROR_INVALID_HANDLE; goto done; }

	const HANDLE get_proc_address = GetProcAddress(kernel32_dll, "GetProcAddress");
	if (get_proc_address == NULL) { dprintf("[MEM SEARCH] Could not get GetProcAddress handle"); result = ERROR_INVALID_ADDRESS; goto done; }
	const GETPROCADDRESS GetProcAddress = (GETPROCADDRESS)get_proc_address;

	const HANDLE virtual_query_ex = GetProcAddress(kernel32_dll, "VirtualQueryEx");
	if (virtual_query_ex == NULL) { dprintf("[MEM SEARCH] Could not get VirtualQueryEx handle"); result = ERROR_INVALID_ADDRESS; goto done; }

	const HANDLE open_process = GetProcAddress(kernel32_dll, "OpenProcess");
	if (open_process == NULL) { dprintf("[MEM SEARCH] Could not get OpenProcess handle"); result = ERROR_INVALID_ADDRESS; goto done; }

	const HANDLE close_handle = GetProcAddress(kernel32_dll, "CloseHandle");
	if (close_handle == NULL) { dprintf("[MEM SEARCH] Could not get CloseHandle handle"); result = ERROR_INVALID_ADDRESS; goto done; }

	const HANDLE nt_read_virtual_memory = GetProcAddress(ntdll_dll, "NtReadVirtualMemory");
	if (nt_read_virtual_memory == NULL) { dprintf("[MEM SEARCH] Could not get NtReadVirtualMemory handle"); result = ERROR_INVALID_ADDRESS; goto done; }

	const OPENPROCESS OpenProcess = (OPENPROCESS)open_process;
	const CLOSEHANDLE CloseHandle = (CLOSEHANDLE)close_handle;
	const VIRTUALQUERYEX VirtualQueryEx = (VIRTUALQUERYEX)virtual_query_ex;
	const NTREADVIRTUALMEMORY NtReadVirtualMemory = (NTREADVIRTUALMEMORY)nt_read_virtual_memory;

	const DWORD process_vm_read = 0x0010;
	const DWORD process_query_information = 0x0400;
	const DWORD wanted_process_perms = process_vm_read | process_query_information;

	dprintf("[MEM SEARCH] Opening process");
	process_handle = OpenProcess(wanted_process_perms, FALSE, pid);
	if (process_handle == NULL) { dprintf("[MEM SEARCH] Could not get process handle"); result = ERROR_INVALID_HANDLE; goto done; }

	MEMORY_BASIC_INFORMATION mem = { 0 };
	const size_t megabytes_64 = 64 * 1024 * 1024;

	dprintf("[MEM SEARCH] Allocating buffer for storing process memory");
	buffer = (char*)malloc(megabytes_64);
	if (buffer == NULL) { dprintf("[MEM SEARCH] Could not allocate memory buffer"); result = ERROR_OUTOFMEMORY; goto done; }

	// The maximum length of data that we can read into a buffer at a time from a memory region.
	const size_t current_max_size = megabytes_64;

	for (size_t current_ptr = 0; VirtualQueryEx(process_handle, (LPCVOID)current_ptr, &mem, sizeof(mem)); current_ptr += mem.RegionSize)
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
			const size_t bytes_to_read = min(leftover_bytes, current_max_size);
			dprintf("[MEM SEARCH] Leftover Bytes count: %llu", leftover_bytes);
			dprintf("[MEM SEARCH] Bytes to read: %llu", bytes_to_read);
			size_t bytes_read = 0;

			const size_t read_address = (size_t)mem.BaseAddress + memory_region_offset;
			// Note: This will read up to a maximum of bytes_to_read OR to the end of the memory region if the end of it has been reached.
			const NTSTATUS read_virtual_memory_status = NtReadVirtualMemory(process_handle, (LPCVOID)read_address, buffer, bytes_to_read, &bytes_read);
			if (read_virtual_memory_status != ERROR_SUCCESS) { dprintf("[MEM SEARCH] Failed to read some virtual memory for process, skipping %u bytes", bytes_to_read); memory_region_offset += bytes_to_read; continue; }

			dprintf("[MEM SEARCH] Read %llu bytes", bytes_read);
			// Note: Increment the offset so that we aren't stuck in an infinite loop, trying to read zero bytes from the same pointer.
			if (bytes_read == 0) { dprintf("[MEM SEARCH] Read zero bytes from a readable memory region"); memory_region_offset += bytes_to_read; continue; }

			for (size_t current_needle_index = 0; current_needle_index < needle_enum_index; current_needle_index++)
			{
				// This is the buffer offset for this needle only.
				size_t current_buffer_offset = 0;
				size_t match_length = 0;
				int result = -1;

				do
				{
					const char* current_buffer_ptr = buffer + current_buffer_offset;
					const size_t bytes_to_regex = bytes_read - current_buffer_offset;

					result = re_matchp(regex_needles[current_needle_index]->compiled_needle, current_buffer_ptr, bytes_to_regex, &match_length);

					if (result != -1)
					{
						const size_t match_address = read_address + result;
						dprintf("[MEM SEARCH] -- ! FOUND A REGEX MATCH ! --");
						dprintf("[MEM SEARCH] Address: %p", match_address);

						dprintf("[MEM SEARCH] Creating results group");
						
						Packet* search_results = met_api->packet.create_group();
						if (search_results == NULL) { dprintf("[MEM SEARCH] Could not create search result group"); result = ERROR_OUTOFMEMORY; goto done; }

						dprintf("[MEM SEARCH] Adding results to packet group");

						dprintf("[MEM SEARCH] Adding Match bytes");
						// TODO: Add a workaround for match length to the regex itself, allowing the regex engine to stop matching once an upper limit has been reached.
						const size_t current_match_length = min(max_match_length, match_length);
					
						// Note: This raw data needs to be read from the buffer we copied. Trying to read it from mem.BaseAddress directly will make us crash.
						met_api->packet.add_tlv_raw(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_STR, buffer + current_buffer_offset + result, (DWORD)current_match_length);

						dprintf("[MEM SEARCH] Adding Match address");
						met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_ADDR, match_address);
						
						dprintf("[MEM SEARCH] Adding Region base address");
						met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_START_ADDR, (size_t)mem.BaseAddress);

						dprintf("[MEM SEARCH] Adding Region size");
						met_api->packet.add_tlv_qword(search_results, TLV_TYPE_MEMORY_SEARCH_SECT_LEN, mem.RegionSize);

						dprintf("[MEM SEARCH] Adding Match Length");
						met_api->packet.add_tlv_uint(search_results, TLV_TYPE_MEMORY_SEARCH_MATCH_LEN, (UINT)current_match_length);
						
						dprintf("[MEM SEARCH] Adding Group");
						met_api->packet.add_group(response, TLV_TYPE_MEMORY_SEARCH_RESULTS, search_results);

						current_buffer_offset += (result + current_match_length);
					}

				} while (result != -1);

			}

			memory_region_offset += bytes_to_read;
		}
	}

	result = ERROR_SUCCESS;

done:
	dprintf("[MEM SEARCH] Memory Search complete.");
	if (buffer != NULL) { dprintf("[MEM SEARCH] Freeing process memory buffer."); free(buffer); }
	if (process_handle != NULL) { dprintf("[MEM SEARCH] Closing process handle."); CloseHandle(process_handle); }

	dprintf("[MEM SEARCH] Cleaning up needles");
	for (size_t i = 0; i < needle_enum_index; i++)
	{
		if (regex_needles[i] != NULL)
		{
			if (regex_needles[i]->raw_needle_buffer != NULL)
			{
				dprintf("[MEM SEARCH] Freeing needle buffer");
				free(regex_needles[i]->raw_needle_buffer);
			}

			dprintf("[MEM SEARCH] Freeing regex needle.");
			free(regex_needles[i]);
		}
	}

	dprintf("[MEM SEARCH] Transmitting response");
	met_api->packet.transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}
