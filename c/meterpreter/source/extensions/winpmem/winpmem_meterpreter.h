/*!
 * @file WINPMEM_MAIN.h
 * @brief Entry point and intialisation declrations for the WINPMEM extention.
 */
#include "winpmem.h"

#ifndef _METERPRETER_SOURCE_EXTENSION_WINPMEM_WINPMEM_H
#define _METERPRETER_SOURCE_EXTENSION_WINPMEM_WINPMEM_H

#define TLV_TYPE_EXTENSION_WINPMEM	0

// Custom TLVs go here
#define TLV_TYPE_WINPMEM_ERROR_CODE	\
		MAKE_CUSTOM_TLV(TLV_META_TYPE_UINT, TLV_TYPE_EXTENSION_WINPMEM, TLV_EXTENSIONS + 1)

// Custom TLVs go here
#define TLV_TYPE_WINPMEM_MEMORY_SIZE	\
		MAKE_CUSTOM_TLV(TLV_META_TYPE_QWORD, TLV_TYPE_EXTENSION_WINPMEM, TLV_EXTENSIONS + 2)

#define WINPMEM_ERROR_SUCCESS 0
#define WINPMEM_ERROR_FAILED_LOAD_DRIVER 1
#define WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY 2
#define WINPMEM_ERROR_FAILED_ALLOCATE_MEMORY 3
#define WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL 4
#define WINPMEM_ERROR_UNKNOWN 255

typedef struct
{
	class WinPmem_meterpreter *winpmem;
	__int64 index;
	__int64 offset;
	struct PmemMemoryInfo pmem_info;
} WinpmemContext;

class WinPmem_meterpreter : public WinPmem {
public:
	virtual int extract_file_(__int64 resource_id, TCHAR *filename);
	virtual HANDLE get_fd();
	virtual uint64_t get_max_physical_memory();
};

class WinPmem_meterpreter32 : public WinPmem_meterpreter {
	virtual int extract_driver();
};

class WinPmem_meterpreter64 : public WinPmem_meterpreter {
	virtual int extract_driver();
};

static DWORD winpmem_channel_read(Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead);

static DWORD winpmem_channel_close(Channel *channel, Packet *request, LPVOID context);

static DWORD winpmem_channel_eof(Channel *channel, Packet *request, LPVOID context, LPBOOL iseof);

#endif
