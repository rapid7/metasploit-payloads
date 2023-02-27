/*!
 * @file common_metapi.h
 * @brief Declarations for the Metepreter API to be used by extensions.
 */
#ifndef _METERPRETER_COMMON_METAPI_H
#define _METERPRETER_COMMON_METAPI_H

typedef struct _InjectApi
{
	DWORD(*dll)(DWORD dwPid, LPVOID lpDllBuffer, DWORD dwDllLength, LPCSTR reflectiveLoader, char* cpCommandLine);
	DWORD(*via_apcthread)(Remote* remote, Packet* response, HANDLE hProcess, DWORD dwProcessID, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter);
	DWORD(*via_remotethread)(Remote* remote, Packet* response, HANDLE hProcess, DWORD dwDestinationArch, LPVOID lpStartAddress, LPVOID lpParameter);
	DWORD(*via_remotethread_wow64)(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, HANDLE* pThread);
} InjectApi;

typedef struct _ChannelApi
{
	BOOL(*exists)(Channel* channel);
	BOOL(*is_interactive)(Channel* channel);
	BOOLEAN(*is_flag)(Channel* channel, ULONG flag);
	Channel*(*create)(DWORD identifier, DWORD flags);
	Channel*(*create_datagram)(DWORD identifier, DWORD flags, DatagramChannelOps* ops);
	Channel*(*create_pool)(DWORD identifier, DWORD flags, PoolChannelOps* ops);
	Channel*(*create_stream)(DWORD identifier, DWORD flags, StreamChannelOps* ops);
	Channel*(*find_by_id)(DWORD id);
	DWORD(*close)(Channel* channel, Remote* remote, Tlv* addend, DWORD addendLength, ChannelCompletionRoutine* completionRoutine);
	DWORD(*default_io_handler)(Channel* channel, ChannelBuffer* buffer, LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length, PULONG bytesXfered);
	DWORD(*get_class)(Channel* channel);
	DWORD(*get_id)(Channel* channel);
	DWORD(*interact)(Channel* channel, Remote* remote, Tlv* addend, DWORD addendLength, BOOL enable, ChannelCompletionRoutine* completionRoutine);
	DWORD(*open)(Remote* remote, Tlv* addend, DWORD addendLength, ChannelCompletionRoutine* completionRoutine);
	DWORD(*read)(Channel* channel, Remote* remote, Tlv* addend, DWORD addendLength, ULONG length, ChannelCompletionRoutine* completionRoutine);
	DWORD(*read_from_buffered)(Channel* channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesRead);
	DWORD(*write)(Channel* channel, Remote* remote, Tlv* addend, DWORD addendLength, PUCHAR buffer, ULONG length, ChannelCompletionRoutine* completionRoutine);
	DWORD(*write_to_buffered)(Channel* channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
	DWORD(*write_to_remote)(Remote* remote, Channel* channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
	LPVOID(*get_native_io_context)(Channel* channel);
	PCHAR(*get_type)(Channel* channel);
	PVOID(*get_buffered_io_context)(Channel* channel);
	ULONG(*get_flags)(Channel* channel);
	VOID(*destroy)(Channel* channel, Packet* request);
	VOID(*set_buffered_io_handler)(Channel* channel, LPVOID dioContext, DirectIoHandler dio);
	VOID(*set_flags)(Channel* channel, ULONG flags);
	VOID(*set_interactive)(Channel* channel, BOOL interactive);
	VOID(*set_native_io_context)(Channel* channel, LPVOID context);
	VOID(*set_type)(Channel* channel, PCHAR type);
} ChannelApi;

typedef struct _LockApi
{
	LOCK* (*create)();
	VOID(*acquire)(LOCK* lock);
	VOID(*destroy)(LOCK* lock);
	VOID(*release)(LOCK* lock);
} LockApi;

typedef struct _EventApi
{
	BOOL(*destroy)(EVENT* event);
	BOOL(*poll)(EVENT* event, DWORD timeout);
	BOOL(*signal)(EVENT* event);
	EVENT*(*create)();
} EventApi;

typedef struct _ThreadApi
{
	BOOL(*destroy)(THREAD* thread);
	BOOL(*join)(THREAD* thread);
	BOOL(*kill)(THREAD* thread);
	BOOL(*run)(THREAD* thread);
	BOOL(*sigterm)(THREAD* thread);
	THREAD*(*create)(THREADFUNK funk, LPVOID param1, LPVOID param2, LPVOID param3);
	THREAD*(*open)();
	HANDLE(*create_remote)(HANDLE hProcess, SIZE_T sStackSize, LPVOID pvStartAddress, LPVOID pvStartParam, DWORD dwCreateFlags, LPDWORD pdwThreadId);
	HANDLE(*update_token)( Remote *remote, HANDLE token );
} ThreadApi;

typedef struct _DesktopApi
{
	VOID(*update)( Remote * remote, DWORD dwSessionID, char * cpStationName, char * cpDesktopName );
} DesktopApi;

typedef struct _SchedulerApi
{
	DWORD(*initialize)(Remote* remote);
	DWORD(*destroy)();
	DWORD(*insert_waitable)(HANDLE waitable, LPVOID entryContext, LPVOID threadContext, WaitableNotifyRoutine routine, WaitableDestroyRoutine destroy);
	DWORD(*signal_waitable)(HANDLE waitable, SchedulerSignal signal);
	DWORD(THREADCALL*waitable_thread)(THREAD* thread);
} SchedulerApi;

typedef struct _PacketApi
{
	BOOL(*get_tlv_value_bool)(Packet* packet, TlvType type);
	BYTE*(*get_tlv_value_raw)(Packet* packet, TlvType type, DWORD* length);
	DWORD(*add_completion_handler)(LPCSTR requestId, PacketRequestCompletion* completion);
	DWORD(*add_exception)(Packet* packet, DWORD code, PCHAR fmt, ...);
	DWORD(*add_group)(Packet* packet, TlvType type, Packet* groupPacket);
	DWORD(*add_request_id)(Packet* packet);
	DWORD(*add_tlv_bool)(Packet* packet, TlvType type, BOOL val);
	DWORD(*add_tlv_group)(Packet* packet, TlvType type, Tlv* entries, DWORD numEntries);
	DWORD(*add_tlv_qword)(Packet* packet, TlvType type, QWORD val);
	DWORD(*add_tlv_raw)(Packet* packet, TlvType type, LPVOID buf, DWORD length);
	DWORD(*add_tlv_string)(Packet* packet, TlvType type, LPCSTR str);
	DWORD(*add_tlv_uint)(Packet* packet, TlvType type, UINT val);
	DWORD(*add_tlv_wstring)(Packet* packet, TlvType type, LPCWSTR str);
	DWORD(*add_tlv_wstring_len)(Packet* packet, TlvType type, LPCWSTR str, size_t strLength);
	DWORD(*add_tlvs)(Packet* packet, Tlv* entries, DWORD numEntries);
	DWORD(*call_completion_handlers)(Remote* remote, Packet* response, LPCSTR requestId);
	DWORD(*enum_tlv)(Packet* packet, DWORD index, TlvType type, Tlv* tlv);
	DWORD(*get_tlv)(Packet* packet, TlvType type, Tlv* tlv);
	DWORD(*get_tlv_group_entry)(Packet* packet, Tlv* group, TlvType type, Tlv* entry);
	DWORD(*get_tlv_string)(Packet* packet, TlvType type, Tlv* tlv);
	DWORD(*is_tlv_null_terminated)(Tlv* tlv);
	DWORD(*remove_completion_handler)(LPCSTR requestId);
	DWORD(*transmit)(Remote* remote, Packet* packet, PacketRequestCompletion* completion);
	DWORD(*transmit_empty_response)(Remote* remote, Packet* packet, DWORD res);
	DWORD(*transmit_response)(DWORD result, Remote* remote, Packet* response);
	PCHAR(*get_tlv_value_string)(Packet* packet, TlvType type);
	Packet*(*create)(PacketTlvType type, UINT commandId);
	Packet*(*create_group)();
	Packet*(*create_response)(Packet* request);
	PacketTlvType(*get_type)(Packet* packet);
	QWORD(*get_tlv_value_qword)(Packet* packet, TlvType type);
	TlvMetaType(*get_tlv_meta)(Packet* packet, Tlv* tlv);
	UINT(*get_tlv_value_uint)(Packet* packet, TlvType type);
	BOOL(*get_tlv_uint)(Packet* packet, TlvType type, UINT* output);
	VOID(*destroy)(Packet* packet);
	wchar_t*(*get_tlv_value_wstring)(Packet* packet, TlvType type);
	LPCSTR(*get_tlv_value_reflective_loader)(Packet* packet);
} PacketApi;;

typedef struct _CommandApi
{
	void(*deregister_all)(Command commands[]);
	void(*register_all)(Command commands[]);
	BOOL(*handle)(Remote* remote, Packet* packet);
} CommandApi;

typedef struct _StringApi
{
	wchar_t*(*utf8_to_wchar)(const char* in);
	char*(*wchar_to_utf8)(const wchar_t* in);
} StringApi;

typedef struct _ListApi
{
	BOOL(*add)(PLIST pList, LPVOID data);
	BOOL(*clear)(PLIST pList, PCLEARFUNC pFunc);
	BOOL(*enumerate)(PLIST pList, PLISTENUMCALLBACK pCallback, LPVOID pState);
	BOOL(*push)(PLIST pList, LPVOID data);
	BOOL(*remove)(PLIST pList, LPVOID data);
	BOOL(*remove_at)(PLIST pList, DWORD index);
	DWORD(*count)(PLIST pList);
	LIST*(*create)(VOID);
	LPVOID(*get)(PLIST pList, DWORD index);
	LPVOID(*pop)(PLIST pList);
	LPVOID(*shift)(PLIST pList);
	VOID(*destroy)(PLIST pList);
} ListApi;

#ifdef DEBUGTRACE
typedef struct _LoggingApi
{
	HANDLE(*get_logging_context)();
	HANDLE(*get_lock)();
} LoggingApi;
#endif
typedef struct _MetApi
{
    PacketApi packet;
    CommandApi command;
    ThreadApi thread;
    LockApi lock;
    EventApi event;
	ChannelApi channel;
    SchedulerApi scheduler;
	StringApi string;
	InjectApi inject;
	DesktopApi desktop;
	ListApi list;
#ifdef DEBUGTRACE
	LoggingApi logging;
#endif
} MetApi;

extern MetApi* met_api;

#endif