#include "metapi.h"

#include "base_inject.h"
#include "remote_thread.h"
#include "unicode.h"
#include "winapi.h"

MetApi api_instance = {
    // PacketApi
    {
        packet_get_tlv_value_bool,
        packet_get_tlv_value_raw,
        packet_add_completion_handler,
        packet_add_exception,
        packet_add_group,
        packet_add_request_id,
        packet_add_tlv_bool,
        packet_add_tlv_group,
        packet_add_tlv_qword,
        packet_add_tlv_raw,
        packet_add_tlv_string,
        packet_add_tlv_uint,
        packet_add_tlv_wstring,
        packet_add_tlv_wstring_len,
        packet_add_tlvs,
        packet_call_completion_handlers,
        packet_enum_tlv,
        packet_get_tlv,
        packet_get_tlv_group_entry,
        packet_get_tlv_string,
        packet_is_tlv_null_terminated,
        packet_remove_completion_handler,
        packet_transmit,
        packet_transmit_empty_response,
        packet_transmit_response,
        packet_get_tlv_value_string,
        packet_create,
        packet_create_group,
        packet_create_response,
        packet_get_type,
        packet_get_tlv_value_qword,
        packet_get_tlv_meta,
        packet_get_tlv_value_uint,
        packet_get_tlv_uint,
        packet_destroy,
        packet_get_tlv_value_wstring,
        packet_get_tlv_value_reflective_loader,
    },
    // CommandApi
    {
        command_deregister_all,
        command_register_all,
        command_handle,
    },
    // ThreadApi
    {
        thread_destroy,
        thread_join,
        thread_kill,
        thread_run,
        thread_sigterm,
        thread_create,
        thread_open,
        create_remote_thread,
        core_update_thread_token,
    },
    // LockApi
    {
        lock_create,
        lock_acquire,
        lock_destroy,
        lock_release,
    },
    // EventApi
    {
        event_destroy,
        event_poll,
        event_signal,
        event_create,
    },
    // ChannelApi
    {
        channel_exists,
        channel_is_interactive,
        channel_is_flag,
        channel_create,
        channel_create_datagram,
        channel_create_pool,
        channel_create_stream,
        channel_find_by_id,
        channel_close,
        channel_default_io_handler,
        channel_get_class,
        channel_get_id,
        channel_interact,
        channel_open,
        channel_read,
        channel_read_from_buffered,
        channel_write,
        channel_write_to_buffered,
        channel_write_to_remote,
        channel_get_native_io_context,
        channel_get_type,
        channel_get_buffered_io_context,
        channel_get_flags,
        channel_destroy,
        channel_set_buffered_io_handler,
        channel_set_flags,
        channel_set_interactive,
        channel_set_native_io_context,
        channel_set_type,
    },
    // SchedulerApi
    {
        scheduler_initialize,
        scheduler_destroy,
        scheduler_insert_waitable,
        scheduler_signal_waitable,
        scheduler_waitable_thread,
    },
    // StringApi
    {
        utf8_to_wchar,
        wchar_to_utf8,
    },
    // InjectApi
    {
        inject_dll,
        inject_via_apcthread,
        inject_via_remotethread,
        inject_via_remotethread_wow64,
    },
    // DesktopApi
    {
        core_update_desktop,
    },
    // ListApi
    {
        list_add,
        list_clear,
        list_enumerate,
        list_push,
        list_remove,
        list_remove_at,
        list_count,
        list_create,
        list_get,
        list_pop,
        list_shift,
        list_destroy,
    },
    // WinApi
    {
            // ntdll
        {
            winapi_ntdll_ZwAllocateVirtualMemory,
            winapi_ntdll_ZwOpenProcess,
            winapi_ntdll_ZwWriteVirtualMemory,
            winapi_ntdll_ZwReadVirtualMemory,
            winapi_ntdll_ZwProtectVirtualMemory,
            winapi_ntdll_ZwQueryVirtualMemory,
            winapi_ntdll_ZwFreeVirtualMemory,
            winapi_ntdll_NtQueueApcThread,
            winapi_ntdll_NtOpenThread
        },
        // kernel32
        {
            winapi_kernel32_WriteProcessMemory,
            winapi_kernel32_ReadProcessMemory,
            winapi_kernel32_OpenProcess,
            winapi_kernel32_VirtualAlloc,
            winapi_kernel32_VirtualAllocEx,
            winapi_kernel32_VirtualProtect,
            winapi_kernel32_VirtualProtectEx,
            winapi_kernel32_VirtualQuery,
            winapi_kernel32_VirtualQueryEx,
            winapi_kernel32_VirtualFree,
            winapi_kernel32_CreateRemoteThread,
            winapi_kernel32_CloseHandle,
            winapi_kernel32_DuplicateHandle,
            winapi_kernel32_CreateToolhelp32Snapshot,
            winapi_kernel32_Thread32First,
            winapi_kernel32_OpenThread,
            winapi_kernel32_SuspendThread,
            winapi_kernel32_Thread32Next,
            winapi_kernel32_ResumeThread,
            winapi_kernel32_FreeLibrary,
            winapi_kernel32_FlushInstructionCache,
            winapi_kernel32_LocalFree,
            winapi_kernel32_CreateFileA,
            winapi_kernel32_WriteFile,
            winapi_kernel32_LoadLibraryA,
            winapi_kernel32_WaitForMultipleObjects,
            winapi_kernel32_SetHandleInformation,
            winapi_kernel32_GlobalFree,
            winapi_kernel32_CreateNamedPipeA,
            winapi_kernel32_ConnectNamedPipe,
            winapi_kernel32_GetOverlappedResult,
            winapi_kernel32_ReadFile,
            winapi_kernel32_CreateThread,
            winapi_kernel32_ResetEvent,
            winapi_kernel32_SetThreadErrorMode
        },
        // advapi32
        {
            winapi_advapi32_OpenProcessToken,
            winapi_advapi32_AdjustTokenPrivileges,
            winapi_advapi32_ImpersonateLoggedOnUser,
            winapi_advapi32_CryptDuplicateKey,
            winapi_advapi32_CryptSetKeyParam,
            winapi_advapi32_CryptDecrypt,
            winapi_advapi32_CryptGenRandom,
            winapi_advapi32_CryptEncrypt,
            winapi_advapi32_CryptDestroyKey,
            winapi_advapi32_CryptReleaseContext,
            winapi_advapi32_CryptImportKey,
            winapi_advapi32_OpenThreadToken,
            winapi_advapi32_AllocateAndInitializeSid,
            winapi_advapi32_SetEntriesInAclW,
            winapi_advapi32_InitializeAcl,
            winapi_advapi32_InitializeSecurityDescriptor,
            winapi_advapi32_SetSecurityDescriptorDacl,
            winapi_advapi32_SetSecurityDescriptorSacl,
            winapi_advapi32_LookupPrivilegeValueW
        },
        // crypt32
        {
            winapi_crypt32_CryptDecodeObjectEx,
            winapi_crypt32_CryptImportPublicKeyInfo,
            winapi_crypt32_CertGetCertificateContextProperty
        },
        // user32
        {
            winapi_user32_GetUserObjectInformationA,
            winapi_user32_GetThreadDesktop
        },
        // ws2_32
        {
            winapi_ws2_32_WSAStartup,
            winapi_ws2_32_socket,
            winapi_ws2_32_connect,
            winapi_ws2_32_accept,
            winapi_ws2_32_setsockopt,
            winapi_ws2_32_recv,
            winapi_ws2_32_WSADuplicateSocketA
        },
        // wininet
        {
            winapi_wininet_InternetOpenW,
            winapi_wininet_InternetConnectW,
            winapi_wininet_HttpOpenRequestW,
            winapi_wininet_InternetSetOptionW,
            winapi_wininet_HttpSendRequestW,
            winapi_wininet_HttpQueryInfoW,
            winapi_wininet_InternetReadFile,
            winapi_wininet_InternetCloseHandle,
            winapi_wininet_InternetCrackUrlW
        },
        // rpcrt4
        {
            winapi_rpcrt4_CoCreateGuid
        },
        // winhttp
        {
            winapi_winhttp_WinHttpOpen,
            winapi_winhttp_WinHttpConnect,
            winapi_winhttp_WinHttpOpenRequest,
            winapi_winhttp_WinHttpGetIEProxyConfigForCurrentUser,
            winapi_winhttp_WinHttpGetProxyForUrl,
            winapi_winhttp_WinHttpSetOption,
            winapi_winhttp_WinHttpSendRequest,
            winapi_winhttp_WinHttpReceiveResponse,
            winapi_winhttp_WinHttpQueryHeaders,
            winapi_winhttp_WinHttpReadData,
            winapi_winhttp_WinHttpQueryOption,
            winapi_winhttp_WinHttpCrackUrl
        }
    },
#ifdef DEBUGTRACE
    // LoggingApi
    {
        get_logging_context,
        get_lock,
    },
#endif
};

MetApi* met_api = &api_instance;
