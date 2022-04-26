#include "metapi.h"
#include "unicode.h"
#include "remote_thread.h"
#include "base_inject.h"

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
#ifdef DEBUGTRACE
		// LoggingApi
	{
		get_logging_context,
		get_lock,
	},
#endif
};

MetApi* met_api = &api_instance;
