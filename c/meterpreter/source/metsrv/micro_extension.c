#include "micro_extension.h"

typedef enum _MicroExtensionStatus
{
	MicroExtensionActive,
	MicroExtensionUnloading
} MicroExtensionStatus;

typedef struct _MicroExtensionEntry
{
	QWORD handle;
	MicroCoffImage* image;
	const MicroExtension* descriptor;
	MicroDeinit deinit;
	volatile LONG status;
	volatile LONG active_calls;
	struct _MicroExtensionEntry* next;
} MicroExtensionEntry;

typedef struct _MicroChannelBinding
{
	DWORD channel_id;
	Channel* channel;
	MicroExtensionEntry* owner;
	struct _MicroChannelBinding* next;
} MicroChannelBinding;

static LOCK* micro_lock = NULL;
static MicroExtensionEntry* micro_extensions = NULL;
static MicroChannelBinding* micro_channels = NULL;
static QWORD micro_next_handle = 1;

static MicroExtensionEntry* micro_find_name(LPCSTR name)
{
	MicroExtensionEntry* entry;
	for (entry = micro_extensions; entry != NULL; entry = entry->next)
	{
		if (strcmp(entry->descriptor->name, name) == 0)
		{
			return entry;
		}
	}
	return NULL;
}

static MicroExtensionEntry* micro_find_handle(QWORD handle)
{
	MicroExtensionEntry* entry;
	for (entry = micro_extensions; entry != NULL; entry = entry->next)
	{
		if (entry->handle == handle)
		{
			return entry;
		}
	}
	return NULL;
}

static MicroExtensionEntry* micro_find_command(UINT command_id, DWORD* command_index)
{
	MicroExtensionEntry* entry;
	for (entry = micro_extensions; entry != NULL; entry = entry->next)
	{
		DWORD index;
		for (index = 0; index < entry->descriptor->command_count; index++)
		{
			if (entry->descriptor->commands[index].command_id == command_id)
			{
				if (command_index != NULL)
				{
					*command_index = index;
				}
				return entry;
			}
		}
	}
	return NULL;
}

static MicroExtensionEntry* micro_find_channel_provider(LPCSTR type, DWORD* provider_index)
{
	MicroExtensionEntry* entry;
	for (entry = micro_extensions; entry != NULL; entry = entry->next)
	{
		DWORD index;
		for (index = 0; index < entry->descriptor->channel_provider_count; index++)
		{
			if (strcmp(entry->descriptor->channel_providers[index].type, type) == 0)
			{
				if (provider_index != NULL)
				{
					*provider_index = index;
				}
				return entry;
			}
		}
	}
	return NULL;
}

static BOOL micro_entry_has_open_channels(MicroExtensionEntry* entry)
{
	BOOL open = FALSE;
	MicroChannelBinding* binding = micro_channels;
	MicroChannelBinding* previous = NULL;
	while (binding != NULL)
	{
		MicroChannelBinding* next = binding->next;
		if (binding->owner == entry)
		{
			if (channel_find_by_id(binding->channel_id) == binding->channel)
			{
				open = TRUE;
				previous = binding;
			}
			else
			{
				if (previous == NULL)
				{
					micro_channels = next;
				}
				else
				{
					previous->next = next;
				}
				free(binding);
			}
		}
		else
		{
			previous = binding;
		}
		binding = next;
	}
	return open;
}

static BOOL micro_unsupported(Remote* remote, Packet* packet, DWORD* result)
{
	Packet* response = packet_create_response(packet);
	*result = ERROR_NOT_SUPPORTED;
	if (response != NULL)
	{
		*result = packet_transmit_response(*result, remote, response);
	}
	return TRUE;
}

static BOOL micro_dispatch(Remote* remote, Packet* packet, DWORD* result)
{
	MicroExtensionEntry* entry;
	INLINE_DISPATCH_ROUTINE handler;
	DWORD command_index = 0;
	UINT command_id = packet_get_tlv_value_uint(packet, TLV_TYPE_COMMAND_ID);
	BOOL server_continue;

	lock_acquire(micro_lock);
	entry = micro_find_command(command_id, &command_index);
	if (entry == NULL || InterlockedCompareExchange(&entry->status, MicroExtensionActive, MicroExtensionActive) != MicroExtensionActive)
	{
		lock_release(micro_lock);
		return micro_unsupported(remote, packet, result);
	}
	InterlockedIncrement(&entry->active_calls);
	handler = entry->descriptor->commands[command_index].request.inline_handler;
	lock_release(micro_lock);

	server_continue = handler(remote, packet, result);
	InterlockedDecrement(&entry->active_calls);
	return server_continue;
}

static BOOL micro_descriptor_valid(MicroCoffImage* image, const MicroExtension* descriptor, LPCSTR requested_name)
{
	DWORD index;
	if (!micro_coff_contains(image, descriptor, sizeof(MicroExtension)) || descriptor->size != sizeof(MicroExtension) || descriptor->abi_version != MICRO_EXTENSION_ABI_VERSION || descriptor->flags != MICRO_EXTENSION_FLAG_INLINE_HANDLERS)
	{
		return FALSE;
	}
	if (!micro_coff_string(image, descriptor->name, 128) || strcmp(descriptor->name, requested_name) != 0 || descriptor->command_count > MICRO_EXTENSION_MAX_COMMANDS || descriptor->channel_provider_count > MICRO_EXTENSION_MAX_CHANNEL_PROVIDERS || (descriptor->command_count == 0 && descriptor->channel_provider_count == 0))
	{
		return FALSE;
	}
	if (descriptor->command_count > 0 && (descriptor->command_count > MAXDWORD / sizeof(Command) || !micro_coff_contains(image, descriptor->commands, descriptor->command_count * sizeof(Command))))
	{
		return FALSE;
	}
	for (index = 0; index < descriptor->command_count; index++)
	{
		const Command* command = &descriptor->commands[index];
		DWORD other_index;
		if (command->command_id < MICRO_COMMAND_ID_RANGE || command->request.handler != NULL || command->request.inline_handler == NULL || !micro_coff_contains(image, command->request.inline_handler, 1) || command->request.numArgumentTypes > MAX_CHECKED_ARGUMENTS || command->response.handler != NULL || command->response.inline_handler != NULL)
		{
			return FALSE;
		}
		for (other_index = index + 1; other_index < descriptor->command_count; other_index++)
		{
			if (command->command_id == descriptor->commands[other_index].command_id)
			{
				return FALSE;
			}
		}
	}
	if (descriptor->channel_provider_count > 0 && !micro_coff_contains(image, descriptor->channel_providers, descriptor->channel_provider_count * sizeof(MicroChannelProvider)))
	{
		return FALSE;
	}
	for (index = 0; index < descriptor->channel_provider_count; index++)
	{
		const MicroChannelProvider* provider = &descriptor->channel_providers[index];
		DWORD other_index;
		if (!micro_coff_string(image, provider->type, 128) || provider->type[0] == '\0' || provider->open == NULL || !micro_coff_contains(image, provider->open, 1))
		{
			return FALSE;
		}
		for (other_index = index + 1; other_index < descriptor->channel_provider_count; other_index++)
		{
			if (strcmp(provider->type, descriptor->channel_providers[other_index].type) == 0)
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}


static DWORD micro_register_commands(MicroExtensionEntry* entry)
{
	DWORD index;
	DWORD result = ERROR_SUCCESS;
	entry->next = micro_extensions;
	micro_extensions = entry;

	for (index = 0; index < entry->descriptor->command_count; index++)
	{
		Command command = entry->descriptor->commands[index];
		command.request.inline_handler = micro_dispatch;
		result = command_register(&command);
		if (result != ERROR_SUCCESS)
		{
			break;
		}
	}
	if (result != ERROR_SUCCESS)
	{
		while (index-- > 0)
		{
			command_deregister(&entry->descriptor->commands[index]);
		}
		micro_extensions = entry->next;
	}
	return result;
}

static DWORD micro_remove(Remote* remote, MicroExtensionEntry* entry)
{
	MicroExtensionEntry* current;
	MicroExtensionEntry* previous = NULL;
	DWORD index;
	DWORD result = ERROR_SUCCESS;
	DWORD start = GetTickCount();

	if (micro_entry_has_open_channels(entry))
	{
		return ERROR_BUSY;
	}
	if (InterlockedCompareExchange(&entry->status, MicroExtensionUnloading, MicroExtensionActive) == MicroExtensionActive)
	{
		for (index = 0; index < entry->descriptor->command_count; index++)
		{
			DWORD command_result = command_deregister(&entry->descriptor->commands[index]);
			if (command_result != ERROR_SUCCESS && result == ERROR_SUCCESS)
			{
				result = command_result;
			}
		}
	}
	lock_release(micro_lock);

	while (InterlockedCompareExchange(&entry->active_calls, 0, 0) != 0 && GetTickCount() - start < 30000)
	{
		Sleep(1);
	}
	lock_acquire(micro_lock);
	if (InterlockedCompareExchange(&entry->active_calls, 0, 0) != 0)
	{
		return ERROR_BUSY;
	}

	if (entry->deinit != NULL)
	{
		DWORD deinit_result = entry->deinit(remote);
		if (deinit_result != ERROR_SUCCESS && result == ERROR_SUCCESS)
		{
			result = deinit_result;
		}
	}
	for (current = micro_extensions; current != NULL; current = current->next)
	{
		if (current == entry)
		{
			if (previous == NULL)
			{
				micro_extensions = current->next;
			}
			else
			{
				previous->next = current->next;
			}
			break;
		}
		previous = current;
	}
	lock_release(micro_lock);
	micro_coff_unload(entry->image);
	free(entry);
	lock_acquire(micro_lock);
	return result;
}

VOID micro_extension_initialize(VOID)
{
	if (micro_lock == NULL)
	{
		micro_lock = lock_create();
	}
}

VOID micro_extension_destroy(Remote* remote)
{
	if (micro_lock == NULL)
	{
		return;
	}
	lock_acquire(micro_lock);
	while (micro_extensions != NULL)
	{
		if (micro_remove(remote, micro_extensions) == ERROR_BUSY)
		{
			break;
		}
	}
	lock_release(micro_lock);
	if (micro_extensions != NULL)
	{
		return;
	}
	lock_destroy(micro_lock);
	micro_lock = NULL;
}

BOOL micro_extension_owns_command(UINT commandId)
{
	BOOL present = FALSE;
	if (micro_lock != NULL)
	{
		MicroExtensionEntry* entry;
		lock_acquire(micro_lock);
		entry = micro_find_command(commandId, NULL);
		present = entry != NULL;
		lock_release(micro_lock);
	}
	return present;
}

static DWORD micro_request_channel_open(Remote* remote, Packet* packet)
{
	Packet* response = packet_create_response(packet);
	const char* requested_type = packet_get_tlv_value_string(packet, TLV_TYPE_CHANNEL_TYPE);
	MicroExtensionEntry* entry = NULL;
	MicroChannelOpen handler = NULL;
	MicroChannelBinding* binding = NULL;
	Channel* channel = NULL;
	DWORD provider_index = 0;
	DWORD result = ERROR_NOT_FOUND;
	BOOL accepted = FALSE;

	if (micro_lock != NULL && requested_type != NULL)
	{
		lock_acquire(micro_lock);
		entry = micro_find_channel_provider(requested_type, &provider_index);
		if (entry != NULL && InterlockedCompareExchange(&entry->status, MicroExtensionActive, MicroExtensionActive) == MicroExtensionActive)
		{
			InterlockedIncrement(&entry->active_calls);
			handler = entry->descriptor->channel_providers[provider_index].open;
		}
		lock_release(micro_lock);
	}
	if (handler != NULL && response != NULL)
	{
		__try
		{
			result = handler(remote, packet, &channel);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			result = ERROR_BAD_EXE_FORMAT;
		}
		if (result == ERROR_SUCCESS && (channel == NULL || !channel_exists(channel)))
		{
			result = ERROR_BAD_EXE_FORMAT;
		}
		if (result == ERROR_SUCCESS)
		{
			result = packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(channel));
		}
		if (result == ERROR_SUCCESS)
		{
			binding = (MicroChannelBinding*)calloc(1, sizeof(MicroChannelBinding));
			if (binding == NULL)
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		if (result == ERROR_SUCCESS)
		{
			channel_set_type(channel, (PCHAR)requested_type);
			lock_acquire(micro_lock);
			if (InterlockedCompareExchange(&entry->status, MicroExtensionActive, MicroExtensionActive) == MicroExtensionActive)
			{
				binding->channel_id = channel_get_id(channel);
				binding->channel = channel;
				binding->owner = entry;
				binding->next = micro_channels;
				micro_channels = binding;
				binding = NULL;
				accepted = TRUE;
			}
			else
			{
				result = ERROR_BUSY;
			}
			lock_release(micro_lock);
		}
	}
	if (!accepted && channel != NULL && channel_exists(channel))
	{
		channel_destroy(channel, packet);
	}
	free(binding);
	if (entry != NULL)
	{
		InterlockedDecrement(&entry->active_calls);
	}
	return response == NULL ? ERROR_NOT_ENOUGH_MEMORY : packet_transmit_response(result, remote, response);
}

static Command micro_channel_command = COMMAND_REQ(COMMAND_ID_CORE_CHANNEL_OPEN, micro_request_channel_open);

Command* micro_extension_channel_command(Packet* packet)
{
	const char* type = packet_get_tlv_value_string(packet, TLV_TYPE_CHANNEL_TYPE);
	Command* command = NULL;
	if (micro_lock != NULL && type != NULL)
	{
		lock_acquire(micro_lock);
		if (micro_find_channel_provider(type, NULL) != NULL)
		{
			command = &micro_channel_command;
		}
		lock_release(micro_lock);
	}
	return command;
}


BOOL micro_request_load(Remote* remote, Packet* packet, DWORD* result)
{
	Packet* response = packet_create_response(packet);
	const char* requested_name = packet_get_tlv_value_string(packet, TLV_TYPE_MICRO_NAME);
	DWORD object_size = 0;
	const BYTE* object = packet_get_tlv_value_raw(packet, TLV_TYPE_MICRO_IMAGE, &object_size);
	MicroCoffImage* image = NULL;
	MicroExtensionEntry* entry = NULL;
	MicroInit init;
	MicroDeinit deinit;
	const MicroExtension* descriptor = NULL;
	const char* failure_phase = "request validation";
	DWORD index;

	*result = ERROR_INVALID_PARAMETER;
	if (micro_lock == NULL)
	{
		*result = ERROR_INVALID_STATE;
		goto finish;
	}
	if (response == NULL || requested_name == NULL || requested_name[0] == '\0' || object == NULL || object_size == 0 || object_size > 16 * 1024 * 1024)
	{
		goto finish;
	}
#if defined(_WIN64)
	if (object_size < sizeof(WORD) || *(const WORD*)object != IMAGE_FILE_MACHINE_AMD64)
#else
	if (object_size < sizeof(WORD) || *(const WORD*)object != IMAGE_FILE_MACHINE_I386)
#endif
	{
		failure_phase = "COFF architecture";
		*result = ERROR_BAD_EXE_FORMAT;
		goto finish;
	}
	failure_phase = "COFF mapping";
	*result = micro_coff_load(object, object_size, &image);
	if (*result != ERROR_SUCCESS)
	{
		goto finish;
	}
	init = (MicroInit)micro_coff_symbol(image, object, object_size, "micro_init");
	deinit = (MicroDeinit)micro_coff_symbol(image, object, object_size, "micro_deinit");
	failure_phase = "entry-point lookup";
	if (init == NULL || deinit == NULL)
	{
		*result = ERROR_PROC_NOT_FOUND;
		goto finish;
	}

	__try
	{
		failure_phase = "micro_init";
		descriptor = init(met_api, remote);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		*result = ERROR_BAD_EXE_FORMAT;
	}
	failure_phase = "descriptor validation";
	if (!micro_descriptor_valid(image, descriptor, requested_name))
	{
		*result = ERROR_BAD_EXE_FORMAT;
		goto finish;
	}

	entry = (MicroExtensionEntry*)calloc(1, sizeof(MicroExtensionEntry));
	if (entry == NULL)
	{
		*result = ERROR_NOT_ENOUGH_MEMORY;
		goto finish;
	}
	entry->image = image;
	entry->descriptor = descriptor;
	entry->deinit = deinit;
	entry->status = MicroExtensionActive;

	lock_acquire(micro_lock);
	failure_phase = "command registration";
	entry->handle = micro_next_handle++;
	if (micro_find_name(requested_name) != NULL)
	{
		*result = ERROR_ALREADY_EXISTS;
	}
	else
	{
		for (index = 0; index < descriptor->command_count; index++)
		{
			if (command_locate_extension(descriptor->commands[index].command_id) != NULL)
			{
				*result = ERROR_ALREADY_EXISTS;
				break;
			}
		}
		if (index == descriptor->command_count)
		{
			failure_phase = "channel registration";
			for (index = 0; index < descriptor->channel_provider_count; index++)
			{
				if (micro_find_channel_provider(descriptor->channel_providers[index].type, NULL) != NULL)
				{
					*result = ERROR_ALREADY_EXISTS;
					break;
				}
			}
			if (index == descriptor->channel_provider_count)
			{
				failure_phase = "command registration";
				*result = micro_register_commands(entry);
			}
		}
	}
	lock_release(micro_lock);
	if (*result != ERROR_SUCCESS)
	{
		goto finish;
	}

	image = NULL;
	packet_add_tlv_qword(response, TLV_TYPE_MICRO_HANDLE, entry->handle);
	for (index = 0; index < descriptor->command_count; index++)
	{
		packet_add_tlv_uint(response, TLV_TYPE_UINT, descriptor->commands[index].command_id);
	}
	for (index = 0; index < descriptor->channel_provider_count; index++)
	{
		packet_add_tlv_string(response, TLV_TYPE_CHANNEL_TYPE, descriptor->channel_providers[index].type);
	}

finish:
	if (image != NULL)
	{
		if (deinit != NULL && descriptor != NULL)
		{
			deinit(remote);
		}
		micro_coff_unload(image);
	}
	if (*result != ERROR_SUCCESS)
	{
		free(entry);
	}
	if (response != NULL)
	{
		if (*result != ERROR_SUCCESS)
		{
			packet_add_tlv_string(response, TLV_TYPE_MICRO_DIAGNOSTIC, failure_phase);
		}
		*result = packet_transmit_response(*result, remote, response);
	}
	return TRUE;
}

BOOL micro_request_enum(Remote* remote, Packet* packet, DWORD* result)
{
	Packet* response = packet_create_response(packet);
	MicroExtensionEntry* entry;
	*result = micro_lock == NULL ? ERROR_INVALID_STATE : (response == NULL ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS);
	if (*result == ERROR_SUCCESS)
	{
		lock_acquire(micro_lock);
		for (entry = micro_extensions; entry != NULL; entry = entry->next)
		{
			Packet* group = packet_create_group();
			DWORD index;
			if (group == NULL)
			{
				*result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
			packet_add_tlv_string(group, TLV_TYPE_MICRO_NAME, entry->descriptor->name);
			packet_add_tlv_qword(group, TLV_TYPE_MICRO_HANDLE, entry->handle);
			packet_add_tlv_uint(group, TLV_TYPE_MICRO_ABI, entry->descriptor->abi_version);
			for (index = 0; index < entry->descriptor->command_count; index++)
			{
				packet_add_tlv_uint(group, TLV_TYPE_UINT, entry->descriptor->commands[index].command_id);
			}
			for (index = 0; index < entry->descriptor->channel_provider_count; index++)
			{
				packet_add_tlv_string(group, TLV_TYPE_CHANNEL_TYPE, entry->descriptor->channel_providers[index].type);
			}
			packet_add_group(response, TLV_TYPE_MICRO_ENTRY, group);
		}
		lock_release(micro_lock);
		*result = packet_transmit_response(*result, remote, response);
	}
	return TRUE;
}

BOOL micro_request_unload(Remote* remote, Packet* packet, DWORD* result)
{
	Packet* response = packet_create_response(packet);
	QWORD handle = packet_get_tlv_value_qword(packet, TLV_TYPE_MICRO_HANDLE);
	const char* name = packet_get_tlv_value_string(packet, TLV_TYPE_MICRO_NAME);
	MicroExtensionEntry* entry;
	DWORD index;

	*result = ERROR_NOT_FOUND;
	if (micro_lock == NULL)
	{
		*result = ERROR_INVALID_STATE;
		goto finish;
	}
	lock_acquire(micro_lock);
	entry = handle != 0 ? micro_find_handle(handle) : (name != NULL ? micro_find_name(name) : NULL);
	if (entry != NULL)
	{
		for (index = 0; response != NULL && index < entry->descriptor->command_count; index++)
		{
			packet_add_tlv_uint(response, TLV_TYPE_UINT, entry->descriptor->commands[index].command_id);
		}
		for (index = 0; response != NULL && index < entry->descriptor->channel_provider_count; index++)
		{
			packet_add_tlv_string(response, TLV_TYPE_CHANNEL_TYPE, entry->descriptor->channel_providers[index].type);
		}
		*result = micro_remove(remote, entry);
	}
	lock_release(micro_lock);
finish:
	if (response != NULL)
	{
		*result = packet_transmit_response(*result, remote, response);
	}
	return TRUE;
}

BOOL micro_request_has_command(Remote* remote, Packet* packet, DWORD* result)
{
	DWORD index = 0;
	Tlv command_id_tlv = { 0 };
	Packet* response = packet_create_response(packet);
	*result = micro_lock == NULL ? ERROR_INVALID_STATE : (response == NULL ? ERROR_NOT_ENOUGH_MEMORY : ERROR_SUCCESS);
	if (*result == ERROR_SUCCESS)
	{
		lock_acquire(micro_lock);
		while (packet_enum_tlv(packet, index++, TLV_TYPE_UINT, &command_id_tlv) == ERROR_SUCCESS)
		{
			if (command_id_tlv.header.length == sizeof(UINT))
			{
				UINT command_id = met_api->win_api.ws2_32.ntohl(*(PUINT)command_id_tlv.buffer);
				MicroExtensionEntry* entry = micro_find_command(command_id, NULL);
				if (entry != NULL && InterlockedCompareExchange(&entry->status, MicroExtensionActive, MicroExtensionActive) == MicroExtensionActive)
				{
					packet_add_tlv_uint(response, TLV_TYPE_UINT, command_id);
				}
			}
		}
		lock_release(micro_lock);
		*result = packet_transmit_response(*result, remote, response);
	}
	return TRUE;
}
