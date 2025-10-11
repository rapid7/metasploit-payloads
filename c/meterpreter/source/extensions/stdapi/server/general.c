#include "precomp.h"

#include "common_metapi.h"

#ifdef STDAPI_NAMESPACE_AUDIO
extern DWORD request_audio_output_channel_open(Remote *remote, Packet *packet);
#endif
#ifdef STDAPI_NAMESPACE_NET
extern DWORD request_net_tcp_client_channel_open(Remote *remote, Packet *packet);
extern DWORD request_net_tcp_server_channel_open(Remote *remote, Packet *packet);
extern DWORD request_net_udp_channel_open(Remote *remote, Packet *packet);
#endif

// Channel type dispatch table
struct
{
	LPCSTR type;
	DWORD  (*handler)(Remote *, Packet *);
} channel_open_handlers[] =
{
	#ifdef STDAPI_NAMESPACE_FS
	{ "stdapi_fs_file",        request_fs_file_channel_open        },
	#endif
	#ifdef STDAPI_NAMESPACE_AUDIO
	{ "audio_output",          request_audio_output_channel_open   },
	#endif
	#ifdef STDAPI_NAMESPACE_NET
	{ "stdapi_net_tcp_client", request_net_tcp_client_channel_open },
	{ "stdapi_net_tcp_server", request_net_tcp_server_channel_open },
	{ "stdapi_net_udp_client", request_net_udp_channel_open        },
	#endif
	{ NULL,                    NULL                                },
};

/*
 * Dispatches channel open requests to the appropriate handlers internally if
 * they are destined to a type that is managed by this extension.
 */
DWORD request_general_channel_open(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	LPCSTR channelType;
	DWORD result = ERROR_NOT_FOUND;
	DWORD index;

	do
	{
		// Get the requested channel type
		channelType = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_CHANNEL_TYPE);

		// No channel?  Lame.
		if (!channelType)
		{
			break;
		}

		// Enumerate the channel type dispatch table searching for a match
		for (index = 0; channel_open_handlers[index].type; index++)
		{
			if (!strcmp(channel_open_handlers[index].type, channelType))
			{
				result = channel_open_handlers[index].handler(remote, packet);
				break;
			}
		}

	} while (0);

	return result;
}