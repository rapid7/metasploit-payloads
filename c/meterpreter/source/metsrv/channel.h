#ifndef _METERPRETER_METSRV_CHANNEL_H
#define _METERPRETER_METSRV_CHANNEL_H

#include "common.h"

/*
 * Channel manipulation
 */
Channel *channel_create(DWORD identifier, DWORD flags);
Channel *channel_create_stream(DWORD identifier, DWORD flags, StreamChannelOps *ops);
Channel *channel_create_datagram(DWORD identifier, DWORD flags, DatagramChannelOps *ops);
Channel *channel_create_pool(DWORD identifier, DWORD flags, PoolChannelOps *ops);
VOID channel_destroy(Channel *channel, Packet *request);
DWORD channel_get_id(Channel *channel);
VOID channel_set_type(Channel *channel, PCHAR type);
PCHAR channel_get_type(Channel *channel);
DWORD channel_get_class(Channel *channel);
VOID channel_set_flags(Channel *channel, ULONG flags);
BOOLEAN channel_is_flag(Channel *channel, ULONG flag);
ULONG channel_get_flags(Channel *channel);
VOID channel_set_interactive(Channel *channel, BOOL interactive);
BOOL channel_is_interactive(Channel *channel);
DWORD channel_write_to_remote(Remote *remote, Channel *channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
DWORD channel_write_to_buffered(Channel *channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesWritten);
DWORD channel_read_from_buffered(Channel *channel, PUCHAR chunk, ULONG chunkLength, PULONG bytesRead);
VOID channel_set_buffered_io_handler(Channel *channel, LPVOID dioContext, DirectIoHandler dio);
PVOID channel_get_buffered_io_context(Channel *channel);
VOID channel_set_native_io_context(Channel *channel, LPVOID context);
LPVOID channel_get_native_io_context(Channel *channel);
DWORD channel_default_io_handler(Channel *channel, ChannelBuffer *buffer, LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length, PULONG bytesXfered);

/*
 * Remote channel API, used for communication with remotes
 *
 * Each of these routines accepts a completion routine that allows for custom
 * handling of the response.
 */
DWORD channel_open(Remote *remote, Tlv *addend, DWORD addendLength, ChannelCompletionRoutine *completionRoutine);
DWORD channel_read(Channel *channel, Remote *remote, Tlv *addend, DWORD addendLength, ULONG length, ChannelCompletionRoutine *completionRoutine);
DWORD channel_write(Channel *channel, Remote *remote, Tlv *addend, DWORD addendLength, PUCHAR buffer, ULONG length, ChannelCompletionRoutine *completionRoutine);
DWORD channel_close(Channel *channel, Remote *remote, Tlv *addend, DWORD addendLength, ChannelCompletionRoutine *completionRoutine);
DWORD channel_interact(Channel *channel, Remote *remote, Tlv *addend, DWORD addendLength, BOOL enable, ChannelCompletionRoutine *completionRoutine);

/*
 * Channel searching
 */
Channel *channel_find_by_id(DWORD id);
BOOL channel_exists(Channel *channel);

#endif
