#ifndef _METERPRETER_COMMON_CHANNEL_H
#define _METERPRETER_COMMON_CHANNEL_H

#include "common_remote.h"

struct _Channel;
struct _ChannelBuffer;

// Direct I/O operation modes (read/write/close)
typedef enum
{
	CHANNEL_DIO_MODE_OPEN     = 0,
	CHANNEL_DIO_MODE_READ     = 1,
	CHANNEL_DIO_MODE_WRITE    = 2,
	CHANNEL_DIO_MODE_CLOSE    = 3,
	CHANNEL_DIO_MODE_INTERACT = 3,
} ChannelDioMode;

// Direct I/O handler -- used in place of internal buffering for channels
// that can do event based forwarding of buffers.
typedef DWORD (*DirectIoHandler)(struct _Channel *channel, struct _ChannelBuffer *buffer, LPVOID context, ChannelDioMode mode, PUCHAR chunk, ULONG length, PULONG bytesXfered);

// Asynchronous completion routines -- used with channel_open, channel_read, 
// etc.
typedef DWORD (*ChannelOpenCompletionRoutine)(Remote *remote, struct _Channel *channel, LPVOID context, DWORD result);
typedef DWORD (*ChannelReadCompletionRoutine)(Remote *remote, struct _Channel *channel, LPVOID context, DWORD result, PUCHAR buffer, ULONG bytesRead);
typedef DWORD (*ChannelWriteCompletionRoutine)(Remote *remote, struct _Channel *channel, LPVOID context, DWORD result, ULONG bytesWritten);
typedef DWORD (*ChannelCloseCompletionRoutine)(Remote *remote, struct _Channel *channel, LPVOID context, DWORD result);
typedef DWORD (*ChannelInteractCompletionRoutine)(Remote *remote, struct _Channel *channel, LPVOID context, DWORD result);

// Completion routine wrapper context
typedef struct _ChannelCompletionRoutine
{
	LPVOID context;

	struct
	{
		ChannelOpenCompletionRoutine     open;
		ChannelReadCompletionRoutine     read;
		ChannelWriteCompletionRoutine    write;
		ChannelCloseCompletionRoutine    close;
		ChannelInteractCompletionRoutine interact;
	} routine;

} ChannelCompletionRoutine;

// Logical channel buffer used to queue or for event based updating
typedef struct _ChannelBuffer
{
	PUCHAR          buffer;
	ULONG           currentSize;
	ULONG           totalSize;

	// IO handler -- default is internal queuing
	DirectIoHandler dio;
	LPVOID          dioContext;
} ChannelBuffer;

// Channel operations that are used by any channel
typedef struct _NativeChannelOps
{
	LPVOID context;
	DWORD (*write)(struct _Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten);
	DWORD (*close)(struct _Channel *channel, Packet *request, LPVOID context);
	DWORD (*interact)(struct _Channel *channel, Packet *request, LPVOID context, BOOLEAN interact);
} NativeChannelOps;

// Channel operations for a stream-based channel
typedef struct _StreamChannelOps
{
	NativeChannelOps native;
} StreamChannelOps;

// Channel operations for a datagram-based channel
typedef struct _DatagramChannelOps
{
	NativeChannelOps native;
} DatagramChannelOps;

// Channel operations for a pool-based channel
typedef struct _PoolChannelOps
{
	NativeChannelOps native;
	DWORD (*read)(struct _Channel *channel, Packet *request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead);
	DWORD (*eof)(struct _Channel *channel, Packet *request, LPVOID context, LPBOOL isEof);
	DWORD (*seek)(struct _Channel *channel, Packet *request, LPVOID context, LONG offset, DWORD whence);
	DWORD (*tell)(struct _Channel *channel, Packet *request, LPVOID context, LPLONG offset);
} PoolChannelOps;

/*
 * Values for the 'cls' attribute
 */
#define CHANNEL_CLASS_BUFFERED 0
#define CHANNEL_CLASS_STREAM   1
#define CHANNEL_CLASS_DATAGRAM 2
#define CHANNEL_CLASS_POOL     3

typedef struct _Channel
{
	// The channel's identifier 
	DWORD                 identifier;
	// The channel's class
	DWORD                 cls;
	// The type of channel, NULL for default.
	PCHAR                 type;
	// Flag for whether or not the channel is currently interactive
	BOOL                  interactive;
	// Operational flags
	ULONG                 flags;
	// Lock for synchronizing communication to a channel
	LOCK *                lock;
	// The buffered output buffer (as in being outputted bufferedly)
	union
	{
		ChannelBuffer      buffered;
		StreamChannelOps   stream;
		DatagramChannelOps datagram;
		PoolChannelOps     pool;
	}                     ops;

	// Internal attributes for list
	struct _Channel       *prev;
	struct _Channel       *next;
} Channel;

#define CHANNEL_CHUNK_SIZE 4096

#endif
