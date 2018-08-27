#include "precomp.h"

#include <sys/stat.h>

/***************************
 * Audio Channel Operations *
 ***************************/

typedef struct
{
	size_t offset;
	void* buffer;
} AudioContext;

/*
 * Writes the supplied data to the audio buffer
 */
static DWORD audio_channel_write(Channel *channel, Packet *request,
		LPVOID context, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesWritten)
{
	AudioContext *ctx = (AudioContext *)context;
	DWORD result = ERROR_SUCCESS;
	size_t written = 0;

	// Write to the buffer
	if (bufferSize) {
		char* newbuffer = 0;
		if (ctx->buffer) {
			newbuffer = realloc(ctx->buffer, ctx->offset + bufferSize);
		} else {
			newbuffer = malloc(bufferSize);
		}

		if (newbuffer) {
			memcpy(newbuffer + ctx->offset, buffer, bufferSize);
			ctx->buffer = newbuffer;
			ctx->offset += bufferSize;
			written = bufferSize;
		} else {
			result = ERROR_NOT_ENOUGH_MEMORY;
		}
	}

	if (bytesWritten) {
		*bytesWritten = (DWORD)written;
	}

	return result;
}

/*
 * Play the audio on channel close
 */
static DWORD audio_channel_close(Channel *channel, Packet *request,
		LPVOID context)
{
	AudioContext *ctx = (AudioContext *)context;

	// Play the audio buffer
	sndPlaySound(ctx->buffer, SND_MEMORY);

	if (ctx->buffer) {
		free(ctx->buffer);
		ctx->buffer = 0;
	}
	free(ctx);

	return ERROR_SUCCESS;
}


/*
 * Handles the open request for a audio channel and returns a valid channel
 */
DWORD request_audio_output_channel_open(Remote *remote, Packet *packet)
{
	Packet *response = NULL;
	DWORD res = ERROR_SUCCESS;
	DWORD flags = 0;
	PoolChannelOps chops = { 0 };
	AudioContext *ctx;
	Channel *newChannel = NULL;

	// Allocate a response
	response = packet_create_response(packet);

	// Allocate storage for the audio buffer context
	if (!(ctx = calloc(1, sizeof(AudioContext)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Get the channel flags
	flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

	memset(&chops, 0, sizeof(chops));

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.write   = audio_channel_write;
	chops.native.close   = audio_channel_close;

	// Check the response allocation & allocate a un-connected
	// channel
	if ((!response) || (!(newChannel = channel_create_pool(0, flags, &chops)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	// Add the channel identifier to the response
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));

out:
	// Transmit the packet if it's valid
	packet_transmit_response(res, remote, response);

	// Clean up on failure
	if (res != ERROR_SUCCESS) {
		if (newChannel) {
			channel_destroy(newChannel, NULL);
		}
	}

	return res;
}

