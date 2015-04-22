#include "precomp.h"


typedef struct
{
	BOOL  eof;
} NTDSContext;


DWORD ntds_parse(Remote *remote, Packet *packet){
	Packet *response = NULL;
	DWORD res = ERROR_SUCCESS;
	jetState *ntdsState = malloc(sizeof(jetState));
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_NTDS_PATH);
	// Check if the File exists
	if (0xffffffff == GetFileAttributes(filePath)){
		res = 2;
		goto out;
	}
	strncpy(ntdsState->ntdsPath, filePath, 255);
	// Attempt to get the SysKey from the Registry
	unsigned char sysKey[17];
	if (!get_syskey(sysKey)){
		res = GetLastError();
		goto out;
	}

out:
	packet_transmit_response(res, remote, response);
	return res;
}

DWORD ntds_test_channel(Remote *remote, Packet *packet){
	PoolChannelOps chops;
	Channel *newChannel;
	NTDSContext *ctx;
	DWORD res = ERROR_SUCCESS;
	Packet *response = packet_create_response(packet);

	// Allocate storage for the NTDS context
	if (!(ctx = calloc(1, sizeof(NTDSContext)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	memset(&chops, 0, sizeof(chops));

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.write = ntds_channel_write;
	chops.native.close = ntds_channel_close;
	chops.read = ntds_channel_read;

	// Allocate the pool channel
	if (!(newChannel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS, &chops)))
	{
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	channel_set_type(newChannel, "ntds");
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));
	packet_transmit_response(res, remote, response);
out:
	return res;
}

static DWORD ntds_channel_write(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten){
	return ERROR_SUCCESS;
}

static DWORD ntds_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead){
	DWORD result = ERROR_SUCCESS;
	NTDSContext *ctx = (NTDSContext *)context;
	char testString[] = "This is a test of NTDS streaming";
	strncpy(buffer, testString, sizeof(testString));
	*bytesRead = sizeof(testString);
	return result;
}

static DWORD ntds_channel_close(Channel *channel, Packet *request,
	LPVOID context){
	return ERROR_SUCCESS;
}