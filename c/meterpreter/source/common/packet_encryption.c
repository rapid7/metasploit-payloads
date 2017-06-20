#include "common.h"
#include "remote.h"
#include "packet_encryption.h"

#define BLOCKSIZE 16

typedef struct _CryptProviderParams
{
	const TCHAR* provider;
	const DWORD type;
	const DWORD flags;
} CryptProviderParams;

const CryptProviderParams AesProviders[] =
{
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_NEWKEYSET}
};

DWORD encrypt_packet(Remote* remote, Packet* packet, LPBYTE* buffer, LPDWORD bufferSize)
{
	DWORD result = ERROR_SUCCESS;

	vdprintf("[ENC] Preparing for encryption ...");

	// create a new XOR key here, because the content will be copied into the final
	// payload as part of the prepration process
	rand_xor_key(packet->header.xor_key);

	// copy the session ID to the header as this will be used later to identify the packet's destination session
	//memcpy_s(packet->header.session_guid, sizeof(packet->header.session_guid), remote->orig_config->session.session_guid, sizeof(remote->orig_config->session.session_guid));

	// TODO: probably add the UUID here at some point as well.

	// Only encrypt if the context was set up correctly
	if (remote->enc_ctx != NULL && remote->enc_ctx->valid)
	{
		vdprintf("[ENC] Context is valid, moving on ... ");
		// only send the packet if encryption has been enabled
		if (remote->enc_ctx->enabled)
		{
			vdprintf("[ENC] Context is enabled, doing the AES encryption");
			BYTE iv[BLOCKSIZE];
			if (!CryptGenRandom(remote->enc_ctx->provider, sizeof(iv), iv))
			{
				result = GetLastError();
				vdprintf("[ENC] Failed to generate random IV: %d (%x)", result, result);
			}

			if (!CryptSetKeyParam(remote->enc_ctx->aes_key, KP_IV, iv, 0))
			{
				result = GetLastError();
				vdprintf("[ENC] Failed to generate random IV: %d (%x)", result, result);
			}

			// Round up
			DWORD maxEncryptSize = ((packet->payloadLength / BLOCKSIZE) + 1) * BLOCKSIZE;
			// Need to have space for the IV at the start, as well as the packet Header
			DWORD memSize = maxEncryptSize + sizeof(iv) + sizeof(packet->header);

			*buffer = (BYTE*)malloc(memSize);
			BYTE* headerPos = *buffer;
			BYTE* ivPos = headerPos + sizeof(packet->header);
			BYTE* payloadPos = ivPos + sizeof(iv);

			*bufferSize = packet->payloadLength;

			// prepare the payload
			memcpy_s(payloadPos, packet->payloadLength, packet->payload, packet->payloadLength);

			if (!CryptEncrypt(remote->enc_ctx->aes_key, 0, TRUE, 0, payloadPos, bufferSize, maxEncryptSize))
			{
				result = GetLastError();
				vdprintf("[ENC] Failed to encrypt: %d (%x)", result, result);
			}

			// update the length to match the size of the encrypted data with IV
			packet->header.length = *bufferSize + sizeof(iv);

			// update the returned total size to include both the IV and header size.
			*bufferSize += sizeof(iv) + sizeof(packet->header);

			// write the header and IV to the payload
			memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
			memcpy_s(ivPos, sizeof(iv), iv, sizeof(iv));
		}
		else
		{
			dprintf("[ENC] Enabling the context");
			// if the encryption is valid, then we set the enbaled flag here because
			// we know that the first packet going out is the response to the negotiation
			// and from here we want to make sure that the encryption function is on.
			remote->enc_ctx->enabled = TRUE;
		}
	}
	else
	{
		vdprintf("[ENC] No encryption context present");
	}

	// if we don't have a valid buffer at this point, we'll create one and add the packet as per normal
	if (*buffer == NULL)
	{
		*bufferSize = packet->payloadLength + sizeof(packet->header);
		*buffer = (BYTE*)malloc(*bufferSize);
		BYTE* headerPos = *buffer;
		BYTE* payloadPos = headerPos + sizeof(packet->header);
		memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
		memcpy_s(payloadPos, packet->payloadLength, packet->payload, packet->payloadLength);
	}

	// finally XOR obfuscate like we always did before, skippig the xor key itself.
	xor_bytes(packet->header.xor_key, *buffer + sizeof(packet->header.xor_key), *bufferSize - sizeof(packet->header.xor_key));

	return result;
}

DWORD free_encryption_context(Remote* remote)
{
	DWORD result = ERROR_SUCCESS;

	dprintf("[ENC] Freeing encryption context %p", remote->enc_ctx);
	if (remote->enc_ctx != NULL);
	{
		dprintf("[ENC] Encryption context not null, so ditching AES key");
		if (remote->enc_ctx->aes_key != 0)
		{
			CryptDestroyKey(remote->enc_ctx->aes_key);
		}

		dprintf("[ENC] Encryption context not null, so ditching provider");
		if (remote->enc_ctx->provider != 0)
		{
			CryptReleaseContext(remote->enc_ctx->provider, 0);
		}

		dprintf("[ENC] Encryption context not null, so freeing the context");
		free(remote->enc_ctx);
		remote->enc_ctx = NULL;
	}
	return result;
}

DWORD request_negotiate_aes_key(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response = packet_create_response(packet);

	do
	{
		if (remote->enc_ctx != NULL)
		{
			dprintf("[ENC] context already created.");
			// Done this before, so don't do it again.
			break;
		}

		remote->enc_ctx = (PacketEncryptionContext*)calloc(1, sizeof(PacketEncryptionContext));

		if (remote->enc_ctx == NULL)
		{
			dprintf("[ENC] failed to allocate the encryption context");
			result = ERROR_OUTOFMEMORY;
			break;
		}

		PacketEncryptionContext* ctx = remote->enc_ctx;

		for (int i = 0; i < _countof(AesProviders); ++i)
		{
			if (!CryptAcquireContext(&ctx->provider, NULL, AesProviders[i].provider, AesProviders[i].type, AesProviders[i].flags))
			{
				result = GetLastError();
				dprintf("[ENC] failed to acquire the crypt context %d: %d (%x)", i, result, result);
			}
			else
			{
				result = ERROR_SUCCESS;
				ctx->provider_idx = i;
				dprintf("[ENC] managed to acquire the crypt context %d!", i);
				break;
			}
		}

		if (result != ERROR_SUCCESS)
		{
			break;
		}

		ctx->key_data.header.bType = PLAINTEXTKEYBLOB;
		ctx->key_data.header.bVersion = CUR_BLOB_VERSION;
		ctx->key_data.header.aiKeyAlg = CALG_AES_256;
		ctx->key_data.length = sizeof(ctx->key_data.key);

		if (!CryptGenRandom(ctx->provider, ctx->key_data.length, ctx->key_data.key))
		{
			result = GetLastError();
			dprintf("[ENC] failed to generate random key: %d (%x)", result, result);
			break;
		}

		if (!CryptImportKey(ctx->provider, (const BYTE*)&ctx->key_data, sizeof(Aes256Key), 0, 0, &ctx->aes_key))
		{
			result = GetLastError();
			dprintf("[ENC] failed to import random key: %d (%x)", result, result);
			break;
		}

		DWORD mode = CRYPT_MODE_CBC;
		if (!CryptSetKeyParam(ctx->aes_key, KP_MODE, (const BYTE*)&mode, 0))
		{
			result = GetLastError();
			dprintf("[ENC] Failed to set mode to CBC: %d (%x)", result, result);
			break;
		}

		ctx->valid = TRUE;
		// TODO: add the random AES key to the packet

	} while (0);


	if (remote->enc_ctx->valid)
	{
		packet_add_tlv_raw(response, TLV_TYPE_AES_KEY, remote->enc_ctx->key_data.key, remote->enc_ctx->key_data.length);
	}

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}
