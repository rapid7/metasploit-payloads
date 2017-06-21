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

DWORD decrypt_packet(Remote* remote, Packet** packet, LPBYTE buffer, DWORD bufferSize)
{
	DWORD result = ERROR_SUCCESS;
	Packet* localPacket = NULL;
	HCRYPTKEY dupKey = 0;

#ifdef DEBUGTRACE
	PUCHAR h = buffer;
	vdprintf("[DEC] given header of: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28]);
#endif

	vdprintf("[DEC] Packet buffer size is: %u", bufferSize);

	do
	{
		PacketHeader* header = (PacketHeader*)buffer;

		// Start by decoding the entire packet
		xor_bytes(header->xor_key, buffer + sizeof(header->xor_key), bufferSize - sizeof(header->xor_key));

#ifdef DEBUGTRACE
		h = buffer;
		vdprintf("[DEC] Decoded header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28]);
#endif


		// Allocate a packet structure
		if (!(localPacket = (Packet *)calloc(1, sizeof(Packet))))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Only decrypt if the context was set up correctly
		if (remote->enc_ctx != NULL && remote->enc_ctx->valid && header->encrypted)
		{
			vdprintf("[DEC] Context is valid, moving on ... ");
			LPBYTE payload = buffer + sizeof(PacketHeader);

			// the first 16 bytes of the payload we're given is the IV
			LPBYTE iv = payload;

			vdprintf("[DEC] IV: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
				iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);

			// the rest of the payload bytes contains the actual encrypted data
			DWORD encryptedSize = ntohl(header->length) - sizeof(TlvHeader) - BLOCKSIZE;
			LPBYTE encryptedData = payload + BLOCKSIZE;

			vdprintf("[DEC] Encrypted Size: %u (%x)", encryptedSize, encryptedSize);
			vdprintf("[DEC] Encrypted Size mod BLOCKSIZE: %u", encryptedSize % BLOCKSIZE);

			if (!CryptDuplicateKey(remote->enc_ctx->aes_key, NULL, 0, &dupKey))
			{
				result = GetLastError();
				vdprintf("[DEC] Failed to duplicate key: %d (%x)", result, result);
				break;
			}

			DWORD mode = CRYPT_MODE_CBC;
			if (!CryptSetKeyParam(dupKey, KP_MODE, (const BYTE*)&mode, 0))
			{
				result = GetLastError();
				dprintf("[ENC] Failed to set mode to CBC: %d (%x)", result, result);
				break;
			}

			// decrypt!
			if (!CryptSetKeyParam(remote->enc_ctx->aes_key, KP_IV, iv, 0))
			{
				result = GetLastError();
				vdprintf("[DEC] Failed to set IV: %d (%x)", result, result);
				break;
			}

			if (!CryptDecrypt(remote->enc_ctx->aes_key, 0, TRUE, 0, encryptedData, &encryptedSize))
			{
				result = GetLastError();
				vdprintf("[DEC] Failed to decrypt: %d (%x)", result, result);
				break;
			}

			// shift the decrypted data back to the start of the packet buffer so that we
			// can pretend it's a normal packet
			memmove_s(iv, encryptedSize, encryptedData, encryptedSize);

			// adjust the header size
			header->length = htonl(encryptedSize + sizeof(TlvHeader));

			// done, the packet parsing can continue as normal now
		}

		localPacket->header.length = header->length;
		localPacket->header.type = header->type;
		localPacket->payloadLength = ntohl(localPacket->header.length) - sizeof(TlvHeader);

		vdprintf("[DEC] Actual payload Length: %d", localPacket->payloadLength);
		vdprintf("[DEC] Header Type: %d", ntohl(localPacket->header.type));

		localPacket->payload = malloc(localPacket->payloadLength);
		if (localPacket->payload == NULL)
		{
			vdprintf("[DEC] failed to allocate payload");
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		vdprintf("[DEC] Local packet payload successfully allocated, copying data");
		memcpy_s(localPacket->payload, localPacket->payloadLength, buffer + sizeof(PacketHeader), localPacket->payloadLength);

#ifdef DEBUGTRACE
		h = localPacket->payload;
		vdprintf("[DEC] TLV 1 length / type: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
		DWORD tl = ntohl(((TlvHeader*)h)->length);
		vdprintf("[DEC] Skipping %u bytes", tl);
		h += tl;
		vdprintf("[DEC] TLV 2 length / type: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
#endif

		vdprintf("[DEC] Writing localpacket %p to packet pointer %p", localPacket, packet);
		*packet = localPacket;
	} while (0);

	if (result != ERROR_SUCCESS)
	{
		if (localPacket != NULL)
		{
			packet_destroy(localPacket);
		}
	}

	return result;
}

DWORD encrypt_packet(Remote* remote, Packet* packet, LPBYTE* buffer, LPDWORD bufferSize)
{
	DWORD result = ERROR_SUCCESS;
	HCRYPTKEY dupKey = 0;

	vdprintf("[ENC] Preparing for encryption ...");

	// create a new XOR key here, because the content will be copied into the final
	// payload as part of the prepration process
	rand_xor_key(packet->header.xor_key);

	// copy the session ID to the header as this will be used later to identify the packet's destination session
	memcpy_s(packet->header.session_guid, sizeof(packet->header.session_guid), remote->orig_config->session.session_guid, sizeof(remote->orig_config->session.session_guid));

	// Only encrypt if the context was set up correctly
	if (remote->enc_ctx != NULL && remote->enc_ctx->valid)
	{
		vdprintf("[ENC] Context is valid, moving on ... ");
		// only encrypt the packet if encryption has been enabled
		if (remote->enc_ctx->enabled)
		{
			do
			{
				vdprintf("[ENC] Context is enabled, doing the AES encryption");

				if (!CryptDuplicateKey(remote->enc_ctx->aes_key, NULL, 0, &dupKey))
				{
					result = GetLastError();
					vdprintf("[ENC] Failed to duplicate AES key: %d (%x)", result, result);
					break;
				}

				DWORD mode = CRYPT_MODE_CBC;
				if (!CryptSetKeyParam(dupKey, KP_MODE, (const BYTE*)&mode, 0))
				{
					result = GetLastError();
					dprintf("[ENC] Failed to set mode to CBC: %d (%x)", result, result);
					break;
				}

				BYTE iv[BLOCKSIZE];
				if (!CryptGenRandom(remote->enc_ctx->provider, sizeof(iv), iv))
				{
					result = GetLastError();
					vdprintf("[ENC] Failed to generate random IV: %d (%x)", result, result);
				}

				vdprintf("[ENC] IV: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
					iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);


				if (!CryptSetKeyParam(dupKey, KP_IV, iv, 0))
				{
					result = GetLastError();
					vdprintf("[ENC] Failed to set IV: %d (%x)", result, result);
					break;
				}

				vdprintf("[ENC] IV Set successfully");
				// mark this packet as an encrypted packet
				packet->header.encrypted = 1;


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

				if (!CryptEncrypt(dupKey, 0, TRUE, 0, payloadPos, bufferSize, maxEncryptSize))
				{
					result = GetLastError();
					vdprintf("[ENC] Failed to encrypt: %d (%x)", result, result);
				}
				else
				{
					vdprintf("[ENC] Data encrypted successfully, size is %u", *bufferSize);
				}

				// update the length to match the size of the encrypted data with IV and the TlVHeader
				packet->header.length = ntohl(*bufferSize + sizeof(iv) + sizeof(TlvHeader));

				// update the returned total size to include both the IV and header size.
				*bufferSize += sizeof(iv) + sizeof(packet->header);

				// write the header and IV to the payload
				memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
				memcpy_s(ivPos, sizeof(iv), iv, sizeof(iv));
			} while (0);
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

		// mark this packet as a non-encrypted packet
		packet->header.encrypted = 0;

		memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
		memcpy_s(payloadPos, packet->payloadLength, packet->payload, packet->payloadLength);
	}
	vdprintf("[ENC] Packet buffer size is: %u", *bufferSize);

	// finally XOR obfuscate like we always did before, skippig the xor key itself.
	xor_bytes(packet->header.xor_key, *buffer + sizeof(packet->header.xor_key), *bufferSize - sizeof(packet->header.xor_key));

	vdprintf("[ENC] Packet encoded and ready for transmission");
#ifdef DEBUGTRACE
	LPBYTE h = *buffer;
	vdprintf("[ENC] Sending header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28]);
#endif

	if (dupKey != 0)
	{
		CryptDestroyKey(dupKey);
	}

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

		ctx->valid = TRUE;
	} while (0);


	if (remote->enc_ctx->valid)
	{
		packet_add_tlv_raw(response, TLV_TYPE_AES_KEY, remote->enc_ctx->key_data.key, remote->enc_ctx->key_data.length);
	}

	packet_transmit_response(result, remote, response);

	remote->enc_ctx->enabled = TRUE;

	//BYTE* buffer;
	//DWORD bufferSize;
	//Packet* p;
	//encrypt_packet(remote, response, &buffer, &bufferSize);
	//dprintf("[ENC] TEST BEGINS HERE ============================");
	//decrypt_packet(remote, &p, buffer, bufferSize);
	//dprintf("[ENC] TEST ENDS HERE ============================");
	//free(buffer);
	//packet_destroy(p);

	return ERROR_SUCCESS;
}
