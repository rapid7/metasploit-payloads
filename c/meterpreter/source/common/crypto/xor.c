/*!
 * @file xor.c
 * @brief Definitions of functions that perform XOR encryption.
 */
#include "common.h"

#define TLV_TYPE_XOR_KEY       MAKE_CUSTOM_TLV(TLV_META_TYPE_UINT, 0, 1)

DWORD xor_crypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength);

/*!
 * @brief Populates the crypto context's handlers for XOR.
 * @param context Pointer to the crypto context to populate.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD xor_populate_handlers(CryptoContext *context)
{
	context->extension                          = NULL;
	context->handlers.process_negotiate_request = xor_process_negotiate_request;
	context->handlers.encrypt                   = xor_encrypt;
	context->handlers.decrypt                   = xor_decrypt;

	return ERROR_SUCCESS;
}

/*!
 * @brief Processes a negotiate request that has been sent from the remote endpoint.
 * @param context Pointer to the crypto context to use.
 * @param request Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed successfully.
 * @retval ERROR_INVALID_PARAMETER One of the expected TLV parameters was
 *         missing from the \c request.
 */
DWORD xor_process_negotiate_request(CryptoContext *context, 
		Packet *request)
{
	Tlv cipherParameters, xorKey;
	DWORD res = ERROR_INVALID_PARAMETER;

	memset(&xorKey, 0, sizeof(xorKey));

	// If valid parameters were supplied
	if ((packet_get_tlv(request, TLV_TYPE_CIPHER_PARAMETERS, 
			&cipherParameters) == ERROR_SUCCESS) &&
	    (packet_get_tlv_group_entry(request, &cipherParameters, 
			TLV_TYPE_XOR_KEY, &xorKey) == ERROR_SUCCESS) &&
	    (xorKey.header.length >= sizeof(DWORD)))
	{
		// Set the XOR key to what has been supplied to us
		context->extension = (LPVOID)ntohl(*(LPDWORD)xorKey.buffer);

		res = ERROR_SUCCESS;
	}

	return res;
}

/*!
 * @brief Encrypts the supplied buffer using the supplied crypto context.
 * @param context Pointer to the crypto context to use for encryption.
 * @param inBuffer Buffer to encrypt.
 * @param inBufferLength The number of bytes in \c inBuffer to encrypt.
 * @param outBuffer Pointer that will receive the output buffer.
 * @param outBufferLength Pointer that will receive the output buffer length.
 * @remark The memory referenced by \c outBuffer needs to be deallocated using \c free.
 * @sa xor_crypt
 * @sa xor_decrypt
 */
DWORD xor_encrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	return xor_crypt(context, inBuffer, inBufferLength, outBuffer,
			outBufferLength);
}

/*!
 * @brief Decrypts the supplied buffer using the supplied crypto context.
 * @param context Pointer to the crypto context to use for decryption.
 * @param inBuffer Buffer to decrypt.
 * @param inBufferLength The number of bytes in \c inBuffer to encrypt.
 * @param outBuffer Pointer that will receive the output buffer.
 * @param outBufferLength Pointer that will receive the output buffer length.
 * @returns Indication of success or failure.
 * @remark The memory referenced by \c outBuffer needs to be deallocated using \c free.
 * @sa xor_crypt
 * @sa xor_encrypt
 */
DWORD xor_decrypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	return xor_crypt(context, inBuffer, inBufferLength, outBuffer,
			outBufferLength);
}

/*!
 * @brief Performs an XOR operation on every 4 byte block of the supplied buffer.
 * @param context Pointer to the crypto context to use for decryption.
 * @param inBuffer Buffer to decrypt.
 * @param inBufferLength The number of bytes in \c inBuffer to encrypt.
 * @param outBuffer Pointer that will receive the output buffer.
 * @param outBufferLength Pointer that will receive the output buffer length.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed successfully.
 * @retval ERROR_NOT_ENOUGH_MEMORY Memory allocation failed.
 * @remark The memory referenced by \c outBuffer needs to be deallocated using \c free.
 * @sa xor_decrypt
 * @sa xor_encrypt
 */
DWORD xor_crypt(CryptoContext *context, PUCHAR inBuffer, ULONG inBufferLength,
		PUCHAR *outBuffer, PULONG outBufferLength)
{
	DWORD newLength = inBufferLength, remainder = inBufferLength % 4, offset = 0;
	PUCHAR newBuffer = NULL;
	LPDWORD currentIn, currentOut;
	DWORD res = ERROR_SUCCESS;
	DWORD key = (DWORD)context->extension;

	if (remainder)
		newLength += 4 - remainder;

	do
	{
		// No memory?
		if (!(newBuffer = (PUCHAR)malloc(newLength)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// We assume that though the input buffer may not align on a 4 byte
		// boundary, its allocated unit should.  Given that, we don't care what
		// the overflow bytes are.  Anyone see anything wrong w/ this?
		for (currentIn = (LPDWORD)inBuffer, currentOut = (LPDWORD)newBuffer, offset = 0;
		     offset < newLength;
		     currentIn++, currentOut++, offset += 4)
			*currentOut = *currentIn ^ key;

	} while (0);

	// Did we fail or what?
	if (res != ERROR_SUCCESS)
	{
		if (newBuffer)
			free(newBuffer);

		newBuffer = NULL;
	}

	// Populate our out pointers
	if (outBuffer)
		*outBuffer = newBuffer;
	if (outBufferLength)
		*outBufferLength = newLength;

	return res;
}
