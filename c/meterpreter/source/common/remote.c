/*!
 * @file remote.c
 * @brief Definitions of functions and types that interact with a remote endpoint.
 */
#include "common.h"

/*!
 * @brief Instantiate a remote context from a file descriptor.
 * @details This function takes a file descriptor and wraps it in \c Remote
 *          context which makes it easier to interact with the endpoint.
 * @param fd File descriptor for the socket that needs to be wrapped.
 * @returns Pointer to the created \c Remote instance.
 * @retval NULL Indicates a memory allocation failure or a lock creation failure.
 * @retval Non-NULL Successful creation of the context.
 */
Remote *remote_allocate(SOCKET fd)
{
	Remote *remote = NULL;

	if ((remote = (Remote *)malloc(sizeof(Remote))))
	{
		memset(remote, 0, sizeof(Remote));

		remote->fd = fd;

		remote->lock = lock_create();


		// If we failed to create the lock we must fail to create the remote
		// as we wont be able to synchronize communication correctly.
		if( remote->lock == NULL )
		{
			remote_deallocate( remote );
			return NULL;
		}
	}

	return remote;
}

/*!
 * @brief Deallocate a remote context.
 * @param remote Pointer to the \c Remote instance to deallocate.
 */
VOID remote_deallocate(Remote * remote)
{
	if (remote->fd)
	{
		closesocket(remote->fd);
	}

	if (remote->lock)
	{
		lock_destroy(remote->lock);
	}

	if (remote->uri)
	{
		free(remote->uri);
	}

	// Wipe our structure from memory
	memset(remote, 0, sizeof(Remote));

	free(remote);
}

/*!
 * @brief Override a previously set file descriptor.
 * @param remote Pointer to the existing \c Remote instance.
 * @param fd The new file descriptor to use for the \c Remote instance.
 */
VOID remote_set_fd(Remote *remote, SOCKET fd)
{
	remote->fd = fd;
}

/*!
 * @brief Get the remote context's file descriptor.
 * @param remote Pointer to the \c Remote instance to get the file descriptor from.
 * @returns The associated file descriptor.
 */
SOCKET remote_get_fd(Remote *remote)
{
	return remote->fd;
}

/*!
 * @brief Initializes a given cipher as instructed by the remote endpoint.
 * @param remote Pointer to the \c Remote instance.
 * @param cipher Name of the cipher to use.
 * @param initializer Pointer to the received \c Packet instance.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS The cipher was set correctly.
 * @retval ERROR_NOT_ENOUGH_MEMORY Memory allocation failed.
 * @retval ERROR_NOT_FOUND An invalid value was specified for \c cipher.
 */
DWORD remote_set_cipher(Remote *remote, LPCSTR cipher, Packet *initializer)
{
	DWORD res = ERROR_SUCCESS;

	if (remote->crypto)
		free(remote->crypto);

	do
	{
		// Allocate storage for the crypto context
		if (!(remote->crypto = (CryptoContext *)malloc(sizeof(CryptoContext))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		memset(remote->crypto, 0, sizeof(CryptoContext));

		// Set the remote pointer on the crypto context
		remote->crypto->remote = remote;

		// Populate handlers according to what cipher was selected
		if (!strcmp(cipher, "xor"))
		{
			res = xor_populate_handlers(remote->crypto);
		}
		else
		{
			res = ERROR_NOT_FOUND;
		}

		// If we got a context and it wants to process the request, do it.
		if ((res == ERROR_SUCCESS) &&
			(remote->crypto->handlers.process_negotiate_request))
		{
			res = remote->crypto->handlers.process_negotiate_request(
				remote->crypto, initializer);
		}

	} while (0);

	// If we fail, destroy the crypto context should it have been allocated.
	if (res != ERROR_SUCCESS)
	{
		if (remote->crypto)
		{
			free(remote->crypto);
		}

		remote->crypto = NULL;
	}

	return res;
}

/*!
 * @brief Gets a pointer to the remote endpoint's crypto context.
 * @param remote The \c Remote instance to get the crypto context from.
 * @returns A pointer to the crypto context.
 */
CryptoContext *remote_get_cipher(Remote *remote)
{
	return remote->crypto;
}
