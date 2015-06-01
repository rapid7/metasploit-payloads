/*!
 * @file clipboard_image.h
 * @brief Declarations for clipboard image handling functionality
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_IMAGE_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_CLIPBOARD_IMAGE_H

typedef struct _ConvertedImage
{
	/*!
	 * @brief Pointer to a pointer which will receive the JPEG image data buffer.
	 *        This value is allocated using \c malloc prior to returning. If after
	 *        calling this function the value is non-NULL the caller must call
	 *        \c free to release this memory.
	 */
	PBYTE              pImageBuffer;
	/*!
	 * @brief The size of the \c pImageBuffer buffer.
	 */
	DWORD              dwImageBufferSize;
} ConvertedImage;

DWORD get_bitmapinfo_size(const LPBITMAPINFO lpBI, BOOL bRGB);
DWORD convert_to_jpg(const LPBITMAPINFO lpBI, const LPVOID lpDIB, ULONG ulQuality, ConvertedImage* pImage);

#endif
