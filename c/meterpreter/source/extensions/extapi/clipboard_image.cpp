/*!
 * @file clipboard_image.cpp
 * @brief Definitions for clipboard image handling functionality
 * @remark This is a C++ file because it uses GDI+ behind the scenes. This is because it's super
 *         easy to do image encoding and prevents us from having to include the massive JPG lib.
 *         It's not late-bound using LoadLibrary due to the fact that doing that with C++ stuff
 *         is nothing short of painful.
 */
extern "C" {
#include "extapi.h"
#include "clipboard_image.h"
}
#include <GdiPlus.h>

/*!
 * @brief Get the Class ID of an encoder which supports encoding to the specified MIME type.
 * @param mimeType The wide-string formatting MIME type identifier.
 * @param pClsId Pointer to the \c CLSID structure that will receive the Class ID.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS The Class ID was extracted successfully.
 * @retval Otherwise The relevant error code.
 */
DWORD get_encoder_clsid( WCHAR *mimeType, CLSID * pClsId )
{
	using namespace Gdiplus;

	DWORD dwResult = ERROR_SUCCESS;
	ImageCodecInfo* pImageCodecInfo = NULL;

	do
	{
		UINT numEncoders;
		UINT size;
		if( GetImageEncodersSize( &numEncoders, &size ) != Ok )
			BREAK_WITH_ERROR( "Unable to get encoders array size.", ERROR_FUNCTION_FAILED );

		if( size == 0 )
			BREAK_WITH_ERROR( "No encoders found.", ERROR_FUNCTION_FAILED );

		if( (pImageCodecInfo = (ImageCodecInfo*)malloc( size )) == NULL )
			BREAK_WITH_ERROR( "Couldn't allocate memory for ImageCodeInfo", ERROR_OUTOFMEMORY );

		if( GetImageEncoders( numEncoders, size, pImageCodecInfo ) != Ok )
			BREAK_WITH_ERROR( "Unable to get encoders.", ERROR_FUNCTION_FAILED );

		for( UINT i = 0; i < numEncoders; ++i ) {
			if( wcscmp( pImageCodecInfo[i].MimeType, mimeType ) == 0 ) {
				// Image encoder for the MIME type found, so copy the Class ID...
				memcpy_s( pClsId, sizeof( CLSID ), &pImageCodecInfo[i].Clsid, sizeof( CLSID ) );

				// .. and finish up.
				break;
			}
		}
	} while(0);

	if( pImageCodecInfo != NULL )
		free( pImageCodecInfo );

	return dwResult;
}

extern "C" {

/*!
 * @brief Convert the given bitmap data into a JPEG image of the specified quality.
 * @param lpBI Pointer to the \cBITMAPINFO structure that contains the detail of the bitmap.
 *             In the case of the clipboard, this is the CF_DIB data.
 * @param lpDIB Pointer to the DIB bytes that make up the image data.
 * @param ulQuality Quality of the resulting JPG image.
 * @param pImage Pointer to the image structure that will receive the image data
 * @retval ERROR_SUCCESS The Class ID was extracted successfully.
 * @retval Otherwise The relevant error code.
 */
DWORD convert_to_jpg( const LPBITMAPINFO lpBI, const LPVOID lpDIB, ULONG ulQuality, ConvertedImage* pImage )
{
	using namespace Gdiplus;

	HRESULT hRes = S_OK;
	DWORD dwResult = ERROR_SUCCESS;
	ULONG_PTR gdiPlusToken = 0;
	Bitmap* pBitmap = NULL;
	GdiplusStartupInput gdiStartupInput;
	IStream* pStream = NULL;

	// set this to NULL up front so that we can keep track of allocations;
	pImage->pImageBuffer = NULL;
	pImage->dwImageBufferSize = 0;

	do
	{
		if( GdiplusStartup( &gdiPlusToken, &gdiStartupInput, NULL ) != Ok )
			BREAK_WITH_ERROR( "Unable to initialize GdiPlus", ERROR_FUNCTION_FAILED );

		CLSID jpegClsid;
		dprintf( "Attempting to get the jpg class id" );
		if( get_encoder_clsid( L"image/jpeg", &jpegClsid ) != ERROR_SUCCESS )
			BREAK_WITH_ERROR( "Unable to find an appropriate image encoder", ERROR_FUNCTION_FAILED );

		if( (pBitmap = new Bitmap( lpBI, lpDIB ) ) == NULL )
			BREAK_WITH_ERROR( "Failed to create bitmap instance", ERROR_FUNCTION_FAILED );

		EncoderParameters encParams;
		encParams.Count = 1;
		encParams.Parameter[0].NumberOfValues = 1;
		encParams.Parameter[0].Guid           = EncoderQuality;
		encParams.Parameter[0].Type           = EncoderParameterValueTypeLong;
		encParams.Parameter[0].Value          = &ulQuality;

		if( CreateStreamOnHGlobal( NULL, TRUE, &pStream ) != S_OK )
			BREAK_WITH_ERROR( "Failed to create stream", ERROR_FUNCTION_FAILED );

		if( pBitmap->Save( pStream, &jpegClsid, &encParams ) != Ok )
			BREAK_WITH_ERROR( "Failed to save image to stream", ERROR_FUNCTION_FAILED );

		STATSTG stat;
		if( pStream->Stat( &stat, STATFLAG_NONAME ) != S_OK )
			BREAK_WITH_ERROR( "Failed to get image stat", ERROR_FUNCTION_FAILED );

		// if the image requires the quadpart, then we're in trouble anyway!
		pImage->dwImageBufferSize = stat.cbSize.LowPart;
		if( (pImage->pImageBuffer = (LPBYTE)malloc( pImage->dwImageBufferSize ) ) == NULL )
			BREAK_WITH_ERROR( "Failed to allocate memory for the JPEG", ERROR_OUTOFMEMORY );

		ULARGE_INTEGER pos;
		LARGE_INTEGER zero;
		zero.QuadPart = 0;
		pos.QuadPart = 0;
		if( pStream->Seek( zero, STREAM_SEEK_SET, &pos ) != S_OK )
			BREAK_WITH_ERROR( "Failed set stream position", ERROR_FUNCTION_FAILED );

		ULONG bytesRead = 0;
		if( (hRes = pStream->Read( pImage->pImageBuffer, pImage->dwImageBufferSize, &bytesRead ) != S_OK) ) {
			dprintf( "Failed to read image data from stream: %u %x", hRes, hRes );
			dwResult = ERROR_FUNCTION_FAILED;
			break;
		}

		if( bytesRead != pImage->dwImageBufferSize )
			BREAK_WITH_ERROR( "Failed to read image data from stream", ERROR_FUNCTION_FAILED );
	} while(0);

	if( dwResult != ERROR_SUCCESS && pImage->pImageBuffer != NULL ) {
		free( pImage->pImageBuffer );
		pImage->pImageBuffer = NULL;
	}

	if( pStream != NULL )
		pStream->Release();

	if( pBitmap != NULL )
		delete pBitmap;

	if( gdiPlusToken != 0 )
		GdiplusShutdown( gdiPlusToken );
	
	return dwResult;
}

}