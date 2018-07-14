#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_AUDIO_AUDIO_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_AUDIO_AUDIO_H

#include <stdint.h>

/*
 * Channel allocation
 */
DWORD request_audio_output_channel_open(Remote *remote, Packet *packet);

#endif
