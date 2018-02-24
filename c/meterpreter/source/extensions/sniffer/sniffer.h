#ifndef _METERPRETER_SOURCE_EXTENSION_SNIFFER_SNIFFER_H
#define _METERPRETER_SOURCE_EXTENSION_SNIFFER_SNIFFER_H

#include "../../common/common.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>

#include "dnet.h"
#define HAVE_REMOTE

#include <pcap/pcap.h>

#pragma comment(lib , "ws2_32.lib") //For winsock
#pragma comment(lib , "wpcap.lib") //For winpcap

// #include <errno.h>
#define lock_acquire(sm) EnterCriticalSection(&sm)
#define lock_release(sm) LeaveCriticalSection(&sm)
#define lock_destroy(sm) DeleteCriticalSection(&sm)
#endif

#ifndef ERROR_ACCESS_DENIED
 #define ERROR_ACCESS_DENIED EACCES
#endif


typedef struct capturejob
{
	unsigned int active;
	unsigned int intf;
	unsigned int max_pkts;
	unsigned int idx_pkts;
	unsigned int cur_pkts;
	unsigned int cur_bytes;
	unsigned int mtu;
	struct PeterPacket **pkts;
	unsigned char *dbuf;
	unsigned int dlen;
	unsigned int didx;
	int capture_linktype; //current capture link type that we want to save, ie. LINKTYPE_ETHERNET
#ifdef _WIN32
	HANDLE thread;
#else
	THREAD *thread;
#endif
	pcap_t *pcap;
} CaptureJob;

#define TLV_TYPE_EXTENSION_SNIFFER	0


#define TLV_TYPE_SNIFFER_INTERFACES	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_GROUP,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 1)

#define TLV_TYPE_SNIFFER_INTERFACE_ID	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 2)

#define TLV_TYPE_SNIFFER_INTERFACE_HANDLE	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 3)

#define TLV_TYPE_SNIFFER_PACKET_COUNT	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 4)

#define TLV_TYPE_SNIFFER_BYTE_COUNT	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_UINT,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 5)

#define TLV_TYPE_SNIFFER_EXCLUDE_PORTS	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_GROUP,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 6)

#define TLV_TYPE_SNIFFER_INCLUDE_PORTS	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_GROUP,				\
				TLV_TYPE_EXTENSION_SNIFFER,		\
				TLV_EXTENSIONS + 7)

#define TLV_TYPE_SNIFFER_PACKETS	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_GROUP,				\
				TLV_TYPE_EXTENSION_SNIFFER,		    \
				TLV_EXTENSIONS + 8)

#define TLV_TYPE_SNIFFER_PACKET	\
		MAKE_CUSTOM_TLV(							\
				TLV_META_TYPE_RAW,  				\
				TLV_TYPE_EXTENSION_SNIFFER,	    	\
				TLV_EXTENSIONS + 9)

#define TLV_TYPE_SNIFFER_ADDITIONAL_FILTER				\
		MAKE_CUSTOM_TLV(					\
			TLV_META_TYPE_STRING,				\
			TLV_TYPE_EXTENSION_SNIFFER,			\
			TLV_EXTENSIONS + 10)

#endif
