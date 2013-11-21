/*!
 * @file common.h
 * @brief Declarations for various common components used across the Meterpreter suite.
 */
#ifndef _METERPRETER_SOURCE_COMMON_COMMON_H
#define _METERPRETER_SOURCE_COMMON_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>

	typedef DWORD __u32;
	typedef struct ___u128 {
		__u32 a1;
		__u32 a2;
		__u32 a3;
		__u32 a4;
	}__u128;
#endif
#include "openssl/ssl.h"
#ifdef _UNIX
#include "compat_types.h"

#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/endian.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <sys/atomics.h>

#define FLAGS_LEN 100

typedef struct ___u128 {
    __u32 a1;
    __u32 a2;
    __u32 a3;
    __u32 a4;
}__u128;

struct iface_address {
	int family;
	union {
		__u32  addr;
		__u128 addr6;
	} ip;
	union {
		__u32  netmask;
		__u128 netmask6;
	} nm;
};

struct iface_entry {
	unsigned char name[IFNAMSIZ+1];
	unsigned char hwaddr[6];
	uint32_t mtu;
	uint32_t index;
	unsigned char flags[FLAGS_LEN+1];
	int addr_count;
	struct iface_address *addr_list;
};

struct ifaces_list {
	int entries;
	struct iface_entry ifaces[0];
};

struct ipv4_route_entry {
	__u32 dest;
	__u32 netmask;
	__u32 nexthop;
	unsigned char interface[IFNAMSIZ+1];
	__u32 metric;
};

struct ipv6_route_entry {
	__u128 dest6;
	__u128 netmask6;
	__u128 nexthop6;
	unsigned char interface[IFNAMSIZ+1];
	__u32 metric;
};

struct ipv4_routing_table {
	int entries;
	struct ipv4_route_entry routes[0];
};

struct ipv6_routing_table {
	int entries;
	struct ipv6_route_entry routes[0];
};

struct routing_table {
	struct ipv4_routing_table ** table_ipv4;
	struct ipv6_routing_table ** table_ipv6;
};

struct arp_entry {
	__u32  ipaddr;
	unsigned char hwaddr[6];
	unsigned char name[IFNAMSIZ+1];
};

struct arp_table {
	int entries;
	struct arp_entry table[0];
};



int netlink_get_routing_table(struct ipv4_routing_table **table_ipv4, struct ipv6_routing_table **table_ipv6);
int netlink_get_interfaces(struct ifaces_list **iface_list);

extern int debugging_enabled;

#define dprintf(...) if(debugging_enabled) { real_dprintf(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__); }

void real_dprintf(char *filename, int line, const char *function, char *format, ...);

#endif

#include "linkage.h"

#include "args.h"
#include "buffer.h"
#include "base.h"
#include "core.h"
#include "remote.h"

#include "channel.h"
#include "scheduler.h"
#include "thread.h"

#include "list.h"

#include "zlib/zlib.h"

/*! @brief Indication that the Meterpreter transport is using SSL. */
#define METERPRETER_TRANSPORT_SSL   0
/*! @brief Indication that the Meterpreter transport is using HTTP. */
#define METERPRETER_TRANSPORT_HTTP  1
/*! @brief Indication that the Meterpreter transport is using HTTPS. */
#define METERPRETER_TRANSPORT_HTTPS 2

#ifdef _WIN32


#include <wininet.h>

/*! @brief When defined, debug output is enabled on Windows builds. */
#define DEBUGTRACE 1

#ifdef DEBUGTRACE
#define dprintf(...) real_dprintf(__VA_ARGS__)
#else
#define dprintf(...) do{}while(0);
#endif

/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to `error`, prints debug output, then `break;` */
#define BREAK_WITH_ERROR( str, err ) { dwResult = err; dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `WASGetLastError()`, prints debug output, then does `break;` */
#define BREAK_ON_WSAERROR( str ) { dwResult = WSAGetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); break; }
/*! @brief Sets `dwResult` to the return value of `GetLastError()`, prints debug output, then does `continue;` */
#define CONTINUE_ON_ERROR( str ) { dwResult = GetLastError(); dprintf( "%s. error=%d (0x%x)", str, dwResult, (ULONG_PTR)dwResult ); continue; }

/*! @brief Close a service handle if not already closed and set the handle to NULL. */
#define CLOSE_SERVICE_HANDLE( h )  if( h ) { CloseServiceHandle( h ); h = NULL; }
/*! @brief Close a handle if not already closed and set the handle to NULL. */
#define CLOSE_HANDLE( h )          if( h ) { DWORD dwHandleFlags; if(GetHandleInformation( h , &dwHandleFlags)) CloseHandle( h ); h = NULL; }

#ifdef DEBUGTRACE
/*!
 * @brief Output a debug string to the debug console.
 * @details The function emits debug strings via `OutputDebugStringA`, hence all messages can be viewed
 *          using Visual Studio's _Output_ window, _DebugView_ from _SysInternals_, or _Windbg_.
 */
static void real_dprintf(char *format, ...) {
	va_list args;
	char buffer[1024];
	va_start(args,format);
	vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer)-3, format,args);
	strcat_s(buffer, sizeof(buffer), "\r\n");
	OutputDebugStringA(buffer);
}
#endif

#endif

#endif

int current_unix_timestamp(void);
