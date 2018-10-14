#ifndef _METERPRETER_SERVER_SETUP_WINDNS
#define _METERPRETER_SERVER_SETUP_WINDNS

#define MAX_DNS_NAME_SIZE 253
#define MAX_DNS_SUBNAME_SIZE 62
#define THREADS_MAX 5

#include <ws2tcpip.h>
#include <windns.h>
#pragma comment (lib, "Dnsapi.lib")

#pragma pack(push, 1)
typedef struct _IncapsulatedDns
{
	size_t size;
	PUCHAR packet;
	USHORT status;
} IncapsulatedDns;


typedef struct _DnsReverseHeader
{
	BYTE next_sub_seq[8];
	BYTE status_flag;
	DWORD size;
	BYTE reserved;
} DnsReverseHeader;


typedef union _DnsData
{
	BYTE data[14];
	DnsReverseHeader header;
} DnsData;

typedef struct _DnsIPv6Tunnel
{
	BYTE ff;
	BYTE index_size;
	DnsData block;
} DnsIPv6Tunnel;

typedef struct _DNSThreadParams
{
	PHANDLE mutex;
	size_t index;
    size_t index_stop;
	WORD request_type;
	wchar_t *subd;
	wchar_t *domain;
    wchar_t *client_id;
	PIP4_ARRAY pSrvList;
	UINT size;
    UINT status;
	UCHAR *result;
} DNSThreadParams;
#pragma pack(pop)

void transport_write_dns_config(Transport* transport, MetsrvTransportDns* config);
Transport* transport_create_dns(MetsrvTransportDns* config);

#endif