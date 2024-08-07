#ifndef POOL_PARTY_H
#define POOL_PARTY_H
#pragma once
typedef struct IUnknown IUnknown;
#include <windows.h>
#include <winbase.h>
#include <winternl.h>

// ---------//
// Structs //
// --------//
#ifndef __MINGW32__
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
#endif

//typedef struct _FILE_IO_COMPLETION_INFORMATION
//{
//    PVOID KeyContext;
//    PVOID ApcContext;
//    IO_STATUS_BLOCK IoStatusBlock;
//} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef struct _FILE_COMPLETION_INFORMATION {
    HANDLE Port;
    PVOID  Key;
} FILE_COMPLETION_INFORMATION, * PFILE_COMPLETION_INFORMATION;


typedef struct _ALPC_PORT_ATTRIBUTES
{
    unsigned long Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    unsigned __int64 MaxMessageLength;
    unsigned __int64 MemoryBandwidth;
    unsigned __int64 MaxPoolUsage;
    unsigned __int64 MaxSectionSize;
    unsigned __int64 MaxViewSize;
    unsigned __int64 MaxTotalSectionSize;
    ULONG DupObjectTypes;
#ifdef _WIN64
    ULONG Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef struct _PORT_MESSAGE
{
    union
    {
        struct
        {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union
    {
        struct
        {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union
    {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
        ULONG CallbackId; // only valid for LPC_REQUEST messages
    };
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE {
    PORT_MESSAGE PortHeader;
    BYTE PortMessage[1000]; // Hard limit for this is 65488. An Error is thrown if AlpcMaxAllowedMessageLength() is exceeded
} ALPC_MESSAGE, * PALPC_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    ULONG AllocatedAttributes;
    ULONG ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ASSOCIATE_COMPLETION_PORT
{
    PVOID CompletionKey;
    HANDLE CompletionPort;
} ALPC_PORT_ASSOCIATE_COMPLETION_PORT, * PALPC_PORT_ASSOCIATE_COMPLETION_PORT;

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG Version;
    ULONG Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
{
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// -------------//
// Enumerations //
// ------------//

typedef enum
{
    SeDebugPrivilege = 20
} PRIVILEGES;

enum ALPC_PORT_INFOCLASS
{
    AlpcAssociateCompletionPortInformation = 2
};

enum FILE_INFOCLASS
{
    FileReplaceCompletionInformation = 61
};

enum PROCESS_INFOCLASS
{
    ProcessHandleInformation = 51
};

typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation,
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, // 10
    WorkerFactoryThreadBasePriority,
    WorkerFactoryTimeoutWaiters, // since THRESHOLD
    WorkerFactoryFlags,
    WorkerFactoryThreadSoftMaximum,
    MaxWorkerFactoryInfoClass
} _WORKERFACTORYINFOCLASS;

// ---------//
// Structs //
// --------//

typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;

typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;

typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;

typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;

typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;

typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;

typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;

typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;

typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;

typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;

typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;

typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    UINT32 ThreadId;
    UINT32 ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;

typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;

typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;

typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;

typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;

typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;

typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;

typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER, * PFULL_TP_TIMER;

typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;

typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;

typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;

typedef struct _FULL_TP_JOB
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* JobHandle;
    union
    {
        volatile long long CompletionState;
        long long Rundown : 1;
        long long CompletionCount : 63;
    };
    struct _RTL_SRWLOCK RundownLock;
} FULL_TP_JOB, * PFULL_TP_JOB;

typedef VOID(NTAPI* PTP_ALPC_CALLBACK)(
    _Inout_ PTP_CALLBACK_INSTANCE Instance,
    _Inout_opt_ PVOID Context,
    _In_ PFULL_TP_ALPC Alpc
    );

typedef struct pNtDll {
    NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    NTSTATUS(NTAPI* pNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    NTSTATUS(NTAPI* pZwAssociateWaitCompletionPacket)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN);
    NTSTATUS(NTAPI* pZwSetIoCompletion)(HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR);
 
    //NTSTATUS(NTAPI* pZwSetInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
    //NTSTATUS(NTAPI* pNtAlpcCreatePort)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES);
    //NTSTATUS(NTAPI* pNtAlpcSetInformation)(HANDLE, ULONG, PVOID, ULONG);
    //NTSTATUS(NTAPI* pNtAlpcConnectPort)(PHANDLE, PUNICODE_STRING, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, DWORD, PSID, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER);
    //NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
    //NTSTATUS(NTAPI* pNtSetTimer2)(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS);

    //NTSTATUS(NTAPI* pNtTpAllocAlpcCompletion)(PVOID, HANDLE, PVOID, PVOID, PVOID);
    //NTSTATUS(NTAPI* pTpAllocJobNotification)(PVOID, HANDLE, PVOID, PVOID, PVOID);

    //NTSTATUS(NTAPI* pNtQueryInformationWorkerFactory)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG, PULONG);
    //NTSTATUS(NTAPI* pNtSetInformationWorkerFactory)(HANDLE, _WORKERFACTORYINFOCLASS, PVOID, ULONG);
}pNtDll;
#endif