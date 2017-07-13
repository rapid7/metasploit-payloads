#include <stdint.h>

typedef void* RTR0PTR;

typedef struct _SUPREQHDR {
    /** Cookie. */
    uint32_t        u32Cookie;
    /** Session cookie. */
    uint32_t        u32SessionCookie;
    /** The size of the input. */
    uint32_t        cbIn;
    /** The size of the output. */
    uint32_t        cbOut;
    /** Flags. See SUPREQHDR_FLAGS_* for details and values. */
    uint32_t        fFlags;
    /** The VBox status code of the operation, out direction only. */
    int32_t         rc;
} SUPREQHDR;

/** SUP_IOCTL_COOKIE. */
typedef struct _SUPCOOKIE {
    /** The header.
     * u32Cookie must be set to SUPCOOKIE_INITIAL_COOKIE.
     * u32SessionCookie should be set to some random value. */
    SUPREQHDR               Hdr;
    union
    {
        struct
        {
            /** Magic word. */
            char            szMagic[16];
            /** The requested interface version number. */
            uint32_t        u32ReqVersion;
            /** The minimum interface version number. */
            uint32_t        u32MinVersion;
        } In;
        struct
        {
            /** Cookie. */
            uint32_t        u32Cookie;
            /** Session cookie. */
            uint32_t        u32SessionCookie;
            /** Interface version for this session. */
            uint32_t        u32SessionVersion;
            /** The actual interface version in the driver. */
            uint32_t        u32DriverVersion;
            /** Number of functions available for the SUP_IOCTL_QUERY_FUNCS request. */
            uint32_t        cFunctions;
            /** Session handle. */
            /*R0PTRTYPE(PSUPDRVSESSION)*/ PVOID   pSession;
        } Out;
    } u;
} SUPCOOKIE, *PSUPCOOKIE;

typedef struct _SUPLDROPEN {
    /** The header. */
    SUPREQHDR               Hdr;
    union
    {
        struct
        {
            /** Size of the image we'll be loading. */
            uint32_t        cbImage;
            /** Image name.
             * This is the NAME of the image, not the file name. It is used
             * to share code with other processes. (Max len is 32 chars!)  */
            char            szName[32];
        } In;
        struct
        {
            /** The base address of the image. */
            RTR0PTR         pvImageBase;
            /** Indicate whether or not the image requires loading. */
            BOOLEAN         fNeedsLoading;
        } Out;
    } u;
} SUPLDROPEN, *PSUPLDROPEN;

typedef enum _SUPLDRLOADEP {
    SUPLDRLOADEP_NOTHING = 0,
    SUPLDRLOADEP_VMMR0,
    SUPLDRLOADEP_SERVICE,
    SUPLDRLOADEP_32BIT_HACK = 0x7fffffff
} SUPLDRLOADEP;

typedef struct _SUPSETVMFORFAST {
    /** The header. */
    SUPREQHDR               Hdr;
    union
    {
        struct
        {
            /** The ring-0 VM handle (pointer). */
            PVOID           pVMR0;
        } In;
    } u;
} SUPSETVMFORFAST, *PSUPSETVMFORFAST;

typedef struct _SUPLDRLOAD
{
    /** The header. */
    SUPREQHDR               Hdr;
    union
    {
        struct
        {
            /** The address of module initialization function. Similar to _DLL_InitTerm(hmod, 0). */
            PVOID pfnModuleInit;
            /** The address of module termination function. Similar to _DLL_InitTerm(hmod, 1). */
            PVOID pfnModuleTerm;
            /** Special entry points. */
            union
            {
                /** SUPLDRLOADEP_VMMR0. */
                struct
                {
                    /** The module handle (i.e. address). */
                    RTR0PTR                 pvVMMR0;
                    /** Address of VMMR0EntryInt function. */
                    RTR0PTR                 pvVMMR0EntryInt;
                    /** Address of VMMR0EntryFast function. */
                    RTR0PTR                 pvVMMR0EntryFast;
                    /** Address of VMMR0EntryEx function. */
                    RTR0PTR                 pvVMMR0EntryEx;
                } VMMR0;
                /** SUPLDRLOADEP_SERVICE. */
                struct
                {
                    /** The service request handler.
                     * (PFNR0SERVICEREQHANDLER isn't defined yet.) */
                    RTR0PTR                 pfnServiceReq;
                    /** Reserved, must be NIL. */
                    RTR0PTR                 apvReserved[3];
                } Service;
            }               EP;
            /** Address. */
            RTR0PTR         pvImageBase;
            /** Entry point type. */
            SUPLDRLOADEP    eEPType;
            /** The offset of the symbol table. */
            uint32_t        offSymbols;
            /** The number of entries in the symbol table. */
            uint32_t        cSymbols;
            /** The offset of the string table. */
            uint32_t        offStrTab;
            /** Size of the string table. */
            uint32_t        cbStrTab;
            /** Size of image (including string and symbol tables). */
            uint32_t        cbImage;
            /** The image data. */
            char            achImage[1];
        } In;
    } u;
} SUPLDRLOAD, *PSUPLDRLOAD;


#define RT_SIZEOFMEMB(type, member) ( sizeof(((type *)(void *)0)->member) )
#define SUPCOOKIE_INITIAL_COOKIE                        0x69726f74 /* 'tori' */
#define SUP_IOCTL_COOKIE_SIZE_IN                        sizeof(SUPREQHDR) + RT_SIZEOFMEMB(SUPCOOKIE, u.In)
#define SUP_IOCTL_COOKIE_SIZE_OUT                       sizeof(SUPREQHDR) + RT_SIZEOFMEMB(SUPCOOKIE, u.Out)

#define SUP_IOCTL_FLAG     128

#define SUP_CTL_CODE_SIZE(Function, Size)      CTL_CODE(FILE_DEVICE_UNKNOWN, (Function) | SUP_IOCTL_FLAG, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define SUP_CTL_CODE_BIG(Function)             CTL_CODE(FILE_DEVICE_UNKNOWN, (Function) | SUP_IOCTL_FLAG, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define SUP_CTL_CODE_FAST(Function)            CTL_CODE(FILE_DEVICE_UNKNOWN, (Function) | SUP_IOCTL_FLAG, METHOD_NEITHER,  FILE_WRITE_ACCESS)
#define SUP_CTL_CODE_NO_SIZE(uIOCtl)           (uIOCtl)

/** The magic value. */
#define SUPREQHDR_FLAGS_MAGIC                           UINT32_C(0x42000042)
/** The default value. Use this when no special stuff is requested. */
#define SUPREQHDR_FLAGS_DEFAULT                         SUPREQHDR_FLAGS_MAGIC
#define VERR_INTERNAL_ERROR                 (-225)
#define SUPCOOKIE_MAGIC                                 "The Magic Word!"
#define SUPDRV_IOC_VERSION                              0x001a0007
/** The request size. */
#define SUP_IOCTL_COOKIE_SIZE                           sizeof(SUPCOOKIE)
/** Negotiate cookie. */
#define SUP_IOCTL_COOKIE                                SUP_CTL_CODE_SIZE(1, SUP_IOCTL_COOKIE_SIZE)

/** There is extra input that needs copying on some platforms. */
#define SUPREQHDR_FLAGS_EXTRA_IN                        UINT32_C(0x00000100)
/** There is extra output that needs copying on some platforms. */
#define SUPREQHDR_FLAGS_EXTRA_OUT                       UINT32_C(0x00000200)

/** @name SUP_IOCTL_SET_VM_FOR_FAST
 * Set the VM handle for doing fast call ioctl calls.
 * @{
 */
#define SUP_IOCTL_SET_VM_FOR_FAST                       SUP_CTL_CODE_SIZE(19, SUP_IOCTL_SET_VM_FOR_FAST_SIZE)
#define SUP_IOCTL_SET_VM_FOR_FAST_SIZE                  sizeof(SUPSETVMFORFAST)
#define SUP_IOCTL_SET_VM_FOR_FAST_SIZE_IN               sizeof(SUPSETVMFORFAST)
#define SUP_IOCTL_SET_VM_FOR_FAST_SIZE_OUT              sizeof(SUPREQHDR)
#define SUP_IOCTL_FAST_DO_NOP							SUP_CTL_CODE_FAST(66)

#define SUP_IOCTL_LDR_OPEN                              SUP_CTL_CODE_SIZE(5, SUP_IOCTL_LDR_OPEN_SIZE)
#define SUP_IOCTL_LDR_OPEN_SIZE                         sizeof(SUPLDROPEN)
#define SUP_IOCTL_LDR_OPEN_SIZE_IN                      sizeof(SUPLDROPEN)
#define SUP_IOCTL_LDR_OPEN_SIZE_OUT                     (sizeof(SUPREQHDR) + RT_SIZEOFMEMB(SUPLDROPEN, u.Out))

#define SUP_IOCTL_LDR_LOAD                              SUP_CTL_CODE_BIG(6)
#define SUP_IOCTL_LDR_LOAD_SIZE(cbImage)                RT_UOFFSETOF(SUPLDRLOAD, u.In.achImage[cbImage])
#define SUP_IOCTL_LDR_LOAD_SIZE_IN(cbImage)             RT_UOFFSETOF(SUPLDRLOAD, u.In.achImage[cbImage])
#define SUP_IOCTL_LDR_LOAD_SIZE_OUT                     sizeof(SUPREQHDR)

 /** @name SUP_IOCTL_LDR_FREE
 * Free an image.
 * @{
 */
#define SUP_IOCTL_LDR_FREE                              SUP_CTL_CODE_SIZE(7, SUP_IOCTL_LDR_FREE_SIZE)
#define SUP_IOCTL_LDR_FREE_SIZE                         sizeof(SUPLDRFREE)
#define SUP_IOCTL_LDR_FREE_SIZE_IN                      sizeof(SUPLDRFREE)
#define SUP_IOCTL_LDR_FREE_SIZE_OUT                     sizeof(SUPREQHDR)

typedef struct _SUPLDRFREE {
	/** The header. */
	SUPREQHDR               Hdr;
	union
	{
		struct
		{
			/** Address. */
			RTR0PTR         pvImageBase;
		} In;
	} u;
} SUPLDRFREE, *PSUPLDRFREE;
