#pragma once
#include <iostream>

///----------------DATA TYPES-----------------
typedef void VOID;
typedef void* PVOID;
typedef void* LPVOID;
typedef void* HANDLE;
typedef void* HMODULE;

typedef unsigned char BYTE;
typedef unsigned char* PBYTE;

typedef char* LPSTR;
typedef const char* LPCSTR;
typedef wchar_t* LPCWSTR;
typedef bool BOOL;

typedef size_t SIZE_T;

typedef unsigned short WORD;
typedef unsigned int UINT;
typedef unsigned long long UINT64;
typedef unsigned long DWORD;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long* PULONG;
typedef __int64 LONGLONG;
typedef LONG KPRIORITY;
typedef unsigned long long ULONGLONG;
typedef unsigned __int64 ULONG_PTR;
typedef LONG KPRIORITY, *PKPRIORITY;

extern "C" unsigned __int64 __readgsqword(unsigned long Offset);

#ifdef _WIN64
#define TIB_OFFSET 0x30
#else
#define TIB_OFFSET 0x18
#endif

#ifdef _WIN64
#define PEB_OFFSET 0x60
#else
#define PEB_OFFSET 0x30
#endif

#ifndef WINAPI
#define WINAPI __stdcall
#endif

#define NTAPI __stdcall

typedef LONG NTSTATUS;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)
#define STATUS_ACCESS_VIOLATION ((NTSTATUS)0xC0000005)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)

//-----------------STRUCTURES----------------------

//list of loaded modules
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
    unsigned short	length;
    unsigned short	maxLength;
    unsigned char	Reserved[4];
    wchar_t*			buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _ACTIVATION_CONTEXT
{
    unsigned long       magic;
    int                 ref_count;
    //struct file_info    config;
    //struct file_info    appdir;
    struct assembly    *assemblies;
    unsigned int        num_assemblies;
    unsigned int        allocated_assemblies;
    /* section data */
    unsigned long       sections;
    struct strsection_header  *wndclass_section;
    struct strsection_header  *dllredirect_section;
    struct strsection_header  *progid_section;
    struct guidsection_header *tlib_section;
    struct guidsection_header *comserver_section;
    struct guidsection_header *ifaceps_section;
    struct guidsection_header *clrsurrogate_section;
} ACTIVATION_CONTEXT;

//loaded module information
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY			InLoadOrderLinks;				/* 0x00 */
    LIST_ENTRY			InMemoryOrderLinks;				/* 0x10 */
    LIST_ENTRY			InInitializationOrderLinks;		/* 0x20 */
    void*				DllBase;						/* 0x30 */
    void*				EntryPoint;						/* 0x38 */
    unsigned long		SizeOfImage;					/* 0x40 */
    UNICODE_STRING		FullDllName;					/* 0x48 */
    UNICODE_STRING		BaseDllName;					/* 0x58 */
    unsigned long Flags;
    unsigned short LoadCount;
    unsigned short TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            void* SectionPointer;
            unsigned long CheckSum;
        };
    };
    union
    {
        unsigned long TimeDateStamp;
        void* LoadedImports;
    };
    _ACTIVATION_CONTEXT * EntryPointActivationContext;
    void* PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

//entry to loaded modules in memory
typedef struct _PEB_LDR_DATA {
    unsigned int		Length;
    unsigned int		Initialized;
    unsigned short		SsHandle;
    LIST_ENTRY			InLoadOrderModuleList;
    LIST_ENTRY			InMemoryOrderModuleList;
    void*				EntryInProgress;
    unsigned short		ShutdownInProgress;
    void*				ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

//PEB STRUCT
typedef struct _PEB {
    unsigned char		InheritedAddressSpace;
    unsigned char		ReadImageFileExecOptions;
    unsigned char		BeginDebugged;
    unsigned char		Reserved[5];
    unsigned short		Mutant;
    void*				ImageBaseAddress;
    PPEB_LDR_DATA		Ldr;
} PEB, *PPEB;

//TIB STRUCT
typedef struct _TIB {
    unsigned char	Stuff[0x60];
    PPEB			pPEB;
} TIB, *PTIB;

//-------------------------PE STRUCTS--------------------------
#define IMAGE_DOS_SIGNATURE                                    0x5A4D      //MZ
#define IMAGE_NT_SIGNATURE                                     0x50450000  //PE00

#define IMAGE_SIZEOF_FILE_HEADER                               20
#define IMAGE_SIZEOF_SECTION_HEADER                            40
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES                       16
#define IMAGE_SIZEOF_SHORT_NAME                                8

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC                          0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC                          0x20b

typedef enum _PE_MAGIC // uint16_t
{
    PE_ROM_IMAGE = 0x107,
    PE_32BIT = 0x10b,
    PE_64BIT = 0x20b
}PE_MAGIC, * PPE_MAGIC;

#define IMAGE_ORDINAL_FLAG64                                   0x8000000000000000
#define IMAGE_ORDINAL_FLAG32                                   0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define IMAGE_DIRECTORY_ENTRY_EXPORT                           0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT                           1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE                         2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION                        3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY                         4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC                        5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG                            6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE                     7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR                        8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS                              9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG                      10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT                     11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT                              12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT                     13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR                   14   // COM Runtime descriptor

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _RICH_HEADER
{
    DWORD e_magic__DanS;
    DWORD e_align[0x3];
    DWORD e_entry_id0__00937809;
    DWORD e_entry_count0__51;
    DWORD e_entry_id1__00010000;
    DWORD e_entry_count1__135;
    DWORD e_entry_id2__00fd6b14;
    DWORD e_entry_count2__1;
    DWORD e_entry_id3__01006b14;
    DWORD e_entry_count3__1;
    DWORD e_entry_id4__01036b14;
    DWORD e_entry_count4__50;
    DWORD e_entry_id5__01056b14;
    DWORD e_entry_count5__94;
    DWORD e_entry_id6__010e6b14;
    DWORD e_entry_count6__568;
    DWORD e_entry_id7__01046b14;
    DWORD e_entry_count7__75;
    DWORD e_entry_id8__00ff6b14;
    DWORD e_entry_count8__1;
    DWORD e_entry_id9__01026b14;
    DWORD e_entry_count9__1;
    char e_magic[0x4];
    DWORD e_checksum;
}RICH_HEADER, * PRICH_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

//-----------------NTQUERYSYSTEMINFORMATION NEEDS----------------

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    WrIoRing,
    WrMdlCache,
    MaximumWaitReason
} KWAIT_REASON, *PKWAIT_REASON;

typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } THANKSARSIUM;
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef enum _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    ULONG_PTR StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
    ULONG ContextSwitches;
    KTHREAD_STATE ThreadState;
    KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,             // obsolete...delete
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformation = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;


typedef struct {
    ULONG PriorityClass;
    ULONG PrioritySubClass;
} KSPRIORITY, *PKSPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount; // since WIN7
    ULONG NumberOfThreadsHighWatermark; // since WIN7
    ULONGLONG CycleTime; // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS NTAPI NTQUERYSYSTEMINFORMATION (
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
); typedef NTQUERYSYSTEMINFORMATION* PNTQUERYSYSTEMINFORMATION;