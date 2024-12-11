#pragma once
#include <windows.h>
#include <stdio.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L

//---------------------UTILS--------------------
typedef struct _PS_ATTRIBUTE {
    ULONG  Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

//--------------------INITIALIZE--------------------------

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

//-------------------NT FUNCTIONS-------------------------

//NTOPENPROCESS
typedef NTSTATUS NTAPI NTOPENPROCESS(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId OPTIONAL
); typedef NTOPENPROCESS* PNTOPENPROCESS;

//NTALLOCATEVIRTUALMEMORY
typedef NTSTATUS NTAPI* NTALLOCATEVIRTUALMEMORY(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
); typedef NTALLOCATEVIRTUALMEMORY* PNTALLOCATEVIRTUALMEMORY;

//NTPROTECTVIRTUALMEMORY
typedef NTSTATUS NTAPI* NTPROTECTVIRTUALMEMORY(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
); typedef NTPROTECTVIRTUALMEMORY* PNTPROTECTVIRTUALMEMORY;

//NTWRITEVIRTUALMEMORY
typedef NTSTATUS NTAPI* NTWRITEVIRTUALMEMORY(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL
); typedef NTWRITEVIRTUALMEMORY* PNTWRITEVIRTUALMEMORY;

//NTCREATETHREADEX
typedef NTSTATUS NTAPI* NTCREATETHREADEX(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL
); typedef NTCREATETHREADEX* PNTCREATETHREADEX;

//NTWAITFORSINGLEOBJECT
typedef NTSTATUS NTAPI* NTWAITFORSINGLEOBJECT(
    IN HANDLE Handle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL
); typedef NTWAITFORSINGLEOBJECT* PNTWAITFORSINGLEOBJECT;

//NTFREEVIRTUALMEMORY
typedef NTSTATUS NTAPI* NTFREEVIRTUALMEMORY(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
); typedef NTFREEVIRTUALMEMORY* PNTFREEVIRTUALMEMORY;

//NTCLOSE
typedef NTSTATUS NTAPI* NTCLOSE(
    IN HANDLE Handle
); typedef NTCLOSE* PNTCLOSE;