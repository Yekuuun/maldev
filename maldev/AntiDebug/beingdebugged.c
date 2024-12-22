#include "utils.h"

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

//noobie.
BOOL Noobie(){
    return IsDebuggerPresent();
}

//using PEB flag.
BOOL IsBeingDebuggedWithPebFlag(){
    #ifdef _WIN64
        PPEB					pPeb = (PEB*)(__readgsqword(0x60));
    #elif _WIN32
        PPEB					pPeb = (PEB*)(__readfsdword(0x30));
    #endif

    return pPeb->BeingDebugged == 1;
}

//using NtGlobalFlag.
BOOL IsBeingDebuggedNtGlobalFlag(){
    #ifdef _WIN64
        PPEB					pPeb = (PEB*)(__readgsqword(0x60));
    #elif _WIN32
        PPEB					pPeb = (PEB*)(__readfsdword(0x30));
    #endif

    return pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS);
}

/**
 * Consider using other techniques
 * 
 * - NtQuerySystemInformation
 * - Hardware breakpoints
 * - GetTickCount64
 */

//test.
int main(){
    return EXIT_SUCCESS;
}