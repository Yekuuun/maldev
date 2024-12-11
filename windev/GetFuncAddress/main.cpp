/**
 * Author : Yekuuun
 * Github : https://github.com/yekuuun
 * 
 * Notes : this file contains a custom GetModuleHandleW & GetProcessAddress implementation avoiding using windows.h header file.
 * Notes : I didn't use any imports.
 */

#include "ntheader.hpp"

BOOL StringContains(wchar_t* haystack, wchar_t* needle){
    while(*haystack && (*haystack == *needle)){
        haystack++;
        needle++;
    }

    return (*haystack == *needle);
}

/**
 * Return ptr to PEB.
 */
PVOID GetPebAddress(){
    return (PVOID)(__readgsqword(PEB_OFFSET));
}

/**
 * Return base address of a module loaded in memory.
 * @param LPCWSTR moduleName => wchar_t* module name (NTDLL.dll)
 * @return PTR to loaded module (HMODULE)
 */
HMODULE GetModuleHandleW(LPCWSTR moduleName){
    if(moduleName == nullptr){
        return nullptr;
    }

    PPEB ptrPeb = (PPEB)GetPebAddress();

    if(ptrPeb == nullptr){
        return nullptr;
    }

    //loaded modules.
    PPEB_LDR_DATA ptrPebLdrData = ptrPeb->Ldr;
    PLIST_ENTRY ptrInMemoryModules = &ptrPebLdrData->InLoadOrderModuleList;

    //1st module
    PLIST_ENTRY moduleList = ptrInMemoryModules->Flink;

    while(moduleList != ptrInMemoryModules){
        PLDR_DATA_TABLE_ENTRY ptrLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)moduleList; //module base address.
        if(StringContains(ptrLdrDataTableEntry->BaseDllName.buffer, moduleName)){
            return ptrLdrDataTableEntry->DllBase;
        }

        moduleList = moduleList->Flink;
    }

    return nullptr;
}

//test.
int main(){
    LPCWSTR dllName = const_cast<LPCWSTR>(L"ntdll.dll");

    HMODULE dllAddress = GetModuleHandleW(dllName);

    if(dllAddress != nullptr){
        printf("address loaded DLL : %p \n", dllAddress);
    }
    else {
        printf("Failed to find module: %ls\n", dllName);
    }

    return 0;
}