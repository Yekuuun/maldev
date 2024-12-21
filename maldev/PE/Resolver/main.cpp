/**
 * Author : Yekuuun
 * Github : https://github.com/yekuuun
 * 
 * Notes : this file contains a custom GetModuleHandleW & GetProcessAddress implementation avoiding using windows.h header file.
 * Notes : I didn't use any imports.
 * 
 * Notes : this code might not pe super clean but it works fine;)
 * 
 * Notes => USE HASHING TECHNIQUES FOR FUNCTION NAMES OBFUSCATION !
 */

#include "ntheader.hpp"

/**
 * @returns length of a LPCSTR string
 */
size_t CustomStrLenA(LPCSTR str){
    LPCSTR ptrStr = str;
    while(*str != '\0')
    {
        str++;
    }
    return str - ptrStr;
}

/**
 * Compater 2 strings (LPCSTR)
 */
BOOL CompareStringsA(LPCSTR str1, LPCSTR str2){
    if(str1 == nullptr || str2 == nullptr)
    {
        return false;
    }

    if(CustomStrLenA(str1) != CustomStrLenA(str2))
    {
        return false;
    }

    while(*str1 != '\0' && *str2 != '\0')
    {
        if(*str1 != *str2)
        {
            return false;
        }
        str2++;
        str1++;
    }
    return true;
}

/**
 * Base check if string contains another.
 */
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

/**
 * Base GetProcAddress function reimplementing
 * @param hModule retrieved from GetModuleHandleW (address of loaded DLL)
 * @param procName name of function to be retrieved (ex : NtQuerySystemInformation)
 * @return base address of function found.
 */
PVOID GetProcAddress(HMODULE hModule, LPCSTR procName){
    if(hModule == nullptr || procName == nullptr){
        return nullptr;
    }

    BYTE* dllAddress = (BYTE*)hModule;

    PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)hModule;


    PIMAGE_NT_HEADERS64 ptrNtHeader = (PIMAGE_NT_HEADERS64)(dllAddress + ptrDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 ptrOptionnalHeader = &ptrNtHeader->OptionalHeader;

    PIMAGE_EXPORT_DIRECTORY ptrImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + ptrOptionnalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //address of AddressOfNames
    auto rvaNames = (DWORD*)(dllAddress + ptrImageExportDirectory->AddressOfNames);
    auto rvaOrdinalsNames = (WORD*)(dllAddress + ptrImageExportDirectory->AddressOfNameOrdinals);
    auto rvaFunction = (DWORD*)(dllAddress + ptrImageExportDirectory->AddressOfFunctions);

    //looping through names exported
    for(int i = 0; i < ptrImageExportDirectory->NumberOfNames; i++)
    {
        char* functionName = (char*)(dllAddress + rvaNames[i]);
        //compare strings
        if(CompareStringsA(functionName, procName))
        {
            return (LPVOID)(dllAddress + rvaFunction[rvaOrdinalsNames[i]]);
        }
    }

    return nullptr;
}

/**
 * List current running processes using NtQuerySystemInformation
 * 
 * @return List of PID's of running processes.
 */
BOOL GetProcessInformation(){
    wchar_t dllName[]      = L"ntdll.dll";
    ULONG sizePtr          = 0;
    ULONG bufferSize       = 0;
    LPVOID buffer          = nullptr;

    //getting address of NtQuerySystemInformation using custom GetModuleHandle() & GetProcAddress()
    PNTQUERYSYSTEMINFORMATION ptrNtQuerySystemInformation = (PNTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(dllName), "NtQuerySystemInformation");

    NTSTATUS status = ptrNtQuerySystemInformation(SystemProcessInformation, nullptr, sizePtr, &bufferSize);

    while(status == STATUS_INFO_LENGTH_MISMATCH)
    {
        buffer = malloc(bufferSize);
        sizePtr = bufferSize;
        if(buffer == nullptr)
        {
            std::cout << "[-] error allocating memory" << std::endl;
            return false;
        }
        status = ptrNtQuerySystemInformation(SystemProcessInformation, buffer, sizePtr, &bufferSize);
    }

    if(status != STATUS_SUCCESS)
    {
        std::cout << "[-] error calling NtQuerySystemInformation" << std::endl;
        return false;
    }

    PSYSTEM_PROCESS_INFORMATION ptrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    if(ptrProcessInfo == nullptr)
    {
        std::cout << "[-] nullptr for process informations" <<std::endl;
        free(buffer);
        return false;
    }

    std::cout << "\nListing Processes running using NtQuerySystemInformation :" << std::endl;
    std::cout << "---------------------------------------------" << std::endl;
    while(ptrProcessInfo->NextEntryOffset)
    {
        ULONG processId = (ULONG)(ULONG_PTR )ptrProcessInfo->UniqueProcessId;
        std::cout << std::dec;
        std::cout << "[*] PROCESS ID : " << processId << std::endl;

        ptrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)ptrProcessInfo + ptrProcessInfo->NextEntryOffset);
    }

    free(buffer);
    return true;
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

    PVOID procAddress = GetProcAddress(dllAddress, "NtQuerySystemInformation");

    if(procAddress != nullptr){
        printf("address of proc : %p \n", procAddress);
    }
    else {
        printf("Failed to find procAddress: %ls\n", dllName);
    }

    BOOL listProcess = GetProcessInformation();
    if(!listProcess)
    {
        return EXIT_FAILURE;
    }

    return 0;
}