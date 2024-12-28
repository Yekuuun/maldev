/**
 * Base DLL unhooking from disk.
 */

#include "utils.h"

/**
 * Fetching local NTDLL.
 */
PVOID GetLocalNtdllAddress(){
    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #elif _WIN32
    PPEB pPeb = (PPEB)__readgsqword(0x30);
    #endif

    PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10); //The size of the LIST_ENTRY structure is 0x10,
    return pLdr->DllBase;
}

/**
 * Getting sizeof ntdll using OPTIONAL_HEADER.
 * @param => base address of module.
 */
SIZE_T GetSizeOfModuleUsingOpt(PVOID pBaseAddress){
    if(pBaseAddress == NULL){
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBaseAddress;
    if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        return 0;
    }

    PIMAGE_NT_HEADERS64 pNthdr = (PIMAGE_NT_HEADERS64)((PBYTE)pBaseAddress + pDosHdr->e_lfanew);
    if(pNthdr->Signature != IMAGE_NT_SIGNATURE){
        return 0;
    }

    SIZE_T sNtdllTxtSize = pNthdr->OptionalHeader.SizeOfCode;

    return sNtdllTxtSize;
}

/**
 * Getting sizeof ntdll using IMAGE_SECTION_HEADER.
 * @param => base address of module.
 */
SIZE_T GetSizeOfModuleUsingImg(PVOID pBaseAddress){
    SIZE_T sNtdllTxtSize = 0;

    if(pBaseAddress == NULL){
        return 0;
    }

    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBaseAddress;
    if(pDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        return 0;
    }

    PIMAGE_NT_HEADERS64 pNthdr = (PIMAGE_NT_HEADERS64)((PBYTE)pBaseAddress + pDosHdr->e_lfanew);
    if(pNthdr->Signature != IMAGE_NT_SIGNATURE){
        return 0;
    }

    PIMAGE_SECTION_HEADER pSectionHdr = (PIMAGE_SECTION_HEADER)pNthdr;

    for(int i = 0; i < pNthdr->FileHeader.NumberOfSections; i++){
        if ((*(ULONG*)pSectionHdr[i].Name | 0x20202020) == 'xet.') {
            sNtdllTxtSize	= pSectionHdr[i].Misc.VirtualSize;
            break;
        }
    }

    return sNtdllTxtSize;
}

/**
 * Get ntdll from disk.
 * @param => pNtdllBuf => ptr to ntdll.
 */
BOOL ReadNtdllFromDisk(OUT PVOID* pNtdllBuff){
    CHAR cWinPath   [MAX_PATH / 2] = {0};
    CHAR cNtdllPath [MAX_PATH]     = {0};

    HANDLE hFile               = NULL;
    DWORD  dwNumberofBytesRead = 0;
    DWORD  dwFileLen           = 0;
    PVOID  pNtdllBuffer        = NULL;

    //Get path of windows dir
    if(GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0){
        printf("[!] Unable to get path to Win dir using GetWindowsDirectoryA with error : %d\n", GetLastError());
        goto _EndFunc;
    }

    sprintf(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

    //Getting handle to Ntdll
    hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == NULL){
        printf("[!] Error using CreateFileA function with error %d\n", GetLastError());
        goto _EndFunc;
    }

    //Reading Ntdll
    dwFileLen  = GetFileSize(hFile, NULL);
    pNtdllBuff = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);

    //Reading file.
    if(!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberofBytesRead, NULL) || dwFileLen != dwNumberofBytesRead){
        printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Read %d of %d Bytes \n", dwNumberofBytesRead, dwFileLen);
		goto _EndFunc;
    } 

    *pNtdllBuff = pNtdllBuffer;

_EndFunc:
    if(hFile){
        CloseHandle(hFile);
    }

    return !(*pNtdllBuff == NULL);
}

/**
 * Get ntdll from disk => using MapViewOfFile => (copied from learning path.)
 * @param => pNtdllBuf => ptr to ntdll.
 * 
 * Notes : Sometimes when the ntdll.dll file is read from disk rather than mapped to memory, the offset of its text section might be 4096 instead of the expected 1024. Mapping the ntdll.dll file to memory is more reliable since the text section offset will always equal the IMAGE_SECTION_HEADER.VirtualAddress offset of the DLL file.
 */
BOOL MapNtdllFromDisk(OUT PVOID* ppNtdllBuf) {
	HANDLE  hFile                           = NULL;
	HANDLE	hSection                        = NULL;
	CHAR    cWinPath    [MAX_PATH / 2]      = { 0 };
	CHAR    cNtdllPath  [MAX_PATH]          = { 0 };
	PBYTE   pNtdllBuffer                    = NULL;

	if (GetWindowsDirectoryA(cWinPath, sizeof(cWinPath)) == 0) {
		printf("[!] GetWindowsDirectoryA Failed With Error : %d \n", GetLastError());
		goto _EndFunc;
	}

	sprintf_s(cNtdllPath, sizeof(cNtdllPath), "%s\\System32\\%s", cWinPath, NTDLL);

	hFile = CreateFileA(cNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		goto _EndFunc;
	}

	// creating a mapping view of the ntdll.dll file using the 'SEC_IMAGE_NO_EXECUTE' flag
	hSection = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, NULL, NULL, NULL);
	if (hSection == NULL) {
		printf("[!] CreateFileMappingA Failed With Error : %d \n", GetLastError());
		goto _EndFunc;
	}

	// mapping the view of file of ntdll.dll
	pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndFunc;
	}

	*ppNtdllBuf = pNtdllBuffer;

_EndFunc:
	if (hFile){
        CloseHandle(hFile);
    }
	if (hSection){
        CloseHandle(hSection);
    }
	
    return !(*ppNtdllBuf == NULL);
}

// Mapped
// PVOID pUnhookedTxtNtdll = (ULONG_PTR)(MapNtdllFromDisk output) + (4096 or IMAGE_SECTION_HEADER.VirtualAddress of ntdll.dll);

// Read
// PVOID pUnhookedTxtNtdll = (ULONG_PTR)(ReadNtdllFromDisk output) + 1024;
//-----------------------------------------------------------------------------------------------------------------------------

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
	PVOID pLocalNtdll = (PVOID)GetLocalNtdllAddress();

    if(pLocalNtdll == NULL){
        return FALSE;
    }

	//Getting the dos header
	PIMAGE_DOS_HEADER pLocalDosHdr	= (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        return FALSE;
    }
	
	// Getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs	= (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }


	PVOID		pLocalNtdllTxt	 = NULL,	// local hooked text section base address
			    pRemoteNtdllTxt  = NULL;    // the unhooked text section base address

	SIZE_T		sNtdllTxtSize	 = NULL;    // the size of the text section


	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);
	
	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {
		
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {

			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);

            pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress); //  => using MAP.

            // pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + 1024); => using READ

			sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize){
        return FALSE;
    }

	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	
	// rrestoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

//From Maldev.
VOID PrintState(char* cSyscallName, PVOID pSyscallAddress) {
	printf("[#] %s [ 0x%p ] ---> %s \n", cSyscallName, pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");
}

//Check => NOTES (i'm using Mapping technique => better.)
int main(){
    PVOID	pNtdll		= NULL;

    printf("[i] Fetching A New \"ntdll.dll\" File By Mapping \n");
	if (!MapNtdllFromDisk(&pNtdll)){
        return EXIT_FAILURE;
    }

    PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

    UnmapViewOfFile(pNtdll);

    printf("[+] Ntdll Unhooked Successfully \n");

	// check if NtProtectVirtualMemory is unhooked
	PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return EXIT_SUCCESS;
}