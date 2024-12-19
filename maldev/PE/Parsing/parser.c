/**
 * Author : Yekuuun
 * Github : https://github.com/yekuuun
 * 
 * Notes : base PE informations parsing for PE manipulation.
 */

#include <stdio.h>
#include <windows.h>

/**
 * Read PE file from path.
 * 
 * @param lpPath => path to PE file.
 * @param pRawPe => ptr to PE base address.
 * @param sPe => sizeof loeader PE file.
 */
BOOL ReadPeFile(IN LPCSTR lpPath, OUT PBYTE* pRawPe, OUT SIZE_T* sPe){
    BOOL   STATE               = TRUE;
    HANDLE hFile               = NULL;
    DWORD  dwFileSize          = 0;
    DWORD  dwNumberOfBytesRead = 0;
    PBYTE  pBuff               = NULL;

    hFile = CreateFileA(lpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == NULL){
        printf("[!] Error calling CreateFileA() with error %d\n", GetLastError());
        return FALSE;
    }

    dwFileSize = GetFileSize(hFile, NULL);
    if(dwFileSize == INVALID_FILE_SIZE){
        printf("[!] Error calling GetFileSize() with error : %d \n", GetLastError());
        STATE = FALSE; goto _EndFunc;
    }

    pBuff = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
    if(pBuff == NULL){
        printf("[!] Error calling HeapAlloc() with error : %d\n", GetLastError());
        STATE = FALSE; goto _EndFunc;
    }

    if (!ReadFile(hFile, pBuff, dwFileSize, &dwNumberOfBytesRead, NULL) || dwFileSize != dwNumberOfBytesRead) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read : %d of : %d \n", dwNumberOfBytesRead, dwFileSize);
		STATE = FALSE; goto _EndFunc;
	}

_EndFunc:
    *pRawPe = (PBYTE)pBuff;
    *sPe = (SIZE_T)dwFileSize;

    if(hFile){
        CloseHandle(hFile);
    }
    STATE = (*pRawPe != NULL && *sPe != NULL);
    return STATE;
}

/**
 * Show PE informations.
 * 
 * @param pRawPe => BaseAddress of PE file.
 */
VOID ParseInformations(IN PBYTE pRawPe){
    if(pRawPe == NULL){
        return;
    }

    //display infos.
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pRawPe;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE){
		return;
	}

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pRawPe + pDos->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}


	// 
	printf("\n#####################[ FILE HEADER ]#####################\n\n");
    printf("[*] File Arch : %s \n", pImgNtHdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");

    printf(".....\n");
    
    // using address & ptr arithmethic to explore PE FILE
    // go visit /GetFuncAddress to have more informations.
    // ;)
}

//test.
int main(int argc, char *argv[]){
    if(argc != 2){
        printf("[!] Must pass one argument => <path_to_pe_file>\n");
        return EXIT_FAILURE;
    }

    LPCSTR lpPath = argv[1];

    //data.
    PBYTE  pRawPe = NULL;
    SIZE_T sPe    = 0;

    //reading file
    if(!ReadPeFile(lpPath, &pRawPe, &sPe)){
        return EXIT_FAILURE;
    }

    ParseInformations(pRawPe);

    printf("[*] END => Presse <ENTER> to Quit.... \n");
    getchar();

    HeapFree(GetProcessHeap(), NULL, pRawPe);
    return EXIT_SUCCESS;
}