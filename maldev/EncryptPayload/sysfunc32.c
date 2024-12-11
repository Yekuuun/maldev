/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Base Rc4 encryption using System Function 032
 */

#include "utils.h"

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

// SystemFunction032 def
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Data,
    struct USTRING* Key
);

/**
 * Printing HEX data.
 */
static VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
  printf("unsigned char %s[] = {", Name);

  for (int i = 0; i < Size; i++) {
    	if (i % 16 == 0)
      	    printf("\n\t");
	    
    	if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
    	else {
      	    printf("0x%0.2X ", Data[i]);
        }
  }

  printf("\n};\n\n\n");
}

/**
 * Main function.
 */
static BOOL Rc4ViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayload, IN DWORD sRc4KeySize, IN DWORD sPayloadSize){
    NTSTATUS STATUS = NULL;

    USTRING Data = {
        .Buffer = pPayload,
        .Length = sPayloadSize,
        .MaximumLength = sPayloadSize
    };

    USTRING Key = {
        .Buffer = pRc4Key,
        .Length = sRc4KeySize,
        .MaximumLength = sRc4KeySize
    };

    fnSystemFunction032 ptrSystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    if(ptrSystemFunction032 == NULL){
        printf("[!] Unable to get ptr to SystemFunction032 \n");
        return FALSE;
    }

    STATUS = ptrSystemFunction032(&Data, &Key);
    if(STATUS != STATUS_SUCCESS){
        printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
    }

    return TRUE;
}

//test
int main(){
    printf("[*] shellcode address : 0x%p \n", raw_payload_data);

    //Encryption
    if(!Rc4ViaSystemFunc032(rc4_key, raw_payload_data, sizeof(rc4_key), sizeof(raw_payload_data))){
        printf("[!] Unable to cipher payload. \n");
        return EXIT_FAILURE;
    }

    PrintHexData("Encrypted", raw_payload_data, sizeof(raw_payload_data));

    printf("[#] Press <Enter> To Decrypt ...");
	getchar();

    //Decryption
    if(!Rc4ViaSystemFunc032(rc4_key, raw_payload_data, sizeof(rc4_key), sizeof(raw_payload_data))){
        printf("[!] Unable to cipher payload. \n");
        return EXIT_FAILURE;
    }

    PrintHexData("Decrypted", raw_payload_data, sizeof(raw_payload_data));

    // Exit
	printf("[#] Press <Enter> To Quit ...");
	getchar();

    return EXIT_SUCCESS;
}