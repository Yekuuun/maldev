/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Implements base payload encryption using XOR.
 */
#include "utils.h"

/**
 * Encrypt in XOR using one base key (recommend using input_keys like method)
 */
static VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE key){
    for(size_t i = 0; i < sShellcodeSize; i++){
        pShellcode[i] = pShellcode[i] ^ key;
    }
}

/**
 * XOR using input keys.
 */
static VOID XorByInputKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE pKey, IN SIZE_T sKeySize){
    for(size_t i = 0, j = 0; i < sShellcodeSize; i++, j++){
        if(j > sKeySize){
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ pKey[j];
    }
}

//test.
int main(){
    printf("[*] shellcode addr : 0x%p \n", text_shellcode);

    XorByInputKeys(text_shellcode, sizeof(text_shellcode), xor_input_key, sizeof(xor_input_key));

    printf("[*] shellcode : \"%s\" \n", (char*)text_shellcode);
    printf("[#] Press <ENTER> to decrypt...\n");
    getchar();

    XorByInputKeys(text_shellcode, sizeof(text_shellcode), xor_input_key, sizeof(xor_input_key));
    printf("[*] shellcode : \"%s\" \n", (char*)text_shellcode);

    return EXIT_SUCCESS;
}