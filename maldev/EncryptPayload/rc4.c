/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : base payload encryption using RC4
 */

#include "utils.h"

typedef struct {
    unsigned int i;
    unsigned int j;
    unsigned char s[256];
} Rc4;


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
 * Initialization
 */
static BOOL Rc4Initialize(Rc4 *context, const unsigned char *key, SIZE_T skeySize){
    if(context == NULL){
        return FALSE;
    }

    unsigned int i;
    unsigned int j = 0;
    unsigned char temp;

    context->i = 0;
    context->j = 0;

    // Initialize s => 0 - 255
    for(i = 0; i < 256; i++){
        context->s[i] = i;
    }

    // Key scheduling algorithm (KSA)
    for(i = 0; i < 256; i++){
        j = (j + context->s[i] + key[i % skeySize]) % 256;
        temp = context->s[i];
        context->s[i] = context->s[j];
        context->s[j] = temp;
    }

    return TRUE;
}

/**
 * Encryption/Decryption using RC4
 */
static BOOL Rc4Generate(Rc4 *context, unsigned char *input, unsigned char *output, SIZE_T len){
    if(context == NULL || input == NULL || output == NULL){
        return FALSE;
    }
    
    unsigned char temp;
    unsigned int i = context->i;
    unsigned int j = context->j;
    unsigned char *s = context->s;

    while(len > 0){
        i = (i + 1) % 256;
        j = (j + context->s[i]) % 256;

        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        *output = *input ^ s[(s[i] + s[j]) % 256];

        input++;
        output++;
        len--;
    }

    context->i = i;
    context->j = j;

    return TRUE;
}

//test
int main(){
    Rc4 context                = {0};
    unsigned char *cipher_text = NULL;
    unsigned char *plain_text  = NULL;

    // Encrypt
    if(!Rc4Initialize(&context, rc4_key, sizeof(rc4_key))){
        printf("[!] Error initializing Rc4 context\n"); goto _EndFunc;
    }

    cipher_text = (unsigned char*)malloc(sizeof(raw_payload_data));
    if(cipher_text == NULL){
        printf("[!] Unable to allocate memory\n"); goto _EndFunc;
    }

    memset(cipher_text, 0, sizeof(raw_payload_data));

    if(!Rc4Generate(&context, raw_payload_data, cipher_text, sizeof(raw_payload_data))){
        printf("[!] Error ciphering text\n"); goto _EndFunc;
    }

    PrintHexData("Encrypted", cipher_text, sizeof(raw_payload_data));

    printf("[#] Press <Enter> To Decrypt...");
    getchar();

    // Re-initialize context before decryption
    if(!Rc4Initialize(&context, rc4_key, sizeof(rc4_key))){
        printf("[!] Error reinitializing Rc4 context\n");
        free(cipher_text);
        return EXIT_FAILURE;
    }

    // Decrypt
    plain_text = (unsigned char*)malloc(sizeof(raw_payload_data));
    if(plain_text == NULL){
        printf("[!] Unable to allocate memory\n"); goto _EndFunc;
    }

    memset(plain_text, 0, sizeof(raw_payload_data));

    if(!Rc4Generate(&context, cipher_text, plain_text, sizeof(raw_payload_data))){
        printf("[!] Error unciphering text\n");
        return EXIT_FAILURE;
    }
    
    PrintHexData("Encrypted", plain_text, sizeof(raw_payload_data));

    printf("[#] Press <Enter> To Quit ...");
    getchar();

_EndFunc:
    if(cipher_text != NULL){
        free(cipher_text);
    }
    if(plain_text != NULL){
        free(plain_text);
    }

    return EXIT_SUCCESS;
}
