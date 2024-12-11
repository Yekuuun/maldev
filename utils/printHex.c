/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 */

#include <stdio.h>
#include <windows.h>

// x64 calc metasploit shellcode {272 bytes}
unsigned char raw_payload_data[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
};

/**
 * Base print hex data.
 */
static void print_hex_data(const char *str, unsigned char *data, size_t size){
    printf("unsigned char %s[]{", str);

    for(int i = 0; i < size; i++){
        if(i % 16 == 0){
            printf("\n\t");
        }

        if (i < size - 1) {
            printf("0x%0.2X, ", data[i]);
        }
    	else {
      	    printf("0x%0.2X ", data[i]);
        }
    }

    printf("\n};\n");
}

/**
 * Print hex data using WIN types.
 */
static VOID PrintHexData(LPCSTR str, PBYTE payload, SIZE_T sPayload){
    printf("unsigned char %s[]{", str);

    for(int i = 0; i < sPayload; i++){
        if(i % 16 == 0){
            printf("\n\t");
        }

        if(i < sPayload - 1){
            printf("0x%02X, ", payload[i]);
        }
        else{
            printf("0x%02X ", payload[i]);
        }
    }
}

//test.
int main(){
    print_hex_data("metasploit_payload", raw_payload_data, sizeof(raw_payload_data));
    print_hex_data("metasploit_payload_win_types", raw_payload_data, sizeof(raw_payload_data));
    return 0;
}