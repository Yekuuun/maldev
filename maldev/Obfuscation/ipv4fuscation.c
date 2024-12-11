/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * This file contains base implementation of IP obfuscation base technique => ipv4
 */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

/**
 * Generate IPv4 format address.
 */
static char* GenerateIpv4(int a, int b, int c, int d) {
    static char Output[32];

    snprintf(Output, sizeof(Output), "%d.%d.%d.%d", a, b, c, d);
    return Output;
}

/**
 * Generate the ipv4 shellcode obfuscation format.
 */
BOOL GenerateIpv4Obfuscation(unsigned char *pShellcode, SIZE_T sShellcodeSize) {
    if(pShellcode == NULL || sShellcodeSize == 0 || sShellcodeSize % 4 != 0) {
        return FALSE;
    }

    printf("unsigned char obfuscatedIP[] = {\n\t");

    for(size_t i = 0; i < sShellcodeSize; i += 4) {
        char* IP = GenerateIpv4(
            pShellcode[i], 
            pShellcode[i + 1], 
            pShellcode[i + 2], 
            pShellcode[i + 3]
        );

        if (i == sShellcodeSize - 4) {
            printf("\"%s\"", IP);
        } else {
            printf("\"%s\", ", IP);
        }

        // Saut de ligne tous les 4 paquets pour la lisibilité
        if ((i + 4) % 16 == 0) {
            printf("\n\t");
        }
    }

    printf("\n};\n\n");
    return TRUE;
}

// x64 calc metasploit shellcode {272 bytes}
unsigned char rawData[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
};

int main() {
    if (!GenerateIpv4Obfuscation(rawData, sizeof(rawData))) {
        fprintf(stderr, "Erreur : Taille du shellcode invalide\n");
        return -1;
    }

    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}