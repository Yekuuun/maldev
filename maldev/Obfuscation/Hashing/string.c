/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : contains base implementation of string hashing techniques for obfuscation.
 * 
 * Notes : contains 2 base technique for learning purpose => wants to know more ? => go to https://maldevacademy.com
 */

#include <stdio.h>
#include <windows.h>

#define INITIAL_HASH 3731
#define INITIAL_SEED 7

/**
 * Base Djb2 technique => hashing from ASCII input string
 */
DWORD HashString2Djb2a(IN PCHAR pString){
    ULONG Hash = INITIAL_HASH;
    INT c;

    while(c = *pString++){
        Hash = ((Hash << INITIAL_SEED) + Hash) + c;
    }

    return Hash;
}

/**
 * Base Djb2 technique => hashing from wide input string
 */
DWORD HashStringDjb2W(_In_ PWCHAR pString)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *pString++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

/**
 * Base JenkinsOneAtATime32Bit  technique => hashing from wide input string
 */
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index  = 0;
	UINT32 Hash   = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

/**
 * Base JenkinsOneAtATime32Bit  technique => hashing from wide input string
 */
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index  = 0;
	UINT32 Hash   = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

//test.
int main(){
    char myString[] = "Hello, world!";

    char statckString[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\0' }; //interesting.

    DWORD hash = HashString2Djb2a(myString);
    printf("The HASHED string value is: 0x%lu\n", hash);

    return EXIT_SUCCESS;
}

