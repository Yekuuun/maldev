#pragma once

#include <stdio.h>
#include <windows.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

BYTE xor_key = 0xAA;

// base input key for XOR demo
unsigned char xor_input_key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05
};

unsigned char text_shellcode[] = {
    "WTFFFF IS THIS ?"
};

// x64 calc metasploit shellcode {272 bytes}
unsigned char raw_payload_data[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
};

unsigned char rc4_key[] = { 
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
