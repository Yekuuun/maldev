#include <stdio.h>
#include <windows.h>

/**
 * @returns length of a LPCSTR string
 */
SIZE_T CustomStrLenA(LPCSTR str){
    LPCSTR ptrStr = str;
    while(*str != '\0')
    {
        str++;
    }
    return str - ptrStr;
}