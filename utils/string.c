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

/**
 * Contains a string.
 */
BOOL StringContains(wchar_t* haystack, wchar_t* needle){
    while(*haystack && (*haystack == *needle)){
        haystack++;
        needle++;
    }

    return (*haystack == *needle);
}

/**
 * Compare 2 given LCSTR strings (use other types if you want)
 */
BOOL CompareStringsA(LPCSTR str1, LPCSTR str2){
    if(str1 == NULL || str2 == NULL)
    {
        return FALSE;
    }

    if(CustomStrLenA(str1) != CustomStrLenA(str2))
    {
        return FALSE;
    }

    while(*str1 != '\0' && *str2 != '\0')
    {
        if(*str1 != *str2)
        {
            return FALSE;
        }
        str2++;
        str1++;
    }
    return TRUE;
}