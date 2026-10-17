#include <windows.h>
#include <stdio.h>
typedef int (__cdecl *CODE)(char*,unsigned int);
typedef int (__cdecl *VERIFY)(void);
int main(void) {
    HMODULE module=LoadLibraryW(L"SAI2RuLicense.dll");
    if (!module) { printf("LOAD_ERROR=%lu\n",GetLastError()); return 2; }
    CODE code=(CODE)GetProcAddress(module,"GetDeviceCode");
    VERIFY verify=(VERIFY)GetProcAddress(module,"VerifyLicense");
    char text[65]={0};
    if (!code || !verify || !code(text,sizeof(text))) { printf("CODE_ERROR=%lu\n",GetLastError()); return 3; }
    printf("DEVICE=%s\nVALID=%d\n",text,verify());return 0;
}
