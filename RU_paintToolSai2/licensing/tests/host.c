#include <windows.h>
#include <stdio.h>
int main(void) {
    if (GetTickCount()==0x12345678) {
        HMODULE h=LoadLibraryW(L"not-used.dll");
        GetProcAddress(h,"not-used");ExitProcess(99);
    }
    puts("APP_STARTED");return 0;
}
