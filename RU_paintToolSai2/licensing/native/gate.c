#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define PAYLOAD_SIZE 184
#define LICENSE_SIZE 440
/* Replaced with the owner's public key when building a distribution. */
__declspec(dllexport) volatile struct {
    BYTE marker[16]; BYTE public_blob[276];
} SaiRuPublicKey = {"SAIRU-PUBKEY-V1!", {0}};

static BOOL device_hash(BYTE digest[32]) {
    HKEY key = NULL;
    WCHAR guid[80] = {0}; DWORD size = sizeof(guid), type = 0;
    LONG status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0,
                               KEY_READ | KEY_WOW64_64KEY, &key);
    if (status != ERROR_SUCCESS) return FALSE;
    status = RegQueryValueExW(key, L"MachineGuid", NULL, &type, (BYTE*)guid, &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_SZ || size > sizeof(guid)) return FALSE;
    guid[79] = 0;
    if (wcslen(guid) != 36) return FALSE;
    BYTE normalized[36];
    for (int i=0; i<36; ++i) {
        WCHAR ch = guid[i];
        if (i==8 || i==13 || i==18 || i==23) { if (ch != L'-') return FALSE; }
        else if (!((ch>=L'0' && ch<=L'9') || (ch>=L'a' && ch<=L'f') || (ch>=L'A' && ch<=L'F'))) return FALSE;
        normalized[i] = (BYTE)((ch>=L'A' && ch<=L'F') ? ch+32 : ch);
    }
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0; BOOL ok = FALSE;
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto done;
    if (!CryptHashData(hash, normalized, sizeof(normalized), 0)) goto done;
    size = 32; ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &size, 0) && size==32;
done:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    return ok;
}

static BOOL program_path(WCHAR *path, const WCHAR *name) {
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return FALSE;
    WCHAR *slash = wcsrchr(path, L'\\');
    if (!slash || (size_t)(slash-path)+1+wcslen(name) >= MAX_PATH) return FALSE;
    wcscpy(slash+1, name); return TRUE;
}

__declspec(dllexport) int __cdecl GetDeviceCode(char *output, unsigned int capacity) {
    BYTE hash[32]; static const char digits[] = "0123456789abcdef";
    if (capacity < 65 || !device_hash(hash)) return 0;
    for (int i=0; i<32; ++i) { output[i*2]=digits[hash[i]>>4]; output[i*2+1]=digits[hash[i]&15]; }
    output[64]=0; return 1;
}

/* No dialogs: also usable by the regression test harness. */
__declspec(dllexport) int __cdecl VerifyLicense(void) {
    WCHAR path[MAX_PATH]; BYTE data[LICENSE_SIZE], machine[32], public_blob[276], signature[256];
    DWORD read = 0; HANDLE file = INVALID_HANDLE_VALUE;
    HCRYPTPROV provider = 0; HCRYPTKEY key = 0; HCRYPTHASH hash = 0; BOOL ok = FALSE;
    if (!program_path(path, L"translation.lic") || !device_hash(machine)) return 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER length;
    if (!GetFileSizeEx(file, &length) || length.QuadPart != LICENSE_SIZE) goto done;
    if (!ReadFile(file, data, LICENSE_SIZE, &read, NULL) || read != LICENSE_SIZE) goto done;
    if (memcmp(data, "SAIRUL01", 8) || memcmp(data+8, machine, 32)) goto done;
    if (data[183] != 0) goto done;
    for (int i=0; i<276; ++i) public_blob[i]=SaiRuPublicKey.public_blob[i];
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) goto done;
    if (!CryptImportKey(provider, public_blob, sizeof(public_blob), 0, 0, &key)) goto done;
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto done;
    if (!CryptHashData(hash, data, PAYLOAD_SIZE, 0)) goto done;
    /* CryptoAPI signatures are little-endian, unlike standard RSA encodings. */
    for (int i=0; i<256; ++i) signature[i]=data[PAYLOAD_SIZE+255-i];
    ok = CryptVerifySignatureW(hash, signature, sizeof(signature), key, NULL, 0);
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash) CryptDestroyHash(hash);
    if (key) CryptDestroyKey(key);
    if (provider) CryptReleaseContext(provider, 0);
    return ok ? 1 : 0;
}

__declspec(dllexport) int __cdecl CheckLicense(void) {
    if (VerifyLicense()) return 1;
    char code[65] = {0}; WCHAR wide[65] = {0}, message[1200], request[MAX_PATH];
    if (!GetDeviceCode(code, sizeof(code))) {
        MessageBoxW(NULL, L"Не удалось получить код установки Windows. Обратитесь к владельцу перевода.",
                    L"Лицензия русского перевода", MB_OK | MB_ICONERROR); return 0;
    }
    MultiByteToWideChar(CP_UTF8, 0, code, -1, wide, 65);
    if (program_path(request, L"request-license.txt")) {
        HANDLE file=CreateFileW(request, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file != INVALID_HANDLE_VALUE) {
            char text[180]; DWORD written;
            int length=snprintf(text, sizeof(text), "SAI2 Russian translation license request\r\nDevice: %s\r\n", code);
            WriteFile(file, text, (DWORD)length, &written, NULL); CloseHandle(file);
        }
    }
    swprintf(message, 1200,
        L"Для русского перевода нужна лицензия на этот компьютер.\n\nКод устройства:\n%ls\n\n"
        L"Передайте код владельцу перевода. Полученный translation.lic положите рядом с sai2.exe.\n\n"
        L"Код также записывается в request-license.txt, если папка доступна для записи.\n"
        L"Это окно можно скопировать сочетанием Ctrl+C.", wide);
    MessageBoxW(NULL, message, L"Активация русского перевода", MB_OK | MB_ICONINFORMATION);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved; return TRUE;
}
