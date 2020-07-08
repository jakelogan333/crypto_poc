#pragma comment(lib, "bcrypt.lib")
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#include <wchar.h>
#include <ntstatus.h>

INT wmain(INT argc, WCHAR *argv[])
{
    DWORD dwRetVal = EXIT_SUCCESS;
    NTSTATUS ntRetVal = EXIT_SUCCESS;
    BCRYPT_ALG_HANDLE hProvider = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pPublicKey = NULL;
    PBYTE pPrivateKey = NULL;
    HANDLE hPublicKeyOut, hPrivateKeyOut = INVALID_HANDLE_VALUE;

    ntRetVal = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RSA_ALGORITHM, NULL, 0);
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error opening algo\n");
        goto end;
    }

    ntRetVal = BCryptGenerateKeyPair(hProvider, &hKey, 2048, 0);
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error generating keypair\n");
        goto end;
    }

    BCryptFinalizeKeyPair(hKey, 0);

    DWORD dwSize = 0;
    DWORD dwPublicOutSize = 0;
    DWORD dwPrivateOutSize = 0;
    ntRetVal = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &dwSize, 0);

    if (STATUS_SUCCESS != ntRetVal && STATUS_BUFFER_TOO_SMALL != ntRetVal)
    {
        wprintf(L"Error getting public key size %u\n", ntRetVal);
        goto end;
    }

    pPublicKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);

    ntRetVal = BCryptExportKey(hKey, NULL, BCRYPT_RSAPUBLIC_BLOB, pPublicKey, dwSize, &dwPublicOutSize, 0);

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error exporting public key\n");
        goto end;
    }

    ntRetVal = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, 0, &dwSize, 0);

    if (STATUS_SUCCESS != ntRetVal && STATUS_BUFFER_TOO_SMALL != ntRetVal)
    {
        wprintf(L"Error getting private key size\n");
        goto end;
    }

    pPrivateKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);

    ntRetVal = BCryptExportKey(hKey, NULL, BCRYPT_RSAPRIVATE_BLOB, pPrivateKey, dwSize, &dwPrivateOutSize, 0);

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error exporting private key\n");
        goto end;
    }

    DWORD dwBytesWritten = 0;

    hPublicKeyOut = CreateFileW(
        L"public.key",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0
        );

    WriteFile(hPublicKeyOut, pPublicKey, dwPublicOutSize, &dwBytesWritten, NULL);

    hPrivateKeyOut = CreateFileW(
        L"private.key",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0
        );

    WriteFile(hPrivateKeyOut, pPrivateKey, dwPrivateOutSize, &dwBytesWritten, NULL);

end:
if (INVALID_HANDLE_VALUE != hPublicKeyOut)
{
    CloseHandle(hPublicKeyOut);
}

if (INVALID_HANDLE_VALUE != hPrivateKeyOut)
{
    CloseHandle(hPrivateKeyOut);
}

return dwRetVal;

}