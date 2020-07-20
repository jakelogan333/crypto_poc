#ifndef CRYPTO_COMMS_H
#define CRYPTO_COMMS_H

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#include <ntstatus.h>

typedef struct crypto_data
{
    PBYTE pData;
    DWORD dwDataSize;
} CRYPTO_DATA, *PCRYPTO_DATA;

NTSTATUS CryptoDecrypt(
    BCRYPT_KEY_HANDLE hKey,
    PBYTE pCipherText,
    DWORD dwCipherSize,
    PVOID pPadding,
    PBYTE pIV,
    DWORD dwIVSize,
    DWORD dwFlags,
    PCRYPTO_DATA *pData
);

NTSTATUS CryptoEncrypt(
    BCRYPT_KEY_HANDLE hKey,
    PBYTE pPlainText,
    DWORD dwPlainTextSize,
    PVOID pPadding,
    PBYTE pIV,
    DWORD dwIVSize,
    DWORD dwFlags,
    PCRYPTO_DATA *data
);

#endif