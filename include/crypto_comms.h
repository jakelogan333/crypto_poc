#ifndef CRYPTO_COMMS_H
#define CRYPTO_COMMS_H

#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <bcrypt.h>
#include <ntstatus.h>
#include <WinSock2.h>

#define RAND_BYTES_SIZE 128
#define SECRET_SIZE 16
#define VERIFICATION_SIZE 48
#define RSA_KEY_SIZE 2048
#define CIPHERTEXT_SIZE RSA_KEY_SIZE / 8

typedef struct crypto_data
{
    PBYTE pData;
    DWORD dwDataSize;
} CRYPTO_DATA, *PCRYPTO_DATA;

typedef struct crypto_comms
{
    LPWSTR pAddress;
    WORD wPort;
    SOCKET sock;
} CRYPTO_COMMS, *PCRYPTO_COMMS;

enum CRYPTO_ERRORS
{
    CRYPTO_SUCCESS,
    CRYPTO_FAILURE,
    CRYPTO_SOCKET_ERROR
};

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

DWORD CryptoInitiateKeyExchange(PCRYPTO_COMMS pConnInfo, BCRYPT_KEY_HANDLE hPublicKey);
DWORD CryptoValidateKeyExchange(PCRYPTO_COMMS pConnInfo, BCRYPT_KEY_HANDLE hPrivateKey);
DWORD CryptoGenerateSymmetricKey(LPCWSTR pAlgorithm, LPCWSTR pImplementation, BCRYPT_KEY_HANDLE *hSymmetricKey, PCRYPTO_DATA *data);
BOOL CryptoCompareBytes(PBYTE pOriginal, DWORD dwOrigSize, PBYTE pCompare, DWORD dwCompareSize);
DWORD CryptoImportKeyFromBlob(LPCWSTR pAlgorithm, LPCWSTR pImplementation, BCRYPT_KEY_HANDLE *hKey, PCRYPTO_DATA pKey);

#endif