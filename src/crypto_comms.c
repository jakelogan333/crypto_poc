#include <crypto_comms.h>
#include <debug.h>

NTSTATUS CryptoDecrypt(
    BCRYPT_KEY_HANDLE hKey,
    PBYTE pCipherText,
    DWORD dwCipherSize,
    PVOID pPadding,
    PBYTE pIV,
    DWORD dwIVSize,
    DWORD dwFlags,
    PCRYPTO_DATA *pCryptoData
)
{
    NTSTATUS ntRetVal = STATUS_UNSUCCESSFUL;
    DWORD dwSizeNeeded = 0;

    *pCryptoData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CRYPTO_DATA));

    if (NULL == *pCryptoData)
    {
        goto end;
    }

    // Call BCryptDecrypt the first time to get the size of the plaintext buffer needed
    ntRetVal = BCryptDecrypt(
        hKey,
        pCipherText,
        dwCipherSize,
        pPadding,
        pIV,
        dwIVSize,
        NULL,
        0,
        &dwSizeNeeded,
        dwFlags
    );
    
    DBG_PRINT(L"Decrypt size: %u\n", ntRetVal);

    if (STATUS_SUCCESS != ntRetVal)
    {
        goto end;
    }

    DBG_PRINT(L"Size needed to decrypt: %d\n", dwSizeNeeded);

    (*pCryptoData)->pData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == (*pCryptoData)->pData)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    // Perform the actual decryption
    ntRetVal = BCryptDecrypt(
        hKey,
        pCipherText,
        dwCipherSize,
        pPadding,
        pIV,
        dwIVSize,
        (*pCryptoData)->pData,
        dwSizeNeeded,
        &((*pCryptoData)->dwDataSize),
        dwFlags
    );

    DBG_PRINT(L"Decrypt Error: %u:%d\n", ntRetVal, (*pCryptoData)->dwDataSize);

    if (STATUS_SUCCESS != ntRetVal)
    {
        goto end;
    }

end:
    if (STATUS_SUCCESS != ntRetVal)
    {
        if (NULL != (*pCryptoData)->pData)
        {
            HeapFree(GetProcessHeap(), 0, (*pCryptoData)->pData);
        }

        if (NULL != pCryptoData)
        {
            HeapFree(GetProcessHeap(), 0, (*pCryptoData));
        }
    }

    return ntRetVal;

}

NTSTATUS CryptoEncrypt(
    BCRYPT_KEY_HANDLE hKey,
    PBYTE pPlainText,
    DWORD dwPlainTextSize,
    PVOID pPadding,
    PBYTE pIV,
    DWORD dwIVSize,
    DWORD dwFlags,
    PCRYPTO_DATA *pCryptoData
)
{
    NTSTATUS ntRetVal = STATUS_UNSUCCESSFUL;
    DWORD dwSizeNeeded = 0;
    
    *pCryptoData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CRYPTO_DATA));

    if (NULL == *pCryptoData)
    {
        goto end;
    }

    // Get the size of buffer required
    ntRetVal = BCryptEncrypt(
        hKey,
        pPlainText,
        dwPlainTextSize,
        pPadding,
        pIV,
        dwIVSize,
        NULL,
        0,
        &dwSizeNeeded,
        dwFlags
    );

    DBG_PRINT(L"Size needed to decrypt: %d\n", dwSizeNeeded);

    (*pCryptoData)->pData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == (*pCryptoData)->pData)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptEncrypt(
        hKey,
        pPlainText,
        dwPlainTextSize,
        pPadding,
        pIV,
        dwIVSize,
        (*pCryptoData)->pData,
        dwSizeNeeded,
        &((*pCryptoData)->dwDataSize),
        dwFlags
    );

end:
    if (STATUS_SUCCESS != ntRetVal)
    {
        if (NULL != (*pCryptoData)->pData)
        {
            HeapFree(GetProcessHeap(), 0, (*pCryptoData)->pData);
        }

        if (NULL != pCryptoData)
        {
            HeapFree(GetProcessHeap(), 0, (*pCryptoData));
        }
    }

    return ntRetVal;

}

VOID CryptoPrintBytes(DWORD dwSize, LPWSTR pTitle, PBYTE pBytes)
{
    wprintf(pTitle);
    for(int i = 0; i < dwSize; i++)
    {
        wprintf(L"%02hhx", pBytes[i]);
    }
    wprintf(L"\n");
}


DWORD CryptoInitiateKeyExchange(SOCKET conn)
{
    DWORD dwRetVal = CRYPTO_FAILURE;

end:
    return dwRetVal;
}

DWORD CryptoValidateKeyExchange(SOCKET conn)
{
    DWORD dwRetVal = CRYPTO_FAILURE;

end:
    return dwRetVal;
}