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


DWORD CryptoInitiateKeyExchange(PCRYPTO_COMMS pConnInfo, BCRYPT_KEY_HANDLE hPublicKey)
{
    DWORD dwRetVal = CRYPTO_FAILURE;
    WSABUF socket_buffer = {0};
    DWORD dwBytesRecv = 0;
    DWORD dwFlags = 0;
    NTSTATUS ntRetVal = STATUS_SUCCESS;

    // Create the socket that will be used for key exchange
    pConnInfo->sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    if (INVALID_SOCKET == pConnInfo->sock)
    {
        DBG_PRINT(L"Error creating socket\n");
        dwRetVal = WSAGetLastError();
        goto end;
    }

    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(pConnInfo->wPort);

    // Convert the IP to binary notation
    dwRetVal = InetPtonW(AF_INET, pConnInfo->pAddress, &addr.sin_addr);
    if (1 != dwRetVal)
    {
        DBG_PRINT(L"Error converting ip address %s:%d\n", pConnInfo->pAddress, WSAGetLastError());
        goto end;
    }

    // Initiate three-way handshake
    dwRetVal = WSAConnect(pConnInfo->sock, (SOCKADDR *) &addr, sizeof(SOCKADDR_IN), NULL, NULL, NULL, NULL);
    if (SOCKET_ERROR == dwRetVal)
    {
        DBG_PRINT(L"Error initiating three-way handshake\n");
        dwRetVal = WSAGetLastError();
        goto end;
    }

    // Allocate buffer to receive 128 bytes of random data
    socket_buffer.len = RAND_BYTES_SIZE;
    socket_buffer.buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_BYTES_SIZE);
    if (NULL == socket_buffer.buf)
    {
        DBG_PRINT(L"Error allocating random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    // Blocking call to wait for 128 bytes
    dwRetVal = WSARecv(pConnInfo->sock, &(socket_buffer), 1, &dwBytesRecv, &dwFlags, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error receiving random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    DBG_PRINT(L"Random Bytes received %d\n", dwBytesRecv);

    #ifdef DEBUG
    CryptoPrintBytes(dwBytesRecv, L"Unencrypted Random Bytes\n", socket_buffer.buf);
    #endif
    
    // Encrypt the random bytes and send it back to, so server can verify authenticity of client
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    PCRYPTO_DATA pEncRandBytes = NULL;

    ntRetVal = CryptoEncrypt(
        hPublicKey,
        socket_buffer.buf,
        socket_buffer.len,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pEncRandBytes
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Unable to encrypt random bytes: %u\n", ntRetVal);
        goto end;
    }
    
    #ifdef DEBUG
    CryptoPrintBytes(pEncRandBytes->dwDataSize, L"Encrypted Random Bytes\n", pEncRandBytes->pData);
    #endif

    HeapFree(GetProcessHeap(), 0, socket_buffer.buf);
    socket_buffer.buf = NULL;
    socket_buffer.len = 0;

    // Send back the encrypted bytes
    socket_buffer.len = pEncRandBytes->dwDataSize;
    socket_buffer.buf = pEncRandBytes->pData;

    DWORD dwBytesSent = 0;

    dwRetVal = WSASend(pConnInfo->sock, &(socket_buffer), 1, &dwBytesSent, 0, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error sending encrypted random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    DBG_PRINT(L"\nBytes sent: %d\n", dwBytesSent);

    HeapFree(GetProcessHeap(), 0, socket_buffer.buf);
    socket_buffer.buf = NULL;
    socket_buffer.len = 0;

    // Generate symmetric key and send to server
    PCRYPTO_DATA pSymmetricKey;
    BCRYPT_KEY_HANDLE hSymmetricKey = NULL;

    ntRetVal = CryptoGenerateSymmetricKey(BCRYPT_AES_ALGORITHM, NULL, &hSymmetricKey, &pSymmetricKey);

	PCRYPTO_DATA pEncSymKey = NULL;
    
    ntRetVal = CryptoEncrypt(
        hPublicKey,
        pSymmetricKey->pData,
        pSymmetricKey->dwDataSize,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pEncSymKey
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Unable to encrypt symmetric key: %u\n", ntRetVal);
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(pEncSymKey->dwDataSize, L"Encrypted Symmetric Key\n", pEncSymKey->pData);
    #endif

    socket_buffer.buf = pEncSymKey->pData;
    socket_buffer.len = pEncSymKey->dwDataSize;

    dwRetVal = WSASend(pConnInfo->sock, &socket_buffer, 1, &dwBytesSent, 0, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error sending encrypted Symmetric Key bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    DBG_PRINT(L"\nEncrypted Symmetric Key Bytes sent: %d\n", dwBytesSent);

    // After these are sent we can go ahead and dispose of encypted key
    HeapFree(GetProcessHeap(), 0, pEncSymKey->pData);
    HeapFree(GetProcessHeap(), 0, pEncSymKey);
    socket_buffer.buf = NULL;
    socket_buffer.len = 0;

    // TODO rework verification to be a decryption of encypted symmetric key
    PBYTE pVerificationText = NULL;
    PBYTE pDecryptedVerification = NULL;

    pVerificationText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, VERIFICATION_SIZE);
    if (NULL == pVerificationText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    socket_buffer.len = VERIFICATION_SIZE;
    socket_buffer.buf = pVerificationText;
    dwRetVal = WSARecv(pConnInfo->sock, &socket_buffer, 1, &dwBytesRecv, &dwFlags, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error receiving verification bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    PCRYPTO_DATA pDecryptedVerify = NULL;

    ntRetVal = CryptoDecrypt(
        hSymmetricKey,
        pVerificationText,
        dwBytesRecv,
        NULL,
        NULL,
        0,
        BCRYPT_BLOCK_PADDING,
        &pDecryptedVerify
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error decrypting verification\n");
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(pDecryptedVerify->dwDataSize, L"Decrypted verification\n", pDecryptedVerify->pData);
    #endif

    DBG_PRINT(L"%s\n", (PWCHAR) pDecryptedVerify->pData);


end:
    if (NULL != socket_buffer.buf)
    {
        HeapFree(GetProcessHeap(), 0, socket_buffer.buf);
    }

    return dwRetVal;
}

DWORD CryptoValidateKeyExchange(PCRYPTO_COMMS pConnInfo, BCRYPT_KEY_HANDLE hPrivateKey)
{
    DWORD dwRetVal = CRYPTO_FAILURE;
    NTSTATUS ntRetVal = STATUS_SUCCESS;
    PBYTE pRandBytes = NULL;
    PBYTE pCipherText = NULL;
    BOOL bSuccess = FALSE;
    BCRYPT_KEY_HANDLE hSymmetricKey = NULL;

    
    // Create the socket that will be used for key exchange
    pConnInfo->sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    if (INVALID_SOCKET == pConnInfo->sock)
    {
        DBG_PRINT(L"Error creating socket\n");
        dwRetVal = WSAGetLastError();
        goto end;
    }

    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(pConnInfo->wPort);

    // Convert the IP to binary notation
    dwRetVal = InetPtonW(AF_INET, pConnInfo->pAddress, &addr.sin_addr);
    if (1 != dwRetVal)
    {
        DBG_PRINT(L"Error converting ip address %s:%d\n", pConnInfo->pAddress, WSAGetLastError());
        goto end;
    }

    dwRetVal = bind(pConnInfo->sock, (SOCKADDR *) &addr, sizeof(addr));
    if (SOCKET_ERROR == dwRetVal)
    {
        DBG_PRINT(L"Unable to bind\n");
        goto end;
    }

    dwRetVal = listen(pConnInfo->sock, SOMAXCONN);
    if (SOCKET_ERROR == dwRetVal)
    {
        DBG_PRINT(L"Unable to listen\n");
        goto end;
    }

    SOCKADDR_IN conn_addr = {0};
    SOCKET conn = INVALID_SOCKET;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    DWORD dwAddrLen = sizeof(conn_addr);

    conn = WSAAccept(pConnInfo->sock, (SOCKADDR *) &conn_addr, &dwAddrLen, NULL, 0);

    // Lets generate our random data
    WSABUF socket_buffer = {0};
    socket_buffer.len = RAND_BYTES_SIZE;
    pRandBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_BYTES_SIZE);
    if (NULL == pRandBytes)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptGenRandom(
        NULL,
        pRandBytes,
        RAND_BYTES_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error generating random numbers\n");
        goto end;
    }

    socket_buffer.buf = pRandBytes;

    // Send our random data to client
    DWORD dwBytesSent = 0;

    dwRetVal = WSASend(conn, &socket_buffer, 1, &dwBytesSent, 0, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error sending random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    DBG_PRINT(L"\nRandom Bytes sent: %d\n", dwBytesSent);

    #ifdef DEBUG
    CryptoPrintBytes(dwBytesSent, L"Random Bytes sent\n", socket_buffer.buf);
    #endif

    socket_buffer.buf = NULL;
    socket_buffer.len = 0;


    // Receive the encrypted random bytes back and compare to original
    DWORD dwBytesRecv = 0;
    DWORD dwFlags = 0;
    socket_buffer.len = CIPHERTEXT_SIZE;
    pCipherText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CIPHERTEXT_SIZE);
    if (NULL == pCipherText)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    socket_buffer.buf = pCipherText;

    dwRetVal = WSARecv(conn, &socket_buffer, 1, &dwBytesRecv, &dwFlags, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error receiving encrypted random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(dwBytesRecv, L"Encrypted Random Bytes received\n", socket_buffer.buf);
    #endif

    DWORD dwSizeNeeded = 0;
    DWORD dwBytesEncrypted = 0;
    DWORD dwBytesDecrypted = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    PCRYPTO_DATA pDecryptedRandBytes = NULL;

    ntRetVal = CryptoDecrypt(
        hPrivateKey,
        pCipherText,
        dwBytesRecv,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pDecryptedRandBytes
    );

    bSuccess = CryptoCompareBytes(pRandBytes, RAND_BYTES_SIZE, pDecryptedRandBytes->pData, pDecryptedRandBytes->dwDataSize);
    if (FALSE == bSuccess)
    {
        DBG_PRINT(L"Random Bytes received did not match original");
        goto end;
    }

    // Wait for symmetric key to be sent over
    SecureZeroMemory(pCipherText, CIPHERTEXT_SIZE);

    dwRetVal = WSARecv(conn, &socket_buffer, 1, &dwBytesRecv, &dwFlags, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Error receiving encrypted random bytes\n");
        dwRetVal = GetLastError();
        goto end;
    }

    PCRYPTO_DATA pDecryptedSymmetricKey = NULL;

        ntRetVal = CryptoDecrypt(
        hPrivateKey,
        pCipherText,
        dwBytesRecv,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pDecryptedSymmetricKey
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error decrypting symmetric key\n");
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(pDecryptedSymmetricKey->dwDataSize, L"Decrypted symmetric key\n", pDecryptedSymmetricKey->pData);
    #endif

    dwRetVal = CryptoImportKeyFromBlob(BCRYPT_AES_ALGORITHM, NULL, &hSymmetricKey, pDecryptedSymmetricKey);
    if (STATUS_SUCCESS != dwRetVal)
    {
        DBG_PRINT(L"Error importing symmetric key\n");
        goto end;
    }

    // TODO encrypt symmetric key
    PCRYPTO_DATA pEncVerification = NULL;
    WCHAR exchangebuf[] = L"Key exchange complete";

        ntRetVal = CryptoEncrypt(
        hSymmetricKey,
        (PUCHAR) exchangebuf,
        sizeof(exchangebuf),
        NULL,
        NULL,
        0,
        BCRYPT_BLOCK_PADDING,
        &pEncVerification
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error encrypting verification: %u\n", ntRetVal);
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(pEncVerification->dwDataSize, L"Encrypted Verification Bytes\n", pEncVerification->pData);
    #endif

    socket_buffer.len = pEncVerification->dwDataSize;
    socket_buffer.buf = pEncVerification->pData;

    dwRetVal = WSASend(conn, &socket_buffer, 1, &dwBytesSent, 0, NULL, NULL);
    if (0 != dwRetVal)
    {
        DBG_PRINT(L"Final verification failed\n");
        goto end;
    }

    DBG_PRINT(L"Final verification sent\n");
end:
// TODO cleanup for all allocs
    return ntRetVal;
}

DWORD CryptoGenerateSymmetricKey(LPCWSTR pAlgorithm, LPCWSTR pImplementation, BCRYPT_KEY_HANDLE *hSymmetricKey, PCRYPTO_DATA *data)
{
    BCRYPT_ALG_HANDLE hSymmetricProvider = NULL;
    NTSTATUS ntRetVal = STATUS_SUCCESS;
    PBYTE pKeyObject = NULL;
    PBYTE pRandKey = NULL;
    PBYTE pSymmetricKey = NULL;
    DWORD dwSizeNeeded = 0;

    *data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CRYPTO_DATA));

    if (NULL == *data)
    {
        goto end;
    }

    //Generate a symmetric key, encrypt it with public key and send it back to server
    ntRetVal = BCryptOpenAlgorithmProvider(
        &hSymmetricProvider,
        pAlgorithm,
        pImplementation,
        0
    );
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error opening symmetric algo\n");
        goto end;
    }

    DWORD dwObjectLength = 0;
    DWORD dwBytesCopied = 0;

    // Lets get the size of the key object for specified algorithm
    ntRetVal = BCryptGetProperty(
        hSymmetricProvider,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR) &dwObjectLength,
        sizeof(DWORD),
        &dwBytesCopied,
        0
    );

    DBG_PRINT(L"Object Length: %d\n", dwObjectLength);

    pKeyObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwObjectLength);
    if (NULL == pKeyObject)
    {
        DBG_PRINT(L"Error allocating memory for symmetric key\n");
        goto end;
    }

    // Generate random key to hold secret value
    pRandKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_BYTES_SIZE);
    if (NULL == pRandKey)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    // Generate a random secret value
    ntRetVal = BCryptGenRandom(
        NULL,
        pRandKey,
        SECRET_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    ntRetVal = BCryptGenerateSymmetricKey(
        hSymmetricProvider,
        hSymmetricKey,
        pKeyObject,
        dwObjectLength,
        pRandKey,
        SECRET_SIZE,
        0
        );
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error creating symmetric key\n");
        goto end;
    }

    ntRetVal = BCryptExportKey(
        *hSymmetricKey,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        NULL,
        0,
        &dwSizeNeeded,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error getting symmetric key size\n");
        goto end;
    }

    pSymmetricKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pSymmetricKey)
    {
        DBG_PRINT(L"Error allocating memory for symmetric key\n");
        goto end;
    }

    DWORD dwKeySize = 0;

    ntRetVal = BCryptExportKey(
        *hSymmetricKey,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        pSymmetricKey,
        dwSizeNeeded,
        &dwKeySize,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error exporting symmetric key\n");
        goto end;
    }

    (*data)->pData = pSymmetricKey;
    (*data)->dwDataSize = dwSizeNeeded;

    #ifdef DEBUG
    CryptoPrintBytes((*data)->dwDataSize, L"Symmetric key Bytes\n", (*data)->pData);
    #endif

end:
    if (NULL != pRandKey)
    {
        HeapFree(GetProcessHeap(), 0, pRandKey);
    }

    // TODO close provider
    return ntRetVal;
}

BOOL CryptoCompareBytes(PBYTE pOriginal, DWORD dwOrigSize, PBYTE pCompare, DWORD dwCompareSize)
{
    BOOL bRetVal = FALSE;

    if (dwOrigSize != dwCompareSize)
    {
        goto end;
    }

    for (INT i = 0; i < dwOrigSize; i++)
    {
        if (pOriginal[i] != pCompare[i])
        {
            goto end;
        }
    }

    bRetVal = TRUE;

end:
    return bRetVal;
}

DWORD CryptoImportKeyFromBlob(LPCWSTR pAlgorithm, LPCWSTR pImplementation, BCRYPT_KEY_HANDLE *hKey, PCRYPTO_DATA pKey)
{
    BCRYPT_ALG_HANDLE hProvider = NULL;
    NTSTATUS ntRetVal = STATUS_UNSUCCESSFUL;
    PBYTE pKeyObject = NULL;
    PBYTE pRandKey = NULL;
    DWORD dwSizeNeeded = 0;
    DWORD dwObjectLength = 0;
    DWORD dwBytesCopied = 0;

     ntRetVal = BCryptOpenAlgorithmProvider(
        &hProvider,
        pAlgorithm,
        pImplementation,
        0
    );

    ntRetVal = BCryptGetProperty(
        hProvider,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR) &dwObjectLength,
        sizeof(DWORD),
        &dwBytesCopied,
        0
    );

    DBG_PRINT(L"\nObject Length: %d\n", dwObjectLength);

    pKeyObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwObjectLength);
    if (NULL == pKeyObject)
    {
        DBG_PRINT(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptImportKey(
        hProvider,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        hKey,
        pKeyObject,
        dwObjectLength,
        pKey->pData,
        pKey->dwDataSize,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error importing symmetric key\n");
        goto end;
    }

    ntRetVal = STATUS_SUCCESS;
end:
    return ntRetVal;
}