#define WIN32_LEAN_AND_MEAN

#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <wchar.h>
#include <server_resource.h>
#include <ntstatus.h>
#include <bcrypt.h>
#include <debug.h>
#include <crypto_comms.h>

#define RAND_SIZE 128
#define CIPHER_SIZE 256

DWORD handle_conn(LPVOID param);

INT wmain(INT argc,  WCHAR *argv[])
{
    DWORD dwRetVal = EXIT_SUCCESS;
    SOCKET sock = INVALID_SOCKET;
    WSADATA wsadata = {0};
    HRSRC hResLoc = NULL;
    HGLOBAL hResource = NULL;
    NTSTATUS ntRetVal = EXIT_SUCCESS;
    BCRYPT_ALG_HANDLE hProvider = NULL;
    BCRYPT_ALG_HANDLE hSymmetricProvider = NULL;
    DWORD dwResSize = 0;
    PBYTE pPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hSymmetricKey = NULL;
    PBYTE pRand = NULL;
    PBYTE pDecryptedText = NULL;
    PBYTE pDecryptedKey = NULL;
    PBYTE pCipherText = NULL;
    PBYTE pEncryptedText = NULL;
    PBYTE pKeyObject = NULL;

    if (argc != 3)
    {
        wprintf(L"Usage: client ip port\n");
        goto end;
    }

    // Lets load our private key from our resource
    hResLoc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
    if (NULL == hResLoc)
    {
        wprintf(L"Error getting resource location\n");
        goto end;
    }

    hResource = LoadResource(NULL, hResLoc);
    if (NULL == hResource)
    {
        wprintf(L"Error getting handle to resource\n");
        goto end;
    }

    dwResSize = SizeofResource(GetModuleHandleW(NULL), hResLoc);

    pPrivateKey = LockResource(hResource);
    if (NULL == pPrivateKey)
    {
        wprintf(L"Error getting resource data\n");
        goto end;
    }
    wprintf(L"Debug: %p:%d\n", pPrivateKey, dwResSize);

    // Initialize our crypto and import our key
    ntRetVal = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_RSA_ALGORITHM, NULL, 0);
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error opening algo\n");
        goto end;
    }

    ntRetVal = BCryptImportKeyPair(
        hProvider,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        &hPrivateKey,
        pPrivateKey,
        dwResSize,
        BCRYPT_NO_KEY_VALIDATION
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error loading private key: %u\n", ntRetVal);
        goto end;
    }

// Initialize our socket and wait for a connection
    WSAStartup(MAKEWORD(2, 2), &wsadata);

    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    
    if (INVALID_SOCKET == sock)
    {
        wprintf(L"Error creating socket\n");
        goto end;
    }
    
    // Validate our port is within usable range
    DWORD dwPort = StrToIntW(argv[2]);

    if (dwPort < 1 || dwPort > 65535)
    {
        wprintf(L"Invalid port\n");
        goto end;
    }

    SOCKADDR_IN addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dwPort);

    // Convert the IP to binary notation
    dwRetVal = InetPtonW(AF_INET, argv[1], &addr.sin_addr);
    if (1 != dwRetVal)
    {
        wprintf(L"Error converting ip address %s:%d\n", argv[1], WSAGetLastError());
        goto end;
    }

    dwRetVal = bind(sock, (SOCKADDR *) &addr, sizeof(addr));
    if (SOCKET_ERROR == dwRetVal)
    {
        wprintf(L"Unable to bind\n");
        goto end;
    }

    dwRetVal = listen(sock, SOMAXCONN);
    if (SOCKET_ERROR == dwRetVal)
    {
        wprintf(L"Unable to listen\n");
        goto end;
    }

    SOCKADDR_IN conn_addr = {0};
    SOCKET conn = INVALID_SOCKET;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    DWORD dwAddrLen = sizeof(conn_addr);

    conn = WSAAccept(sock, (SOCKADDR *) &conn_addr, &dwAddrLen, NULL, 0);

    // Lets generate our random data
    WSABUF buf = {0};
    buf.len = RAND_SIZE;
    pRand = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_SIZE);
    if (NULL == pRand)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptGenRandom(
        NULL,
        pRand,
        RAND_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error generating random numbers\n");
        goto end;
    }

    buf.buf = pRand;

    DWORD dwBytesSent = 0;

    WSASend(conn, &buf, 1, &dwBytesSent, 0, NULL, NULL);

    wprintf(L"\nBytes sent: %d\n", dwBytesSent);
    for(int i = 0; i < RAND_SIZE; i++)
    {
        wprintf(L"%02hhx", buf.buf[i]);
    }

    DWORD dwBytesRecv = 0;
    DWORD dwFlags = 0;
    buf.len = CIPHER_SIZE;
    pCipherText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CIPHER_SIZE);
    if (NULL == pCipherText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    buf.buf = pCipherText;

    WSARecv(conn, &buf, 1, &dwBytesRecv, &dwFlags, NULL, NULL);

    wprintf(L"\nCipher bytes received: %d\n", dwBytesRecv);
    wprintf(L"Cipher text\n");
    for(int i = 0; i < CIPHER_SIZE; i++)
    {
        wprintf(L"%02hhx", buf.buf[i]);
    }

    DWORD dwSizeNeeded = 0;
    DWORD dwBytesEncrypted = 0;
    DWORD dwBytesDecrypted = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    PCRYPTO_DATA pEncRandInit = NULL;

    ntRetVal = CryptoDecrypt(
        hPrivateKey,
        pCipherText,
        dwBytesRecv,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pEncRandInit
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        goto end;
    }

    HeapFree(GetProcessHeap(), 0, pCipherText);
    pCipherText = NULL;

    #ifdef DEBUG
    CryptoPrintBytes(pEncRandInit->dwDataSize, L"Decrypted Random Bytes\n", pEncRandInit->pData);
    #endif

    for (INT i = 0; i < RAND_SIZE; i++)
    {
        if (pEncRandInit->pData[i] != pRand[i])
        {
            DBG_PRINT(L"Keys do not match\n");
            goto end;
        }
    }

// TODO acknowlege successful verification

// TODO Wait for symmetric key to be sent over
    buf.len = CIPHER_SIZE;
    pCipherText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CIPHER_SIZE);
    if (NULL == pCipherText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    buf.buf = pCipherText;

    WSARecv(conn, &buf, 1, &dwBytesRecv, &dwFlags, NULL, NULL);

    wprintf(L"\nCipher bytes received: %d\n", dwBytesRecv);
    wprintf(L"Cipher text\n");
    for(int i = 0; i < CIPHER_SIZE; i++)
    {
        wprintf(L"%02hhx", buf.buf[i]);
    }

    PCRYPTO_DATA pEncSymmetricKey = NULL;

    ntRetVal = CryptoDecrypt(
        hPrivateKey,
        pCipherText,
        dwBytesRecv,
        &padding,
        NULL,
        0,
        BCRYPT_PAD_OAEP,
        &pEncSymmetricKey
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        DBG_PRINT(L"Error decrypting symmetric key\n");
        goto end;
    }

    #ifdef DEBUG
    CryptoPrintBytes(pEncSymmetricKey->dwDataSize, L"Decrypted symmetric key\n", pEncSymmetricKey->pData);
    #endif

    HeapFree(GetProcessHeap(), 0, pCipherText);
    pCipherText = NULL;

    // Import key from decrypted blob
    DWORD dwKeySize = 0;

    ntRetVal = BCryptOpenAlgorithmProvider(
        &hSymmetricProvider,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );

    DWORD dwObjectLength = 0;
    DWORD dwBytesCopied = 0;

    ntRetVal = BCryptGetProperty(
        hSymmetricProvider,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR) &dwObjectLength,
        sizeof(DWORD),
        &dwBytesCopied,
        0
    );

    wprintf(L"\nObject Length: %d\n", dwObjectLength);

    pKeyObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwObjectLength);
    if (NULL == pKeyObject)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptImportKey(
        hSymmetricProvider,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        &hSymmetricKey,
        pKeyObject,
        dwObjectLength,
        pEncSymmetricKey->pData,
        pEncSymmetricKey->dwDataSize,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error importing symmetric key\n");
        goto end;
    }

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

    buf.len = pEncVerification->dwDataSize;
    buf.buf = pEncVerification->pData;

    WSASend(conn, &buf, 1, &dwBytesSent, 0, NULL, NULL);



end:
    if (INVALID_SOCKET != sock)
    {
        closesocket(sock);
    }

    if (INVALID_SOCKET != conn)
    {
        closesocket(sock);
    }

    if (NULL != hProvider)
    {
        BCryptCloseAlgorithmProvider(hProvider, 0);
    }

    if (NULL != hPrivateKey)
    {
        BCryptDestroyKey(hPrivateKey);
    }

    if (NULL != pDecryptedText)
    {
        HeapFree(GetProcessHeap(), 0, pDecryptedText);
        pDecryptedText = NULL;
    }

    if (NULL != pCipherText)
    {
        HeapFree(GetProcessHeap(), 0, pCipherText);
        pCipherText = NULL;
    }

    if (NULL != pDecryptedKey)
    {
        HeapFree(GetProcessHeap(), 0, pDecryptedKey);
        pDecryptedKey = NULL;
    }

    return dwRetVal;
}