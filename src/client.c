#pragma comment(lib, "bcrypt.lib")

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

#define RAND_SIZE 128
#define CIPHER_SIZE 256
#define KEY_SIZE 16

INT wmain(INT argc,  WCHAR *argv[])
{
    DWORD dwRetVal = EXIT_SUCCESS;
    SOCKET sock = INVALID_SOCKET;
    WSADATA wsadata = {0};
    HRSRC hResLoc = NULL;
    HGLOBAL hResource = NULL;
    DWORD dwResSize = 0;
    PBYTE pPublicKey = NULL;
    NTSTATUS ntRetVal = EXIT_SUCCESS;
    BCRYPT_ALG_HANDLE hProvider = NULL;
    BCRYPT_ALG_HANDLE hSymmetricProvider = NULL;
    BCRYPT_KEY_HANDLE hSymmetricKey = NULL;
    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    PBYTE pEncryptedRand = NULL;
    PBYTE pRandBytes = NULL;
    PBYTE pKeyObject = NULL;
    PBYTE pRandKey = NULL;
    PBYTE pSymmetricKey = NULL;

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

    pPublicKey = LockResource(hResource);
    if (NULL == pPublicKey)
    {
        wprintf(L"Error getting resource data\n");
        goto end;
    }

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
        BCRYPT_RSAPUBLIC_BLOB,
        &hPublicKey,
        pPublicKey,
        dwResSize,
        BCRYPT_NO_KEY_VALIDATION
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error loading public key %u\n", ntRetVal);
        goto end;
    }


    // Initialize our socket and establish a connection
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

    // Initiate a single connection and recieve random bytes
    dwRetVal = WSAConnect(sock, (SOCKADDR *) &addr, sizeof(SOCKADDR_IN), NULL, NULL, NULL, NULL);
    if (SOCKET_ERROR == dwRetVal)
    {
        wprintf(L"Error connecting\n");
        goto end;
    }

    WSABUF buf = {0};
    buf.len = RAND_SIZE;
    pRandBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_SIZE);
    if (NULL == pRandBytes)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    buf.buf = pRandBytes;

    DWORD dwBytesRecv = 0;
    DWORD dwFlags = 0;

    WSARecv(sock, &buf, 1, &dwBytesRecv, &dwFlags, NULL, NULL);

    wprintf(L"Bytes received %d\n", dwBytesRecv);

    wprintf(L"Random bytes unencrypted\n");
    for(int i = 0; i < dwBytesRecv; i++)
    {
        wprintf(L"%02hhx", pRandBytes[i]);
    }

    DWORD dwSizeNeeded = 0;
    DWORD dwBytesEncrypted = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

     // Get the size of buffer required
    ntRetVal = BCryptEncrypt(
        hPublicKey,
        pRandBytes,
        RAND_SIZE,
        &padding,
        NULL,
        0,
        NULL,
        0,
        &dwSizeNeeded,
        BCRYPT_PAD_OAEP
    );

    wprintf(L"\nSize needed: %d\n", dwSizeNeeded);

    pEncryptedRand = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pEncryptedRand)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptEncrypt(
        hPublicKey,
        pRandBytes,
        RAND_SIZE,
        &padding,
        NULL,
        0,
        pEncryptedRand,
        dwSizeNeeded,
        &dwBytesEncrypted,
        BCRYPT_PAD_OAEP
    );

    wprintf(L"\nEncrypted bytes\n");
    for(int i = 0; i < dwBytesEncrypted; i++)
    {
        wprintf(L"%02hhx", pEncryptedRand[i]);
    }

    buf.len = dwBytesEncrypted;
    buf.buf = pEncryptedRand;
    DWORD dwBytesSent = 0;

    WSASend(sock, &buf, 1, &dwBytesSent, 0, NULL, NULL);
    wprintf(L"\nBytes sent: %d\n", dwBytesSent);


    // Generate a symmetric key, encrypt it with public key and send it back to server
    ntRetVal = BCryptOpenAlgorithmProvider(
        &hSymmetricProvider,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error opening symmetric algo\n");
        goto end;
    }

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

    wprintf(L"Object Length: %d\n", dwObjectLength);

    pKeyObject = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwObjectLength);
    if (NULL == pKeyObject)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    // Generate random key
    pRandKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, RAND_SIZE);
    if (NULL == pRandKey)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptGenRandom(
        NULL,
        pRandKey,
        KEY_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    ntRetVal = BCryptGenerateSymmetricKey(
        hSymmetricProvider,
        &hSymmetricKey,
        pKeyObject,
        dwObjectLength,
        pRandKey,
        KEY_SIZE,
        0
        );
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error creating symmetric key\n");
        goto end;
    }

    ntRetVal = BCryptExportKey(
        hSymmetricKey,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        NULL,
        0,
        &dwSizeNeeded,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error getting symmetric key size\n");
        goto end;
    }

    pSymmetricKey = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pSymmetricKey)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    DWORD dwKeySize = 0;

    ntRetVal = BCryptExportKey(
        hSymmetricKey,
        NULL,
        BCRYPT_KEY_DATA_BLOB,
        pSymmetricKey,
        dwSizeNeeded,
        &dwKeySize,
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error exporting symmetric key\n");
        goto end;
    }

    wprintf(L"\nSymmetric key\n", dwBytesSent);
    for(int i = 0; i < dwKeySize; i++)
    {
        wprintf(L"%02hhx", pSymmetricKey[i]);
    }
    // TODO Encrypt symmetric key and send to server
    // TODO validate symmetric key works

    


end:
    if (INVALID_SOCKET != sock)
    {
        closesocket(sock);
    }

    if (NULL != hProvider)
    {
        BCryptCloseAlgorithmProvider(hProvider, 0);
    }

    if (NULL != hPublicKey)
    {
        BCryptDestroyKey(hPublicKey);
    }

    if (NULL != pRandBytes)
    {
        HeapFree(GetProcessHeap(), 0, pRandBytes);
        pRandBytes = NULL;  
    }

    if (NULL != pEncryptedRand)
    {
        HeapFree(GetProcessHeap(), 0, pEncryptedRand);
        pEncryptedRand = NULL;  
    }

    if (NULL != hSymmetricProvider)
    {
        BCryptCloseAlgorithmProvider(hSymmetricProvider, 0);
    }

    if (NULL != hSymmetricKey)
    {
        BCryptDestroyKey(hSymmetricKey);
    }

    if (NULL != pRandKey)
    {
        HeapFree(GetProcessHeap(), 0, pRandKey);
        pRandKey = NULL;
    }

    if (NULL != pSymmetricKey)
    {
        HeapFree(GetProcessHeap(), 0, pSymmetricKey);
        pSymmetricKey = NULL;
    }

    return dwRetVal;
}