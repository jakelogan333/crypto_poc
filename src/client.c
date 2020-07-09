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
    BCRYPT_KEY_HANDLE hPublicKey = NULL;
    PBYTE pEncryptedRand = NULL;
    PBYTE pRandBytes = NULL;

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

    // Free previous buffer with unencrypted random numbers
    if (NULL != buf.buf)
    {
        HeapFree(GetProcessHeap(), 0, buf.buf);
        buf.buf = NULL;
    }

    buf.len = dwBytesEncrypted;
    buf.buf = pEncryptedRand;
    DWORD dwBytesSent = 0;

    WSASend(sock, &buf, 1, &dwBytesSent, 0, NULL, NULL);
    wprintf(L"\nBytes sent: %d\n", dwBytesSent);


    // Generate a symmetric key, encrypt it with public key and send it back to server


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

    return dwRetVal;
}