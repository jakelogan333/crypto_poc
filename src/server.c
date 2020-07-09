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
    BCRYPT_ALG_HANDLE hRandProvider = NULL;
    DWORD dwResSize = 0;
    PBYTE pPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    UCHAR pPlainText[256] = {0x00, 0x01, 0x02, 0x03};
    PBYTE pEncryptedText = NULL;
    PBYTE pRand = NULL;
    PBYTE pDecryptedText = NULL;

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
    buf.buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CIPHER_SIZE);
    if (NULL == buf.buf)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    WSARecv(conn, &buf, 1, &dwBytesRecv, &dwFlags, NULL, NULL);

    wprintf(L"\nCipher bytes received: %d\n", dwBytesRecv);
    wprintf(L"Cipher text\n");
    for(int i = 0; i < CIPHER_SIZE; i++)
    {
        wprintf(L"%02hhx", buf.buf[i]);
    }

    DWORD dwSizeNeeded = 0;
    DWORD dwBytesEncrypted = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    ntRetVal = BCryptDecrypt(
        hPrivateKey,
        buf.buf,
        dwBytesRecv,
        &padding,
        NULL,
        0,
        NULL,
        0,
        &dwSizeNeeded,
        BCRYPT_PAD_OAEP
    );

    wprintf(L"\nSize needed: %d:%u\n", dwSizeNeeded, ntRetVal);


    pDecryptedText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pDecryptedText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

DWORD dwBytesDecrypted = 0;

ntRetVal = BCryptDecrypt(
    hPrivateKey,
    buf.buf,
    dwBytesRecv,
    &padding,
    NULL,
    0,
    pDecryptedText,
    dwSizeNeeded,
    &dwBytesDecrypted,
    BCRYPT_PAD_OAEP
    );

    wprintf(L"Decryptred Cipher text\n");
    for(int i = 0; i < dwBytesDecrypted; i++)
    {
        wprintf(L"%02hhx", pDecryptedText[i]);
    }

    BOOL bDecryptionMatch = TRUE;

    for (INT i = 0; i < RAND_SIZE; i++)
    {
        if (pDecryptedText[i] != pRand[i])
        {
            bDecryptionMatch = FALSE;
            break;
        }
    }

    if (FALSE == bDecryptionMatch)
    {
        wprintf("\nKeys do not match\n");
        goto end;
    }



end:
    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }

    return dwRetVal;
}