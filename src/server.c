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

#define BUF_SIZE 100

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
    DWORD dwResSize = 0;
    PBYTE pPrivateKey = NULL;
    BCRYPT_KEY_HANDLE hPrivateKey = NULL;
    UCHAR pPlainText[BUF_SIZE] = "Hello Encryption";
    PBYTE pEncryptedText = NULL;

    if (argc != 3)
    {
        wprintf(L"Usage: client ip port\n");
        goto end;
    }

    // Lets get a pointer to our private key
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

    // TODO initialize crypto

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
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error loading private key: %u\n", ntRetVal);
        goto end;
    }

    DWORD dwBytesEncrypted = 0;
    DWORD dwSizeNeeded = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    // Get the size of buffer required
    ntRetVal = BCryptEncrypt(
        hPrivateKey,
        pPlainText,
        BUF_SIZE,
        &padding,
        NULL,
        0,
        NULL,
        0,
        &dwSizeNeeded,
        BCRYPT_PAD_OAEP
    );

    wprintf(L"Size needed: %d\n", dwSizeNeeded);

    pEncryptedText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pEncryptedText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

    ntRetVal = BCryptEncrypt(
        hPrivateKey,
        pPlainText,
        BUF_SIZE,
        &padding,
        NULL,
        0,
        pEncryptedText,
        dwSizeNeeded,
        &dwBytesEncrypted,
        BCRYPT_PAD_OAEP
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error encrypting data %u\n", ntRetVal);
        goto end;
    }

    wprintf(L"Plaintext\n");
    for(int i = 0; i < BUF_SIZE; i++)
    {
        wprintf(L"%hhx", pPlainText[i]);
    }

    wprintf(L"\nEncrypted %d bytes\n", dwBytesEncrypted);
    for(int i = 0; i < dwSizeNeeded; i++)
    {
        wprintf(L"%02hhx", pEncryptedText[i]);
    }

    WSAStartup(MAKEWORD(2, 2), &wsadata);

    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    
    if (INVALID_SOCKET == sock)
    {
        wprintf(L"Error creating socket\n");
        goto end;
    }
    
    // StrToInt is not very fault tolerant but easier than strtol
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

    WSABUF buf = {0};

    buf.len = dwBytesEncrypted;
    buf.buf = pEncryptedText;
    DWORD dwBytesSent = 0;

    WSASend(conn, &buf, 1, &dwBytesSent, 0, NULL, NULL);

    wprintf(L"\nBytes sent: %d\n", dwBytesSent);

end:
    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }

    return dwRetVal;
}

