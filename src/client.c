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
    PBYTE pDecryptedText = NULL;

    if (argc != 3)
    {
        wprintf(L"Usage: client ip port\n");
        goto end;
    }

    // Lets get a pointer to our public key
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
    wprintf(L"Debug: %p\n", pPublicKey);

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

    // Initiate a single connection
    dwRetVal = WSAConnect(sock, (SOCKADDR *) &addr, sizeof(SOCKADDR_IN), NULL, NULL, NULL, NULL);
    if (SOCKET_ERROR == dwRetVal)
    {
        wprintf(L"Error connecting\n");
        goto end;
    }

    WSABUF buf = {0};
    buf.len = 1024;
    buf.buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
    DWORD dwBytesRecv = 0;
    DWORD dwFlags = 0;

    WSARecv(sock, &buf, 1, &dwBytesRecv, &dwFlags, NULL, NULL);

    wprintf(L"Bytes received %d\n", dwBytesRecv);

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
        0
    );

    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error loading public key %u\n", ntRetVal);
        goto end;
    }

    DWORD dwSizeNeeded = 0;
    BCRYPT_OAEP_PADDING_INFO padding = {0};
    padding.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    padding.pbLabel = NULL;
    padding.cbLabel = 0;

    ntRetVal = BCryptDecrypt(
        hPublicKey,
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

    wprintf(L"Size needed: %d:%u\n", dwSizeNeeded, ntRetVal);


pDecryptedText = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSizeNeeded);
    if (NULL == pDecryptedText)
    {
        wprintf(L"Error allocating memory\n");
        goto end;
    }

DWORD dwBytesDecrypted = 0;

    ntRetVal = BCryptDecrypt(
        hPublicKey,
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
    
    if (STATUS_SUCCESS != ntRetVal)
    {
        wprintf(L"Error decrypting data %u\n", ntRetVal);
        goto end;
    }

    wprintf(L"Cipher text\n");
    for(int i = 0; i < dwBytesRecv; i++)
    {
        wprintf(L"%hhx", buf.buf[i]);
    }

    wprintf(L"\nDecrypted %d bytes\n", dwBytesDecrypted);
    for(int i = 0; i < dwBytesRecv; i++)
    {
        wprintf(L"%hhx", pDecryptedText[i]);
    }

end:
    return dwRetVal;
}