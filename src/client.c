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
#include <crypto_comms.h>
#include <debug.h>

#define RAND_SIZE 128
#define CIPHER_SIZE 256
#define KEY_SIZE 16
#define VERIFICATION_SIZE 48

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
    PBYTE pEncryptedKey = NULL;
    PBYTE pVerificationText = NULL;
    PBYTE pDecryptedVerification = NULL;

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

    // Validate our port is within usable range
    DWORD dwPort = StrToIntW(argv[2]);

    if (dwPort < 1 || dwPort > 65535)
    {
        wprintf(L"Invalid port\n");
        goto end;
    }

    CRYPTO_COMMS pConnInfo = {0};
    pConnInfo.pAddress = argv[1];
    pConnInfo.wPort = (WORD) dwPort;

    // TODO pass address of symmetric key and key object so it can be gracefully
    // destroyed upon completion
    CryptoInitiateKeyExchange(&pConnInfo, hPublicKey);


end:
    // TODO close WSA
    return dwRetVal;
}