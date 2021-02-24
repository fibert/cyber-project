#include <UI.h>
#include <agent.h>

#define _WIN32_DCOM
#include <string>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <io.h>
#include <fcntl.h>
#include <fstream>
#include <vector>
#include <set>
#include <unordered_map>
#include <filesystem>

#include <tchar.h>
#include <stdlib.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <shlobj_core.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment (lib, "wintrust")
//using namespace std;


int queryWMI(std::vector<std::string> *, const wchar_t *, const wchar_t *, const wchar_t*);
int runPowerShellCommand(std::vector<std::string> *, const char *);
BOOL VerifyEmbeddedSignature(LPCWSTR);

float checkSignedPEs();
float checkLatestSecurityHotfix();
float checkRootCA();
float checkListeningTCPPorts();
float checkHttpsOrHttp();
float checkListenningPorts();


std::unordered_map<std::wstring, bool> um_verifiedPEs;

void agentMain() {

    float  fScore = 0;
    
    /*fScore += checkLatestSecurityHotfix();
    fScore += checkRootCA();
    fScore += checkListeningTCPPorts();
    fScore += checkHttpsOrHttp();
    fScore += checkSignedPEs();*/
    fScore += checkListenningPorts();

    if (fScore >= 9) {
        setGreen();
    }
    else if (fScore >= 5) {
        setYellow();
    }
    else {
        setRed();
    }

    return;
}

float checkListenningPorts(){
    const char* cmd = "Get - NetTCPConnection - State Listen | ? {$_.LocalAddress - notin(\"::\", \"127.0.0.1\")} | select LocalPort | sort - object - property LocalPort - Unique | ft - HideTableHeaders; echo EOF";
    std::vector<std::string> v_openedPorts;
    
    if (runPowerShellCommand(&v_openedPorts, cmd)) {
        // Something went wrong
        return -1;
    }

    for (auto const& open_port : v_openedPorts)
    {
        OutputDebugStringA("port: ");
        OutputDebugStringA(open_port.c_str());
        OutputDebugStringA("\n");
    }
}

float checkLatestSecurityHotfix() {

    std::string latestHotfixes[] = {"KB4601050", "KB4561600", "KB4566785", "KB4570334" }; // TODO: move this to config
    std::vector<std::string> results;

    // TODO: Log results
    // TODO: Write recommended action somewhere
    if (queryWMI(&results, L"ROOT\\CIMV2", L"Win32_quickfixengineering", L"HotfixID")) {
        // Something went wrong
        return -1;
    }

    //OutputDebugStringA(results[0].c_str());


    if (results[0].compare(latestHotfixes[0]) == 0) {
        return 10.0;
    }
    if (results[0].compare(latestHotfixes[1]) == 0) {
        return 9.0;
    }
    if (results[0].compare(latestHotfixes[2]) == 0) {
        return 7.0;
    }
    if (results[0].compare(latestHotfixes[3]) == 0) {
        return 4.0;
    }
    return 0;
}

float checkSignedPEs() {

    float score = 10;

    std::set<std::wstring> set_PEToVerify;
    
    HKEY hKey;
    wchar_t ValueName[256];
    DWORD chValueName;
    DWORD Type;
    BYTE Data[MAX_PATH*2];
    DWORD cbData;
    LSTATUS status;
    int index;

    std::wstring ws_filename;

    std::unordered_map<std::wstring, bool> um_verifyWhitelist = {
        {L"%windir%\\system32\\SecurityHealthSystray.exe", true}
    };

    std::vector<std::string> registryRunPaths = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };

    for (auto const& it_path : registryRunPaths) {
        for (int j = 0; j < 2; j++) {
            // j is used for opening 2 different registry roots
            RegOpenKeyA(j == 0 ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER, it_path.c_str(), &hKey);

            index = 0;
            while (true) {
                // We use wide characters, so we need to divide by 2
                cbData = sizeof(Data) / 2;
                chValueName = sizeof(ValueName) / 2;

                status = RegEnumValueW(hKey, index, ValueName, &chValueName, NULL, &Type, Data, &cbData);

                if (status != ERROR_SUCCESS) {
                    break;
                }

                index++;

                ws_filename = std::wstring(((wchar_t*)Data));

                // Remove any \" at the start of the PE path
                if (ws_filename[0] == '\"') {
                    ws_filename.erase(ws_filename.begin(), ws_filename.begin() + 1);
                }

                // Add we check only files that end with ".exe"
                size_t exe = ws_filename.find(L".exe");
                if (exe != std::wstring::npos) {
                    // Remove any arguments and trailing \" characters after the PE path
                    ws_filename.erase(exe + 4);
                    set_PEToVerify.insert(ws_filename);
                }

            }

            RegCloseKey(hKey);
        }
    }

    std::vector<std::wstring> v_startupPaths;
    PWSTR w_path;
    
    // Add current user's startup folder to v_startupPaths
    SHGetKnownFolderPath(FOLDERID_Startup, 0, NULL, &w_path);
    v_startupPaths.push_back(w_path);

    // Add common startup folder to v_startupPaths
    SHGetKnownFolderPath(FOLDERID_CommonStartup, 0, NULL, &w_path);
    v_startupPaths.push_back(w_path);

    for (auto const& path : v_startupPaths) {
        for (auto const& file : std::filesystem::directory_iterator(path)) {
            
            // If this is not a regular file, continue to the next file
            if (!std::filesystem::is_regular_file(file)) {
                continue;
            }

            ws_filename = file.path();

            // If this file does not contain ".exe", continue to the next file
            size_t exe = ws_filename.find(L".exe");
            if (exe == std::wstring::npos) {  
                continue;
            }

            set_PEToVerify.insert(ws_filename);
        }
    }


    for (auto const& ws_pathToVerify : set_PEToVerify) {

        // Check if this path was already verified - if it was, skip it
        auto it = um_verifiedPEs.find(ws_pathToVerify);
        if (it != um_verifiedPEs.end()) {
            if (it->second) {
                // This PE was succesfully verified in the past
                continue;
            }
            else {
                // This PE's verification failed in the past
                score = 0;
                continue;
            }
        }

        // Check if this path is in the verify whitelist - if it is, skip it
        if (um_verifyWhitelist.find(ws_pathToVerify) != um_verifyWhitelist.end()) {
            continue;
        }

        // Verify this PE
        bool b_verifyResult = VerifyEmbeddedSignature(ws_pathToVerify.c_str());

        if (!b_verifyResult) {
            score = 0;
        }

        // Add this path um_verifiedPEs so it would not be verified again
        um_verifiedPEs.insert({ ws_pathToVerify, b_verifyResult });


    }

    return score;
}

float checkRootCA() {
    /**
    * Check that the current system Trusted Root CAs are a subset of a known Trusted Root CA
    */
    
    float score = 10;

    std::vector<std::string> v_knownRootCASorted = {
        "58E8ABB0361533FB80F79B1B6D29D3FF8D5F00F0",
        "590D2D7D884F402E617EA562321765CF17D894E9",
        "51501FBFCE69189D609CFAF140C576755DCC1FDF",
        "490A7574DE870A47FE58EEF6C76BEBC60B124099",
        "4EB6D578499B1CCF5F581EAD56BE3D9B6744A5E5",
        "5F3B8CF2F810B37D78B4CEEC1919C37334B9C774",
        "75E0ABB6138512271C04F85FDDDE38E4B7242EFE",
        "8782C6C304353BCFD29692D2593E7D44D934FF11",
        "742C3192E607E424EB4549542BE1BBC53E6174E2",
        "5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25",
        "6252DC40F71143A22FDE9EF7348E064251B18118",
        "47BEABC922EAE80E78783462A79F45C254FDE68B",
        "07E032E020B72C3F192F0628A2593A19A70F069E",
        "093C61F38B8BDC7D55DF7538020500E125F5C836",
        "06F1AA330B927B753A40E68CDF22E34BCBEF3352",
        "02FAF3E291435468607857694DF5E45B68851868",
        "0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43",
        "1F24C630CDA418EF2069FFAD4FDD5F463A1B69AA",
        "36B12B49F9819ED74C9EBC380FC6568F5DACB2F7",
        "3E2BF7F2031B96F38CE6C4D8A85D3E2D58476A0F",
        "3679CA35668772304D30A5FB873B0FA77BB70D54",
        "2796BAE63F1801E277261BA0D77770028F20EEE4",
        "2B8F1B57330DBBA2D07A6C51F70EE90DDAB9AD8E",
        "D4DE20D05E66FC53FE1A50882C78DB2852CAE474",
        "D69B561148F01C77C54578C10926DF5B856976AD",
        "D1EB23A46D17D68FD92564C2F1F1601764D8E349",
        "CF9E876DD3EBFC422697A3B5A37AA076A9062348",
        "D1CBCA5DB2D52A7F693B674DE5F05A1D0C957DF0",
        "DAC9024F54D8F6DF94935FB1732638CA6AD77C13",
        "E12DFB4B41D7D9C32B30514BAC1D81D8385E2D46",
        "F373B387065A28848AF2F34ACE192BDDC78E9CAC",
        "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
        "DE28F4A4FFE5B92FA3C503D1A349A7F9962A8212",
        "DE3F40BD5093D39B6C60F6DABC076201008976C9",
        "CA3AFBCF1240364B44B216208880483919937CF7",
        "9F744E9F2B4DBAEC0F312C50B6563B8E2D93C311",
        "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436",
        "925A8F8D2C6D04E0665F596AFF22D863E8256F3F",
        "8CF427FD790C3AD166068DE81E57EFBB932272D4",
        "91C6D6EE3E8AC86384E548C299295C756C817B81",
        "AD7E1C28B064EF8F6003402014C3D0E3370EB58A",
        "B51C067CEE2B0C3DF855AB2D92F4FE39D4E70F0E",
        "B7AB3308D1EA4477BA1480125A6FBDA936490CBB",
        "B31EB1B740E36C8402DADC37D44DF5D4674952F9",
        "AFE5D244A8D1194230FF479FE2F897BBCD7A8CB4",
        "B1BC968BD4F49D622AA89A81F2150152A41D829C"
    };
    
    // Get a list of all the trusted root CA Thumbprints
    const char* cmd = "dir Cert:\\CurrentUser\\AuthRoot | Select-Object -Property Thumbprint | Sort-Object | ft -HideTableHeaders ; echo EOF";
    std::vector<std::string> v_currentRootCASorted;

    if (runPowerShellCommand(&v_currentRootCASorted, cmd)) {
        // Something went wrong
        return -1;
    }


    // Check that there are no "new" trusted Root CA that are not in the known Root CA list
    // Both vectors are sorted, we can use this fact to iterate both of them together.

    std::vector<std::string>::iterator it_knownCA = v_knownRootCASorted.begin();

    for (auto const& currentCA: v_currentRootCASorted) {        
        while ((it_knownCA != v_knownRootCASorted.end()) && (currentCA != *it_knownCA)) {
            // Search for the current CA in v_knownRootCASorted
            ++it_knownCA;
        }

        if (it_knownCA == v_knownRootCASorted.end()) {
            // We reached the end of the known Root CA list
            // The current CA is not in v_knownRootCASorted. This is a new unknown certificate!
            score = 0;
            break;
        }

        // Here we know that (currentCA == *it_knownCA)
        // We can increase them both and check the next CA
        // (The for-loop will increase currentCA)
        ++it_knownCA;
    }
        
    // v_currentRootCASorted is contained by v_knownRootCASorted

    return score;
}

float checkListeningTCPPorts() {
    // Get number of listening TCP ports (that does not listen on 127.0.0.1)
    const char *cmd = "(get-nettcpconnection | Where{ ($_.State -eq \"Listen\") -and ($_.LocalAddress -ne \"127.0.0.1\")}).Length ; echo EOF";
    std::vector<std::string> ports;

    if (runPowerShellCommand(&ports, cmd)) {
        // Something went wrong
    }

    // Decide what to do with port list

    return 0;
}

float checkHttpsOrHttp() {
    // Get number of established TCP connections on ports 443 and 80
    const char *cmdHttps = "(get-nettcpconnection | Where {($_.State -eq \"Established\") -and ($_.RemotePort -eq \"443\")}).Length ; echo EOF";
    const char *cmdHttp = "(get-nettcpconnection | Where {($_.State -eq \"Established\") -and ($_.RemotePort -eq \"80\")}).Length ; echo EOF";
    std::vector<std::string> httpsCons;
    std::vector<std::string> httpCons;

    if (runPowerShellCommand(&httpsCons, cmdHttps)) {
        // Something went wrong
    }

    if (runPowerShellCommand(&httpCons, cmdHttp)) {
        // Something went wrong
    }

    // Decide what to do with the number of HTTPS and HTTP connections

    return 0;
}


int runPowerShellCommand(std::vector<std::string> *v_result, const char *psCommand)
{
    HANDLE m_hChildStd_OUT_Rd = NULL;
    HANDLE m_hChildStd_OUT_Wr = NULL;
    HANDLE m_hreadDataFromExtProgram = NULL;

    char cmd[256] = "PowerShell.exe -windowstyle hidden -command ";
    strcat_s(cmd, psCommand);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES saAttr;

    ZeroMemory(&saAttr, sizeof(saAttr));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT. 

    if (!CreatePipe(&m_hChildStd_OUT_Rd, &m_hChildStd_OUT_Wr, &saAttr, 0))
    {
        // log error
        return 1;
    }

    // Ensure the read handle to the pipe for STDOUT is not inherited.

    if (!SetHandleInformation(m_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
    {
        // log error
        return 2;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = m_hChildStd_OUT_Wr;
    si.hStdOutput = m_hChildStd_OUT_Wr;
    si.dwFlags |= STARTF_USESTDHANDLES;

    ZeroMemory(&pi, sizeof(pi));

    // Start the child process. 
    if (!CreateProcessA(NULL,           // No module name (use command line)
        (TCHAR*)cmd,    // Command line
        NULL,                           // Process handle not inheritable
        NULL,                           // Thread handle not inheritable
        TRUE,                           // Set handle inheritance to FALSE
        CREATE_NO_WINDOW,               // No creation flags
        NULL,                           // Use parent's environment block
        NULL,                           // Use parent's starting directory 
        &si,                            // Pointer to STARTUPINFO structure
        &pi)                            // Pointer to PROCESS_INFORMATION structure
        ) {
        return 3;
    }
 
    const int BUFSIZE = 512;
    DWORD dwRead;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;

    int fd;
    if ((fd = _open_osfhandle(((intptr_t)m_hChildStd_OUT_Rd), _O_RDONLY | _O_TEXT)) == -1) {
        return 4;
    }

    FILE *f = _fdopen(fd, "r");

    std::string line;

    while (fgets(chBuf, BUFSIZE, f)) {
        line = chBuf;
        line = line.substr(0, line.length() - 1);

        if (line == "")
            continue;

        if (line == "EOF")
            break;

        v_result->push_back(line);
    }

    return 0;
}


int queryWMI(std::vector<std::string> *v_results, const wchar_t *targetNamespace, const wchar_t *targetClass, const wchar_t *targetField) {
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        std::cout << "Failed to initialize COM library. Error code = 0x"
            << std::hex << hres << std::endl;
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        std::cout << "Failed to initialize security. Error code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        std::cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(targetNamespace), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        std::cout << "Could not connect. Error code = 0x"
            << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        std::cout << "Could not set proxy blanket. Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system

    wchar_t WMIQuery[64];
    swprintf(WMIQuery, L"SELECT * FROM %s", targetClass);

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(WMIQuery),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        std::cout << "Query for operating system name failed."
            << " Error code = 0x"
            << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;



    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp = { };

        // Get the value of the Name property
        hr = pclsObj->Get(targetField, 0, &vtProp, 0, 0);
        
        _bstr_t bb(vtProp.bstrVal);
        v_results->push_back(std::string(bb));

        VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return 0;   // Program successfully completed.

}


BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
    BOOL result;
    LONG lStatus;
    DWORD dwLastError;

    // If file does not exists, return true
    if (!std::filesystem::exists(pwszSourceFile)) {
        return true;
    }

    // Initialize the WINTRUST_FILE_INFO structure.

    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileData.pcwszFilePath = pwszSourceFile;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    /*
    WVTPolicyGUID specifies the policy to apply on the file
    WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

    1) The certificate used to sign the file chains up to a root
    certificate located in the trusted root certificate store. This
    implies that the identity of the publisher has been verified by
    a certification authority.

    2) In cases where user interface is displayed (which this example
    does not do), WinVerifyTrust will check for whether the
    end entity certificate is stored in the trusted publisher store,
    implying that the user trusts content from this publisher.

    3) The end entity certificate has sufficient permission to sign
    code, as indicated by the presence of a code signing EKU or no
    EKU.
    */

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;

    // Initialize the WinVerifyTrust input data structure.

    // Default all fields to 0.
    memset(&WinTrustData, 0, sizeof(WinTrustData));

    WinTrustData.cbStruct = sizeof(WinTrustData);

    // Use default code signing EKU.
    WinTrustData.pPolicyCallbackData = NULL;

    // No data to pass to SIP.
    WinTrustData.pSIPClientData = NULL;

    // Disable WVT UI.
    WinTrustData.dwUIChoice = WTD_UI_NONE;

    // No revocation checking.
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

    // Verify an embedded signature on a file.
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

    // Verify action.
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // Verification sets this value.
    WinTrustData.hWVTStateData = NULL;

    // Not used.
    WinTrustData.pwszURLReference = NULL;

    // This is not applicable if there is no UI because it changes 
    // the UI to accommodate running applications instead of 
    // installing applications.
    WinTrustData.dwUIContext = 0;

    // Set pFile.
    WinTrustData.pFile = &FileData;

    // WinVerifyTrust verifies signatures as specified by the GUID 
    // and Wintrust_Data.
    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    switch (lStatus)
    {
    case ERROR_SUCCESS:
        result = true;
        break;

    default:
        result = false;
        break;
    }

    // Any hWVTStateData must be released by a call with close.
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    lStatus = WinVerifyTrust(
        NULL,
        &WVTPolicyGUID,
        &WinTrustData);

    return result;
}
