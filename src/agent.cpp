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

#pragma comment(lib, "wbemuuid.lib")
//using namespace std;


int queryWMI(std::vector<std::string> *, const wchar_t *, const wchar_t *, const wchar_t*);
int runPowerShellCommand(std::vector<std::string> *, const char *);
float checkLatestSecurityHotfix();
float checkRootCA();
float checkListeningTCPPorts();
float checkHttpsOrHttp();


void agentMain() {

    float  fScore = 0;
    
    fScore += checkLatestSecurityHotfix();
    fScore += checkRootCA();
    fScore += checkListeningTCPPorts();
    fScore += checkHttpsOrHttp();

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

float checkRootCA() {
    // Get a list of all the trusted root CA Thumbprints
    const char* cmd = "dir Cert:\CurrentUser\AuthRoot | Select-Object -Property Thumbprint | ft -HideTableHeaders ; echo EOF";
    std::vector<std::string> certs;

    if (runPowerShellCommand(&certs, cmd)) {
        // Something went wrong
    }

    // Compare here to known certs

    return 0;
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


int initWMI() {
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

    return 0;
}

int queryWMI(std::vector<std::string> *v_results, const wchar_t *targetNamespace, const wchar_t *targetClass, const wchar_t *targetField) {
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    //hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    //if (FAILED(hres))
    //{
    //    std::cout << "Failed to initialize COM library. Error code = 0x"
    //        << std::hex << hres << std::endl;
    //    return 1;                  // Program has failed.
    //}

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    //hres = CoInitializeSecurity(
    //    NULL,
    //    -1,                          // COM authentication
    //    NULL,                        // Authentication services
    //    NULL,                        // Reserved
    //    RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
    //    RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
    //    NULL,                        // Authentication info
    //    EOAC_NONE,                   // Additional capabilities 
    //    NULL                         // Reserved
    //);


    //if (FAILED(hres))
    //{
    //    std::cout << "Failed to initialize security. Error code = 0x"
    //        << std::hex << hres << std::endl;
    //    CoUninitialize();
    //    return 1;                    // Program has failed.
    //}

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