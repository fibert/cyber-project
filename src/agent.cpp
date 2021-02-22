#include <UI.h>
#include <agent.h>

#define _WIN32_DCOM
#include <string>
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")
//using namespace std;

int queryWMI(std::string[], const wchar_t *, const wchar_t *, const wchar_t*);
int runPowerShellCommand(std::string *, const char *);
float checkLatestSecurityHotfix();


int c = 0;

void agentMain() {
     //c = (c + 1) % 3;

     //if (c == 0) {
     //    setGreen();
     //}
     //else if (c == 1) {
     //    setYellow();
     //}
     //else if (c == 2) {
     //    setRed();
     //}
    std::string psRes = std::string();
    std::string psCmd = "Get-ComputerInfo";

    if (!runPowerShellCommand(&psRes, psCmd)) {
        // Something went wrong
        OutputDebugStringA("ERROR in ps command\n");
        return;
    }
    /*OutputDebugStringA("SUCCESS\nresult111: ");
    OutputDebugStringA(psRes->c_str());
    OutputDebugStringA("\n*******************************************\n");*/


    float  fScore = 0;
    
    fScore = checkLatestSecurityHotfix();

    //queryWMI(L"ROOT\\CIMV2", "Win32_OperatingSystem", L"NAME");


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
    std::string results[64];

    // TODO: Log results
    // TODO: Write recommended action somewhere
    if (!queryWMI(results, L"ROOT\\CIMV2", L"Win32_quickfixengineering", L"HotfixID")) {
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

int runPowerShellCommand(std::string *result, const char *psCommand)
{
    char buffer[128];

    char cmd[512] = "PowerShell.exe -windowstyle hidden -command ";
    strcat_s(cmd, psCommand);

    // Open pipe to file
    FILE* pipe = _popen(cmd, "rt");
    if (!pipe) {
        OutputDebugStringA("runPowerShellCommand: cannot create process\n");
        return -1;
    }
    
    // read till end of process:
    while (!feof(pipe)) {
        // use buffer to read and add to result
        if (fgets(buffer, 128, pipe) != NULL)
            result->append(buffer);
    }

    _pclose(pipe);
    return 0;
}

int queryWMI(std::string *str_results, const wchar_t *targetNamespace, const wchar_t *targetClass, const wchar_t *targetField)
{
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
        //char* out = bb;
        *str_results = std::string(bb);// str(bb);
        /*OutputDebugStringA(out);*/

        VariantClear(&vtProp);

        pclsObj->Release();

        str_results++;
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return 0;   // Program successfully completed.

}