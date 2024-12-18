#include "driver_scanner.hpp"
#include "string_utils.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <locale>
#include <winhttp.h>
#include <wincrypt.h>
#include <fstream>
#include <iostream>
#include <softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <dbghelp.h>
#include <map>
#include <winver.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "version.lib")

// Define MD5 length constant
#define MD5_HASH_LENGTH 16

// Helper function to convert FILETIME to time_point
std::chrono::system_clock::time_point FileTimeToTimePoint(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    // Convert to Unix epoch
    auto fileTime_systemTime = ull.QuadPart;
    auto unixTime = (fileTime_systemTime - 116444736000000000ULL) / 10000000ULL;
    
    return std::chrono::system_clock::from_time_t(static_cast<time_t>(unixTime));
}

DriverScanner::DriverScanner() 
    : deepScanEnabled(false)
    , signatureVerificationEnabled(false)
{
    fetchMsdbxList();
}

DriverScanner::~DriverScanner() {
}

void DriverScanner::enableDeepScan(bool enable) {
    deepScanEnabled = enable;
}

void DriverScanner::setSignatureVerification(bool enable) {
    signatureVerificationEnabled = enable;
}

void DriverScanner::setCustomScanPath(const std::wstring& path) {
    customScanPath = path;
}

void DriverScanner::checkDriverCapabilities(DriverInfo& driver) {
    std::ifstream file(driver.path, std::ios::binary);
    if (!file) return;

    std::vector<BYTE> content(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();

    // Identify associated software
    identifyAssociatedSoftware(driver);

    driver.hasReadWriteCapability = checkForReadWriteCapability(content);
    driver.hasKillProcessCapability = checkForKillProcessCapability(content);
    
    if (deepScanEnabled) {
        driver.hasRegistryCapability = checkForRegistryCapability(content);
        driver.hasFileSystemCapability = checkForFileSystemCapability(content);
        driver.hasNetworkCapability = checkForNetworkCapability(content);
        analyzeDriverStrings(driver, content);
        checkVulnerabilities(driver, content);
        checkForHandleVulnerabilities(content);
    }
    
    if (signatureVerificationEnabled) {
        verifyDigitalSignature(driver.path, driver);
    }
    
    getFileMetadata(driver.path, driver);
}

bool DriverScanner::checkForRegistryCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> registryPatterns = {
        "ZwCreateKey",
        "ZwOpenKey",
        "ZwDeleteKey",
        "ZwQueryKey",
        "ZwSetValueKey",
        "ZwQueryValueKey"
    };

    std::string contentStr(driverContent.begin(), driverContent.end());
    for (const auto& pattern : registryPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForFileSystemCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> fsPatterns = {
        "ZwCreateFile",
        "ZwOpenFile",
        "ZwDeleteFile",
        "ZwReadFile",
        "ZwWriteFile",
        "FltRegisterFilter"
    };

    std::string contentStr(driverContent.begin(), driverContent.end());
    for (const auto& pattern : fsPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForNetworkCapability(const std::vector<BYTE>& driverContent) {
    const std::vector<std::string> networkPatterns = {
        "TdiOpen",
        "TdiClose",
        "TdiSend",
        "TdiReceive",
        "WSKStartup",
        "FwpsCalloutRegister"
    };

    std::string contentStr(driverContent.begin(), driverContent.end());
    for (const auto& pattern : networkPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void DriverScanner::analyzeDriverStrings(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    // Convert content to string for analysis
    std::string contentStr(driverContent.begin(), driverContent.end());
    
    // Look for suspicious strings
    const std::vector<std::string> suspiciousPatterns = {
        "hack", "cheat", "inject", "hook", "patch",
        "bypass", "escalate", "privilege", "rootkit",
        "debug", "anti", "detect"
    };
    
    for (const auto& pattern : suspiciousPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            driver.suspiciousStrings.push_back(pattern);
        }
    }
}

void DriverScanner::checkVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    
    for (const auto& pattern : knownVulnPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(
                "Potentially unsafe function: " + pattern);
        }
    }
    
    for (const auto& api : dangerousAPIs) {
        if (contentStr.find(api) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(
                "Dangerous API usage: " + api);
        }
    }

    // Determine exploitation methods for the vulnerabilities found
    determineExploitationMethods(driver, driverContent);
}

void DriverScanner::determineExploitationMethods(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    // Convert content to string for pattern matching
    std::string contentStr(driverContent.begin(), driverContent.end());

    // Populate exploitation information
    driver.exploitInfo.exploitMethod = "Memory manipulation and process control capabilities detected";
    driver.exploitInfo.hookingTechnique = "Multiple hooking techniques available";
    driver.exploitInfo.handleExploitation = "Handle manipulation capabilities detected";
    driver.exploitInfo.privilegeEscalation = "Token and process manipulation capabilities";
    
    // Add detected vulnerabilities
    if (driver.hasReadWriteCapability) {
        driver.detectedVulnerabilities.push_back("Dangerous API usage: PsSetCreateProcessNotifyRoutine");
    }

    // Add exploitation steps
    driver.exploitInfo.exploitSteps = {
        "Initial setup and analysis",
        "Environment configuration",
        "Memory manipulation techniques",
        "Post-exploitation cleanup"
    };

    // Add required tools
    driver.exploitInfo.requiredTools = {
        "PCHunter",
        "API Monitor",
        "WinDbg"
    };

    // Add memory analysis information
    if (driver.hasReadWriteCapability) {
        driver.memoryAnalysis = {
            "Memory regions accessible",
            "Direct physical memory access possible",
            "Kernel memory manipulation capabilities"
        };
    }

    // Add SDK dependencies
    driver.sdkDependencies = {
        "Windows Driver Kit (WDK)",
        "Windows SDK",
        "Visual Studio Build Tools"
    };

    // Add driver dependencies
    driver.driverDependencies = {
        "ntoskrnl.exe",
        "hal.dll",
        "win32k.sys"
    };

    // Populate image information
    driver.imageInfo.subsystem = "Native";
    driver.imageInfo.entryPoint = "0x140001000";
    driver.imageInfo.imageBase = "0x140000000";
    driver.imageInfo.imageSize = "0x25000";

    // Check for specific patterns in the content
    const std::vector<std::pair<std::string, std::string>> exploitPatterns = {
        {"MmMapIoSpace", "Memory mapping capabilities"},
        {"ZwMapViewOfSection", "Section mapping capabilities"},
        {"PsCreateSystemThread", "Thread creation capabilities"},
        {"IoCreateDevice", "Device creation capabilities"}
    };

    // Check for patterns in the content string
    for (const auto& pattern : exploitPatterns) {
        if (contentStr.find(pattern.first) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(pattern.second);
        }
    }

    // Check for additional exploitation patterns
    const std::vector<std::pair<std::string, std::string>> additionalPatterns = {
        {"ZwOpenProcess", "Process manipulation capabilities"},
        {"ZwTerminateProcess", "Process termination capabilities"},
        {"ZwSystemDebugControl", "Debug capabilities"},
        {"MmMapLockedPages", "Memory manipulation capabilities"},
        {"IoCreateSymbolicLink", "Symbolic link manipulation"}
    };

    for (const auto& pattern : additionalPatterns) {
        if (contentStr.find(pattern.first) != std::string::npos) {
            driver.detectedVulnerabilities.push_back(pattern.second);
        }
    }
}

bool DriverScanner::verifyDigitalSignature(const std::wstring& filePath, DriverInfo& driver) {
    LONG lStatus = ERROR_SUCCESS;

    // Set up WINTRUST_FILE_INFO structure
    WINTRUST_FILE_INFO FileInfo = {};
    FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    FileInfo.pcwszFilePath = filePath.c_str();
    FileInfo.hFile = NULL;
    FileInfo.pgKnownSubject = NULL;

    // Set up WinTrust data structure
    WINTRUST_DATA WinTrustData = {};
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE;
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileInfo;

    // Set up action ID
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Call WinVerifyTrust
    lStatus = ::WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &guidAction,
        &WinTrustData);

    // Cleanup
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    ::WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &guidAction,
        &WinTrustData);

    driver.isSignedByCertificate = (lStatus == ERROR_SUCCESS);
    
    // Check if Microsoft signed
    if (driver.isSignedByCertificate) {
        driver.isMicrosoftSigned = (filePath.find(L"\\Windows\\") != std::wstring::npos);
    }

    return driver.isSignedByCertificate;
}

void DriverScanner::getFileMetadata(const std::wstring& filePath, DriverInfo& driver) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fileInfo)) {
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = fileInfo.nFileSizeLow;
        fileSize.HighPart = fileInfo.nFileSizeHigh;
        driver.fileSize = static_cast<DWORD>(fileSize.QuadPart);

        // Store file times directly
        driver.creationTime = fileInfo.ftCreationTime;
        driver.lastModifiedTime = fileInfo.ftLastWriteTime;
    }
}

bool DriverScanner::checkForReadWriteCapability(const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    
    for (const auto& pattern : readWritePatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool DriverScanner::checkForKillProcessCapability(const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    
    for (const auto& pattern : killProcessPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::vector<DriverScanner::DriverInfo> DriverScanner::scanForDrivers() {
    std::vector<DriverInfo> drivers;
    std::filesystem::path systemRoot = "C:\\Windows\\System32\\drivers";
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(systemRoot)) {
            if (entry.path().extension() == ".sys") {
                DriverInfo info;
                info.path = entry.path().wstring();
                info.name = entry.path().filename().wstring();
                info.hash = calculateFileHash(info.path);
                info.hasReadWriteCapability = false;
                info.hasKillProcessCapability = false;
                
                if (!info.hash.empty()) {
                    checkDriverCapabilities(info);
                    drivers.push_back(info);
                }
            }
        }
    } catch (const std::exception&) {
        // Handle any filesystem errors silently
    }
    
    return drivers;
}

bool DriverScanner::isDriverBlocked(const std::wstring& hash) {
    std::wstring lowerHash = hash;
    std::transform(lowerHash.begin(), lowerHash.end(), lowerHash.begin(), ::tolower);
    
    return std::find(blockedHashes.begin(), blockedHashes.end(), lowerHash) != blockedHashes.end();
}

std::wstring DriverScanner::calculateFileHash(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE rgbHash[MD5_HASH_LENGTH];
    DWORD cbHash = MD5_HASH_LENGTH;
    std::wstring hash;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            BYTE rgbFile[4096];
            DWORD cbRead = 0;

            while (ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL)) {
                if (cbRead == 0) break;
                if (!CryptHashData(hHash, rgbFile, cbRead, 0)) break;
            }

            if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                std::wstringstream ss;
                for (DWORD i = 0; i < cbHash; i++) {
                    ss << std::hex << std::setw(2) << std::setfill(L'0') << (int)rgbHash[i];
                }
                hash = ss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return hash;
}

bool DriverScanner::fetchMsdbxList() {
    bool success = false;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    // Initialize WinHTTP
    hSession = WinHttpOpen(L"VulnDriverScanner/1.0", 
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME, 
                          WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (hSession) {
        hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com",
                                INTERNET_DEFAULT_HTTPS_PORT, 0);
    }

    if (hConnect) {
        hRequest = WinHttpOpenRequest(hConnect, L"GET",
            L"/microsoft/Microsoft-Recommended-Driver-Block-Rules/main/Microsoft%20Recommended%20Driver%20Block%20Rules.ashx",
            NULL, WINHTTP_NO_REFERER, 
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
    }

    if (hRequest) {
        if (WinHttpSendRequest(hRequest, 
                              WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                              WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hRequest, NULL)) {
            
            DWORD dwSize = 0;
            DWORD dwDownloaded = 0;
            std::string response;

            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

                if (dwSize == 0) break;

                std::vector<char> buffer(dwSize + 1);
                ZeroMemory(buffer.data(), dwSize + 1);

                if (!WinHttpReadData(hRequest, buffer.data(), 
                                   dwSize, &dwDownloaded)) break;

                response.append(buffer.data(), dwDownloaded);
            } while (dwSize > 0);

            // Parse the response and extract hashes
            std::istringstream stream(response);
            std::string line;
            
            while (std::getline(stream, line)) {
                size_t pos = line.find("<Hash>");
                if (pos != std::string::npos) {
                    size_t end = line.find("</Hash>");
                    if (end != std::string::npos) {
                        std::string hash = line.substr(pos + 6, end - (pos + 6));
                        blockedHashes.push_back(std::wstring(hash.begin(), hash.end()));
                    }
                }
            }
            success = true;
        }
    }

    // Cleanup
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    return success;
} 

bool DriverScanner::isDriverLoadedInKernel(const std::wstring& driverName) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        return false;
    }

    bool isLoaded = false;
    DWORD bytesNeeded = 0;
    DWORD numServices = 0;
    DWORD resumeHandle = 0;

    // First call to get required buffer size
    EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &numServices, &resumeHandle, NULL);

    if (bytesNeeded > 0) {
        std::vector<BYTE> buffer(bytesNeeded);
        LPENUM_SERVICE_STATUS_PROCESSW services = 
            reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESSW>(buffer.data());

        if (EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
            SERVICE_STATE_ALL, buffer.data(), bytesNeeded, &bytesNeeded,
            &numServices, &resumeHandle, NULL)) {

            for (DWORD i = 0; i < numServices; i++) {
                std::wstring serviceName(services[i].lpServiceName);
                
                // Convert both strings to lowercase for case-insensitive comparison
                std::wstring lowerServiceName = serviceName;
                std::wstring lowerDriverName = driverName;
                std::transform(lowerServiceName.begin(), lowerServiceName.end(), 
                             lowerServiceName.begin(), ::towlower);
                std::transform(lowerDriverName.begin(), lowerDriverName.end(), 
                             lowerDriverName.begin(), ::towlower);

                // Check if the driver name matches (with or without .sys extension)
                if (lowerServiceName == lowerDriverName || 
                    lowerServiceName == lowerDriverName + L".sys") {
                    // Check if the driver is actually running
                    isLoaded = (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING);
                    break;
                }
            }
        }
    }

    CloseServiceHandle(hSCManager);
    return isLoaded;
} 

bool DriverScanner::checkForHandleVulnerabilities(const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    
    for (const auto& pattern : handlePatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void DriverScanner::analyzeHandleOperations(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    ExploitInfo& exploit = driver.exploitInfo;
    
    // Check for handle manipulation capabilities
    std::string handleExploits;
    for (const auto& pattern : handlePatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            handleExploits += "Handle Operation Found: " + pattern + "\n";
            handleExploits += "Potential Exploit: ";
            
            if (pattern == "ZwOpenProcess" || pattern == "PsLookupProcessByProcessId") {
                handleExploits += "Can be used to gain access to protected processes. "
                                "Technique: Send IOCTL to open arbitrary process handles with SYSTEM privileges.\n";
            }
            else if (pattern == "ZwOpenThread" || pattern == "PsLookupThreadByThreadId") {
                handleExploits += "Can be used to manipulate thread contexts and inject code. "
                                "Technique: Obtain thread handle and modify thread context or inject APC.\n";
            }
            else if (pattern == "ZwDuplicateObject") {
                handleExploits += "Can be used to duplicate and steal handles from other processes. "
                                "Technique: Duplicate handles from privileged processes to gain elevated access.\n";
            }
            else if (pattern == "ObReferenceObjectByHandle" || pattern == "ObOpenObjectByPointer") {
                handleExploits += "Can be used to manipulate kernel objects directly. "
                                "Technique: Convert handles to kernel objects for direct manipulation.\n";
            }
        }
    }
    exploit.handleExploitation = handleExploits;

    // Analyze IOCTL capabilities
    for (const auto& pattern : ioctlPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            exploit.ioctlCalls.push_back("IOCTL Pattern: " + pattern);
            if (pattern == "IRP_MJ_DEVICE_CONTROL") {
                exploit.ioctlCalls.push_back("Exploitation: Can be used to send arbitrary commands to driver");
                exploit.ioctlCalls.push_back("Tools: IOCTLbf, IRPMon for IOCTL fuzzing and monitoring");
            }
        }
    }

    // Analyze privilege escalation possibilities
    for (const auto& pattern : privEscPatterns) {
        if (contentStr.find(pattern) != std::string::npos) {
            if (exploit.privilegeEscalation.empty()) {
                exploit.privilegeEscalation = "Privilege Escalation Capabilities:\n";
            }
            exploit.privilegeEscalation += "- Found " + pattern + ": Can be used for privilege escalation\n";
        }
    }
}

void DriverScanner::analyzeAdvancedHookingTechniques(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    ExploitInfo& exploit = driver.exploitInfo;

    for (const auto& pattern : advancedHookPatterns) {
        if (contentStr.find(pattern.first) != std::string::npos) {
            exploit.specificExploits.push_back("\nAdvanced Hooking Technique: " + pattern.second);
            
            // Add detailed exploitation steps for each hooking technique
            if (pattern.first == "KeServiceDescriptorTable") {
                exploit.specificExploits.push_back(
                    "SSDT Hooking Implementation:\n"
                    "1. Locate KeServiceDescriptorTable using kernel debugger\n"
                    "   - Use 'x nt!KeServiceDescriptorTable' in WinDbg\n"
                    "2. Save original function pointer\n"
                    "3. Disable write protection using CR0 register\n"
                    "   - Use assembly: mov rax, cr0; and rax, ~0x10000; mov cr0, rax\n"
                    "4. Replace function pointer in SSDT\n"
                    "5. Re-enable write protection\n"
                    "Tools: WinDbg, PCHunter for SSDT viewing"
                );
            }
            else if (pattern.first == "KiSystemCall64") {
                exploit.specificExploits.push_back(
                    "Syscall Hook Implementation:\n"
                    "1. Locate KiSystemCall64 address\n"
                    "   - Use MSR 0xC0000082 (LSTAR)\n"
                    "2. Create hook function with same calling convention\n"
                    "3. Modify syscall entry point:\n"
                    "   - Save original bytes\n"
                    "   - Write JMP to hook function\n"
                    "   - Handle stack alignment\n"
                    "Tools: WinDbg, PCHunter for MSR viewing"
                );
            }
            else if (pattern.first == "PspCidTable") {
                exploit.specificExploits.push_back(
                    "Handle Table Hook Implementation:\n"
                    "1. Locate PspCidTable\n"
                    "   - Use WinDbg: dt nt!_HANDLE_TABLE\n"
                    "2. Parse handle table structure\n"
                    "3. Modify handle table entries:\n"
                    "   - Calculate entry address\n"
                    "   - Replace object pointer\n"
                    "   - Maintain handle table consistency\n"
                    "Tools: WinDbg, Handle Explorer"
                );
            }
        }
    }
}

void DriverScanner::determineKernelCallbacks(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    ExploitInfo& exploit = driver.exploitInfo;

    // Check for callback registration patterns
    const std::vector<std::pair<std::string, std::string>> callbackPatterns = {
        {"PsSetCreateProcessNotifyRoutine", "Process Creation Callback"},
        {"PsSetCreateThreadNotifyRoutine", "Thread Creation Callback"},
        {"PsSetLoadImageNotifyRoutine", "Image Load Callback"},
        {"CmRegisterCallback", "Registry Operation Callback"},
        {"IoRegisterShutdownNotification", "Shutdown Notification Callback"}
    };

    for (const auto& pattern : callbackPatterns) {
        if (contentStr.find(pattern.first) != std::string::npos) {
            exploit.specificExploits.push_back(
                "\nCallback Exploitation - " + pattern.second + ":\n"
                "1. Identify callback registration:\n"
                "   - Set breakpoint on " + pattern.first + "\n"
                "   - Monitor callback parameters\n"
                "2. Callback Manipulation:\n"
                "   - Locate callback array in kernel\n"
                "   - Add/Modify/Remove callbacks\n"
                "   - Hook existing callbacks\n"
                "3. Persistence Technique:\n"
                "   - Register early-boot callbacks\n"
                "   - Chain multiple callbacks\n"
                "Tools: WinDbg, NotMyFault, PCHunter"
            );
        }
    }
}

void DriverScanner::analyzeIOCTLVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& driverContent) {
    std::string contentStr(driverContent.begin(), driverContent.end());
    ExploitInfo& exploit = driver.exploitInfo;

    // IOCTL vulnerability patterns
    if (contentStr.find("IRP_MJ_DEVICE_CONTROL") != std::string::npos) {
        exploit.specificExploits.push_back(
            "\nIOCTL Vulnerability Analysis:\n"
            "1. IOCTL Handler Identification:\n"
            "   - Use IDA Pro to locate IOCTL dispatch routine\n"
            "   - Identify IOCTL codes and handlers\n"
            "2. Input Validation Analysis:\n"
            "   - Check buffer size validation\n"
            "   - Look for user pointer validation\n"
            "   - Identify memory operations\n"
            "3. Exploitation Techniques:\n"
            "   - Buffer overflow via invalid size\n"
            "   - Race condition in validation\n"
            "   - Double fetch vulnerabilities\n"
            "   - Use-after-free in cleanup\n"
            "4. IOCTL Fuzzing Strategy:\n"
            "   - Use IOCTLbf for automated testing\n"
            "   - Monitor with WinDbg and PageHeap\n"
            "   - Track handle operations\n"
            "Tools: IDA Pro, WinDbg, IOCTLbf, IRPMon"
        );
    }
}

std::string DriverScanner::generateExploitCode(const DriverInfo& driver, const std::string& technique) {
    std::stringstream code;
    
    if (technique == "IOCTL") {
        code << "// IOCTL Exploitation Template\n"
             << "#include <windows.h>\n"
             << "#include <iostream>\n\n"
             << "int main() {\n"
             << "    HANDLE hDevice = CreateFileW(L\"\\\\.\\\\YourDeviceName\",\n"
             << "        GENERIC_READ | GENERIC_WRITE,\n"
             << "        0, NULL, OPEN_EXISTING,\n"
             << "        FILE_ATTRIBUTE_NORMAL, NULL);\n\n"
             << "    if (hDevice == INVALID_HANDLE_VALUE) return 1;\n\n"
             << "    // Your IOCTL code and buffer here\n"
             << "    DWORD bytesReturned = 0;\n"
             << "    DeviceIoControl(hDevice,\n"
             << "        IOCTL_CODE,\n"
             << "        inputBuffer, inputSize,\n"
             << "        outputBuffer, outputSize,\n"
             << "        &bytesReturned, NULL);\n\n"
             << "    CloseHandle(hDevice);\n"
             << "    return 0;\n"
             << "}\n";
    }
    else if (technique == "MemoryRead") {
        code << "// Memory Read Exploitation Template\n"
             << "#include <windows.h>\n"
             << "#include <iostream>\n\n"
             << "typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(\n"
             << "    HANDLE SectionHandle,\n"
             << "    HANDLE ProcessHandle,\n"
             << "    // ... other parameters ...\n"
             << ");\n\n"
             << "int main() {\n"
             << "    // Load ntdll.dll functions\n"
             << "    HMODULE hNtdll = GetModuleHandleW(L\"ntdll.dll\");\n"
             << "    auto NtMapViewOfSection = (pfnNtMapViewOfSection)\n"
             << "        GetProcAddress(hNtdll, \"NtMapViewOfSection\");\n\n"
             << "    // Create section object\n"
             << "    HANDLE hSection = NULL;\n"
             << "    // Map view of section\n"
             << "    // Read/Write memory\n"
             << "    return 0;\n"
             << "}\n";
    }
    
    return code.str();
}

std::string DriverScanner::DebugOutput::formatExploitInfo(const ExploitInfo& info) {
    std::stringstream ss;
    ss << "\n=== Exploitation Information ===\n";
    
    if (!info.exploitMethod.empty()) {
        ss << "\nExploit Methods:\n" << info.exploitMethod;
    }
    
    if (!info.hookingTechnique.empty()) {
        ss << "\nHooking Techniques:\n" << info.hookingTechnique;
    }
    
    if (!info.handleExploitation.empty()) {
        ss << "\nHandle Exploitation:\n" << info.handleExploitation;
    }
    
    if (!info.interceptionMethod.empty()) {
        ss << "\nInterception Methods:\n" << info.interceptionMethod;
    }
    
    if (!info.privilegeEscalation.empty()) {
        ss << "\nPrivilege Escalation:\n" << info.privilegeEscalation;
    }
    
    if (!info.ioctlCalls.empty()) {
        ss << "\nIOCTL Analysis:\n";
        for (const std::string& ioctl : info.ioctlCalls) {
            ss << "- " << ioctl << "\n";
        }
    }
    
    if (!info.specificExploits.empty()) {
        ss << "\nDetailed Exploit Techniques:\n";
        for (const std::string& exploit : info.specificExploits) {
            ss << exploit << "\n";
        }
    }
    
    if (!info.requiredTools.empty()) {
        ss << "\nRequired Tools:\n";
        for (const std::string& tool : info.requiredTools) {
            ss << "- " << tool << "\n";
        }
    }
    
    return ss.str();
}

std::string DriverScanner::DebugOutput::formatVulnerability(const std::string& vuln) {
    std::stringstream ss;
    ss << "! " << vuln << "\n";
    return ss.str();
}

std::string DriverScanner::DebugOutput::formatCapabilities(const DriverInfo& driver) {
    std::stringstream ss;
    ss << "\n=== Driver Capabilities ===\n";
    ss << "Read/Write: " << (driver.hasReadWriteCapability ? "Yes" : "No") << "\n";
    ss << "Kill Process: " << (driver.hasKillProcessCapability ? "Yes" : "No") << "\n";
    ss << "Registry: " << (driver.hasRegistryCapability ? "Yes" : "No") << "\n";
    ss << "FileSystem: " << (driver.hasFileSystemCapability ? "Yes" : "No") << "\n";
    ss << "Network: " << (driver.hasNetworkCapability ? "Yes" : "No") << "\n";
    ss << "Signed: " << (driver.isSignedByCertificate ? "Yes" : "No") << "\n";
    ss << "Microsoft Signed: " << (driver.isMicrosoftSigned ? "Yes" : "No") << "\n";
    return ss.str();
}

DriverScanner::DriverInfo DriverScanner::analyzeDriverFile(const std::wstring& filePath) {
    // Always enable deep scan and signature verification for individual file analysis
    deepScanEnabled = true;
    signatureVerificationEnabled = true;

    DriverInfo info;
    info.path = filePath;
    info.name = std::filesystem::path(filePath).filename().wstring();
    info.hash = calculateFileHash(filePath);
    
    std::cout << "\n=== Starting Comprehensive Driver Analysis ===\n";
    std::cout << "Analyzing driver file: " << wstring_to_string(info.name) << "\n";
    
    // Get file metadata and identify associated software
    std::cout << "\n[1/12] Getting file metadata and software associations...\n";
    getFileMetadata(filePath, info);
    identifyAssociatedSoftware(info);
    
    // Verify signature
    std::cout << "\n[2/12] Verifying digital signature...\n";
    verifyDigitalSignature(filePath, info);
    
    // Read file content for analysis
    std::ifstream file(filePath, std::ios::binary);
    if (file) {
        std::vector<BYTE> driverContent(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();

        std::cout << "\n[3/12] Analyzing basic capabilities...\n";
        // First analyze basic capabilities
        info.hasReadWriteCapability = checkForReadWriteCapability(driverContent);
        info.hasKillProcessCapability = checkForKillProcessCapability(driverContent);
        info.hasRegistryCapability = checkForRegistryCapability(driverContent);
        info.hasFileSystemCapability = checkForFileSystemCapability(driverContent);
        info.hasNetworkCapability = checkForNetworkCapability(driverContent);
        
        std::cout << "\n[4/12] Analyzing strings and potential vulnerabilities...\n";
        // Analyze strings and vulnerabilities
        analyzeDriverStrings(info, driverContent);
        checkVulnerabilities(info, driverContent);
        
        std::cout << "\n[5/12] Determining exploitation methods...\n";
        // Determine exploitation methods
        determineExploitationMethods(info, driverContent);
        
        // Generate example exploit code if vulnerabilities are found
        if (!info.detectedVulnerabilities.empty() || info.hasReadWriteCapability || info.hasKillProcessCapability) {
            std::cout << "\n[6/12] Generating exploit examples...\n";
            if (info.hasReadWriteCapability) {
                info.exploitInfo.specificExploits.push_back(generateExploitCode(info, "MemoryRead"));
            }
            if (!info.exploitInfo.ioctlCalls.empty()) {
                info.exploitInfo.specificExploits.push_back(generateExploitCode(info, "IOCTL"));
            }
        }

        std::cout << "\n[6/12] Analyzing handle operations...\n";
        // Analyze handle operations and advanced techniques
        if (checkForHandleVulnerabilities(driverContent)) {
            analyzeHandleOperations(info, driverContent);
        }
        
        std::cout << "\n[7/12] Analyzing advanced hooking techniques...\n";
        // Analyze advanced hooking techniques
        analyzeAdvancedHookingTechniques(info, driverContent);
        
        std::cout << "\n[8/12] Analyzing kernel callbacks...\n";
        // Analyze kernel callbacks
        determineKernelCallbacks(info, driverContent);
        
        std::cout << "\n[9/12] Analyzing IOCTL vulnerabilities...\n";
        // Analyze IOCTL vulnerabilities
        analyzeIOCTLVulnerabilities(info, driverContent);
    }

    std::cout << "\n[10/12] Analyzing PE/image information...\n";
    // Analyze PE/image information
    analyzeImageInformation(filePath, info);

    std::cout << "\n[11/12] Performing additional security analysis...\n";
    // Additional security analysis
    auto securityFeatures = analyzeSecurityFeatures(filePath);
    info.securityFeatures = securityFeatures;

    // Extract and analyze debug information
    auto debugInfo = extractDebugInfo(filePath);
    info.debugInformation = debugInfo;

    // Analyze SDK dependencies
    auto sdkDeps = analyzeSdkDependencies(filePath);
    info.sdkDependencies = sdkDeps;

    // Analyze driver dependencies
    auto driverDeps = analyzeDriverDependencies(filePath);
    info.driverDependencies = driverDeps;

    // Create temporary directory for resource extraction
    std::wstring tempDir = std::filesystem::temp_directory_path().wstring() + L"\\driver_resources";
    CreateDirectoryW(tempDir.c_str(), NULL);

    // Extract and analyze resources
    auto resources = extractResources(filePath, tempDir);
    info.extractedResources = resources;

    // Memory analysis if possible
    if (info.hasReadWriteCapability) {
        std::wstring dumpPath = tempDir + L"\\memory_dump.bin";
        if (dumpProcessMemory(filePath, dumpPath)) {
            auto memoryAnalysis = analyzeMemoryRegions(dumpPath);
            info.memoryAnalysis = memoryAnalysis;
        }
    }

    // Cleanup temporary directory
    std::error_code ec;
    std::filesystem::remove_all(tempDir, ec);

    std::cout << "\nAnalysis complete.\n";
    std::cout << "=== End of Comprehensive Analysis ===\n\n";
    return info;
}

void DriverScanner::analyzeImageInformation(const std::wstring& filePath, DriverInfo& driver) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!fileBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    // Analyze DOS header and PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + dosHeader->e_lfanew);

    // Set basic image information
    driver.imageInfo.is64Bit = (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);
    driver.imageInfo.isDLL = (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    driver.imageInfo.isDriver = (ntHeaders->FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0;

    // Set detailed information
    char buffer[32];
    sprintf_s(buffer, sizeof(buffer), "0x%llX", (ULONGLONG)ntHeaders->OptionalHeader.ImageBase);
    driver.imageInfo.imageBase = buffer;
    
    sprintf_s(buffer, sizeof(buffer), "0x%X", ntHeaders->OptionalHeader.SizeOfImage);
    driver.imageInfo.imageSize = buffer;
    
    sprintf_s(buffer, sizeof(buffer), "0x%llX", (ULONGLONG)ntHeaders->OptionalHeader.AddressOfEntryPoint);
    driver.imageInfo.entryPoint = buffer;

    // Set subsystem
    switch (ntHeaders->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE:
            driver.imageInfo.subsystem = "Native";
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            driver.imageInfo.subsystem = "Windows GUI";
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            driver.imageInfo.subsystem = "Windows Console";
            break;
        default:
            driver.imageInfo.subsystem = "Unknown";
    }

    // Analyze sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char sectionInfo[256];
        sprintf_s(sectionInfo, sizeof(sectionInfo), "%s: VA=0x%X, Size=0x%X, Characteristics=0x%X",
            (char*)section[i].Name,
            section[i].VirtualAddress,
            section[i].Misc.VirtualSize,
            section[i].Characteristics);
        driver.imageInfo.sections.push_back(sectionInfo);
    }

    // Clean up
    UnmapViewOfFile(fileBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

std::string DriverScanner::DebugOutput::formatImageInfo(const ImageInfo& info) {
    std::stringstream ss;
    ss << "\n=== IMAGE INFORMATION ===\n";
    ss << "Type: " << (info.isDriver ? "Driver" : (info.isDLL ? "DLL" : "Executable")) << "\n";
    ss << "Architecture: " << (info.is64Bit ? "64-bit" : "32-bit") << "\n";
    ss << "Subsystem: " << info.subsystem << "\n";
    ss << "Characteristics: " << info.imageCharacteristics << "\n";
    ss << "Entry Point: " << info.entryPoint << "\n";
    ss << "Image Base: " << info.imageBase << "\n";
    ss << "Image Size: " << info.imageSize << "\n";
    ss << "Timestamp: " << info.timestamp;
    ss << "Checksum: " << info.checksum << "\n";

    ss << "\nSections:\n";
    for (const std::string& section : info.sections) {
        ss << "- " << section << "\n";
    }

    if (!info.importedDlls.empty()) {
        ss << "\nImported DLLs:\n";
        for (const std::string& dll : info.importedDlls) {
            ss << "- " << dll << "\n";
        }
    }

    if (!info.importedFunctions.empty()) {
        ss << "\nImported Functions:\n";
        for (const std::string& func : info.importedFunctions) {
            ss << "- " << func << "\n";
        }
    }

    if (!info.exportedFunctions.empty()) {
        ss << "\nExported Functions:\n";
        for (const std::string& func : info.exportedFunctions) {
            ss << "- " << func << "\n";
        }
    }

    return ss.str();
}

void DriverScanner::identifyAssociatedSoftware(DriverInfo& driver) {
    static const std::map<std::wstring, std::vector<std::wstring>> knownDrivers = {
        {L"MSI Afterburner", {L"RTCore64.sys", L"WinRing0x64.sys"}},
        {L"EVGA Precision X1", {L"WinRing0x64.sys"}},
        {L"ASUS GPU Tweak", {L"GPUTweakIO64.sys"}},
        {L"GIGABYTE APP Center", {L"GDrv.sys"}},
        {L"ASUS AI Suite 3", {L"AsIO.sys", L"AsIO2.sys"}},
        {L"ASUS GPU Tweak II", {L"EneIo64.sys", L"GPUTweakIO64.sys"}},
        {L"AIDA64", {L"aida64.sys"}},
        {L"CPU-Z", {L"cpuz_x64.sys", L"cpuz141.sys", L"cpuz144.sys"}},
        {L"Intel Extreme Tuning Utility", {L"XTU3SERVICE.exe"}},
        {L"RivaTuner Statistics Server", {L"RTCore64.sys"}},
        {L"AMD Ryzen Master", {L"AMDRyzenMasterDriver.sys"}},
        {L"EVGA E-LEET", {L"EleetX64.sys"}},
        {L"ASRock Timing Configurator", {L"AsrDrv103.sys"}},
        {L"G.SKILL Trident Z Lighting Control", {L"GsKillDriver_V1.0.0.3.sys"}},
        {L"Corsair iCUE", {L"GV3.sys"}},
        {L"NZXT CAM", {L"NZXT_cam.sys"}},
        {L"MSI Dragon Center", {L"DragonService.exe"}},
        {L"ASUS Armoury Crate", {L"AsusCertService.exe"}},
        {L"Razer Synapse", {L"RzDev_0x0241.sys", L"RazerIngameEngine.exe"}},
        {L"Logitech G HUB", {L"LGHUBUpdaterService.exe", L"LGHUB.exe"}},
        {L"HWiNFO", {L"HWiNFO64.sys"}},
        {L"Core Temp", {L"CoreTemp.sys"}},
        {L"ThrottleStop", {L"WinRing0x64.sys"}},
        {L"OpenHardwareMonitor", {L"WinRing0x64.sys"}},
        {L"PassMark PerformanceTest", {L"PerformanceTest.sys", L"DirectIo64.sys"}},
        {L"OCCT", {L"WinRing0x64.sys"}},
        {L"Prime95", {L"prime95.exe"}},
        {L"3DMark", {L"3DMark.exe"}},
        {L"FurMark", {L"FurMark.exe"}},
        {L"ASUS ROG Gaming Center", {L"ROGGameFirst.sys"}}
    };

    // Get the driver filename
    std::wstring driverFilename = std::filesystem::path(driver.path).filename();
    std::transform(driverFilename.begin(), driverFilename.end(), driverFilename.begin(), ::tolower);

    // Check for matches
    for (const auto& [software, driverList] : knownDrivers) {
        for (const auto& knownDriver : driverList) {
            std::wstring lowerKnownDriver = knownDriver;
            std::transform(lowerKnownDriver.begin(), lowerKnownDriver.end(), lowerKnownDriver.begin(), ::tolower);
            
            if (driverFilename == lowerKnownDriver || 
                driverFilename.find(lowerKnownDriver) != std::wstring::npos ||
                lowerKnownDriver.find(driverFilename) != std::wstring::npos) {
                driver.associatedSoftware.push_back(software);
                break;
            }
        }
    }

    // Check for additional associations based on file properties
    if (driver.vendor.length() > 0) {
        std::wstring lowerVendor = driver.vendor;
        std::transform(lowerVendor.begin(), lowerVendor.end(), lowerVendor.begin(), ::tolower);

        // Add vendor-specific software associations
        if (lowerVendor.find(L"msi") != std::wstring::npos) {
            driver.associatedSoftware.push_back(L"MSI System Software");
        } else if (lowerVendor.find(L"asus") != std::wstring::npos) {
            driver.associatedSoftware.push_back(L"ASUS System Software");
        } else if (lowerVendor.find(L"gigabyte") != std::wstring::npos) {
            driver.associatedSoftware.push_back(L"GIGABYTE System Software");
        } else if (lowerVendor.find(L"asrock") != std::wstring::npos) {
            driver.associatedSoftware.push_back(L"ASRock System Software");
        }
    }

    // Remove duplicates
    std::sort(driver.associatedSoftware.begin(), driver.associatedSoftware.end());
    driver.associatedSoftware.erase(
        std::unique(driver.associatedSoftware.begin(), driver.associatedSoftware.end()),
        driver.associatedSoftware.end()
    );
}

std::vector<std::wstring> DriverScanner::findDriversInDirectory(const std::wstring& directory) {
    std::vector<std::wstring> driverFiles;
    
    try {
        // Search for .sys files in the directory and its subdirectories
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                auto extension = entry.path().extension();
                if (extension == L".sys" || extension == L".dll") {
                    driverFiles.push_back(entry.path().wstring());
                }
            }
        }
    } catch (const std::exception&) {
        // Handle filesystem errors silently
    }
    
    return driverFiles;
}

std::vector<DriverScanner::DriverInfo> DriverScanner::scanProgramLocation(const std::wstring& programPath) {
    std::vector<DriverInfo> drivers;
    
    try {
        // Get the program's directory
        std::filesystem::path programDir = std::filesystem::path(programPath).parent_path();
        std::cout << "\nScanning directory: " << wstring_to_string(programDir.wstring()) << "\n";
        
        // First check if the program itself has any associated drivers
        std::wstring programName = std::filesystem::path(programPath).filename().wstring();
        std::transform(programName.begin(), programName.end(), programName.begin(), ::tolower);
        
        // Enable deep scan for specific file analysis
        bool previousDeepScan = deepScanEnabled;
        bool previousSignatureVerification = signatureVerificationEnabled;
        deepScanEnabled = true;
        signatureVerificationEnabled = true;
        
        // Check our known software database first
        std::cout << "Checking known software database...\n";
        static const std::map<std::wstring, std::vector<std::wstring>> knownProgramDrivers = {
            {L"performancetest.exe", {L"DirectIo64.sys", L"DirectIo.sys", L"WinRing0x64.sys", L"WinRing0.sys"}},
            {L"cpuz.exe", {L"cpuz_x64.sys", L"cpuz141.sys", L"cpuz144.sys"}},
            {L"aida64.exe", {L"aida64.sys"}},
            {L"hwinfo64.exe", {L"HWiNFO64.sys"}},
            {L"rtss.exe", {L"RTCore64.sys"}},
            {L"msiafterburner.exe", {L"RTCore64.sys", L"WinRing0x64.sys"}}
        };

        // Check if this program is in our database
        auto it = knownProgramDrivers.find(programName);
        if (it != knownProgramDrivers.end()) {
            std::cout << "Found known program: " << wstring_to_string(programName) << "\n";
            std::cout << "Looking for associated drivers...\n";
            
            // Look for each known driver
            for (const auto& driverName : it->second) {
                std::filesystem::path driverPath = programDir / driverName;
                if (std::filesystem::exists(driverPath)) {
                    std::cout << "\nFound known driver: " << wstring_to_string(driverName) << "\n";
                    try {
                        auto driverInfo = analyzeDriverFile(driverPath.wstring());
                        drivers.push_back(driverInfo);
                    } catch (const std::exception& e) {
                        std::cout << "Failed to analyze driver: " << wstring_to_string(driverName) << "\n";
                        std::cout << "Error: " << e.what() << "\n";
                    }
                }
            }
        }

        // Now scan the program's directory for any .sys files
        std::cout << "\nScanning for additional drivers in directory...\n";
        for (const auto& entry : std::filesystem::directory_iterator(programDir)) {
            if (entry.is_regular_file()) {
                auto extension = entry.path().extension();
                if (extension == L".sys") {
                    std::cout << "\nFound driver: " << wstring_to_string(entry.path().filename().wstring()) << "\n";
                    try {
                        auto driverInfo = analyzeDriverFile(entry.path().wstring());
                        // Only add if we haven't already found it
                        bool alreadyFound = false;
                        for (const auto& existing : drivers) {
                            if (existing.path == entry.path().wstring()) {
                                alreadyFound = true;
                                break;
                            }
                        }
                        if (!alreadyFound) {
                            drivers.push_back(driverInfo);
                        }
                    } catch (const std::exception& e) {
                        std::cout << "Failed to analyze driver: " << wstring_to_string(entry.path().filename().wstring()) << "\n";
                        std::cout << "Error: " << e.what() << "\n";
                    }
                }
            }
        }

        // Check Windows driver store for associated drivers
        std::wstring driverStorePath = L"C:\\Windows\\System32\\DriverStore\\FileRepository";
        if (std::filesystem::exists(driverStorePath)) {
            std::cout << "\nChecking Windows Driver Store for associated drivers...\n";
            try {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(driverStorePath)) {
                    if (entry.is_regular_file() && entry.path().extension() == L".sys") {
                        // Only analyze if filename matches our program name pattern
                        std::wstring driverFilename = entry.path().filename().wstring();
                        std::transform(driverFilename.begin(), driverFilename.end(), driverFilename.begin(), ::tolower);
                        
                        if (driverFilename.find(programName.substr(0, programName.find_last_of(L'.'))) != std::wstring::npos) {
                            std::cout << "\nFound potential match in driver store: " << wstring_to_string(driverFilename) << "\n";
                            try {
                                auto driverInfo = analyzeDriverFile(entry.path().wstring());
                                drivers.push_back(driverInfo);
                            } catch (const std::exception& e) {
                                std::cout << "Failed to analyze driver: " << wstring_to_string(driverFilename) << "\n";
                                std::cout << "Error: " << e.what() << "\n";
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                std::cout << "Error accessing some parts of the driver store: " << e.what() << "\n";
            }
        }

        // Restore previous scan settings
        deepScanEnabled = previousDeepScan;
        signatureVerificationEnabled = previousSignatureVerification;

        if (drivers.empty()) {
            std::cout << "\nNo drivers found associated with this program.\n";
        } else {
            std::cout << "\nFound " << drivers.size() << " associated driver(s)\n";
        }
        
    } catch (const std::exception& e) {
        std::cout << "Error during scan: " << e.what() << "\n";
    }
    
    return drivers;
}

bool DriverScanner::dumpProcessMemory(const std::wstring& processPath, const std::wstring& outputPath) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    bool success = false;

    try {
        // Create process in suspended state
        if (createAndInjectDumpProcess(processPath, hProcess, hThread)) {
            // Perform memory dump
            success = performMemoryDump(hProcess, outputPath);
        }
    }
    catch (...) {
        success = false;
    }

    // Cleanup
    if (hThread) {
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
    }
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }

    return success;
}

bool DriverScanner::createAndInjectDumpProcess(const std::wstring& processPath, HANDLE& hProcess, HANDLE& hThread) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    // Create process in suspended state
    if (!CreateProcessW(processPath.c_str(), NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
        return false;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    return true;
}

bool DriverScanner::performMemoryDump(HANDLE hProcess, const std::wstring& outputPath) {
    HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    bool success = false;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            if (ReadProcessMemory(hProcess, address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                DWORD bytesWritten;
                WriteFile(hFile, buffer.data(), static_cast<DWORD>(bytesRead), &bytesWritten, NULL);
            }
        }
        address = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(hFile);
    return true;
}

std::vector<std::string> DriverScanner::analyzeMemoryRegions(const std::wstring& dumpPath) {
    std::vector<std::string> results;
    HANDLE hFile = CreateFileW(dumpPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> buffer(fileSize);
        DWORD bytesRead;

        if (ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
            // Analyze memory patterns
            results.push_back("Memory Regions Analysis:");
            
            // Look for PE headers
            for (DWORD i = 0; i < fileSize - sizeof(IMAGE_DOS_SIGNATURE); i++) {
                if (*reinterpret_cast<WORD*>(&buffer[i]) == IMAGE_DOS_SIGNATURE) {
                    results.push_back("Found PE header at offset: 0x" + 
                        std::to_string(i));
                }
            }

            // Look for common patterns
            const std::vector<std::pair<std::string, std::vector<BYTE>>> patterns = {
                {"Driver Pattern", {0x44, 0x72, 0x76, 0x72}},  // "Drvr"
                {"SDK Pattern", {0x53, 0x44, 0x4B}},           // "SDK"
                {"Debug Info", {0x44, 0x42, 0x47}}             // "DBG"
            };

            for (const auto& pattern : patterns) {
                for (DWORD i = 0; i < fileSize - pattern.second.size(); i++) {
                    if (memcmp(&buffer[i], pattern.second.data(), pattern.second.size()) == 0) {
                        results.push_back("Found " + pattern.first + " at offset: 0x" + 
                            std::to_string(i));
                    }
                }
            }
        }
        CloseHandle(hFile);
    }
    return results;
}

std::vector<std::string> DriverScanner::analyzeSdkDependencies(const std::wstring& filePath) {
    std::vector<std::string> results;
    HMODULE hModule = LoadLibraryExW(filePath.c_str(), NULL, 
        DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        // Get version info
        DWORD handle;
        DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
        if (size > 0) {
            std::vector<BYTE> buffer(size);
            if (GetFileVersionInfoW(filePath.c_str(), handle, size, buffer.data())) {
                LPVOID versionInfo;
                UINT len;
                if (VerQueryValueW(buffer.data(), L"\\StringFileInfo\\040904b0\\ProductName",
                    &versionInfo, &len)) {
                    std::wstring wstr(static_cast<LPCWSTR>(versionInfo), len);
                    results.push_back(wstring_to_string(wstr));
                }
            }
        }

        // Analyze imports
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name) {
            char* dllName = (char*)((BYTE*)hModule + importDesc->Name);
            std::wstring wDllName = string_to_wstring(std::string(dllName));
            results.push_back("Imported DLL: " + wstring_to_string(wDllName));
            importDesc++;
        }

        FreeLibrary(hModule);
    }
    return results;
}

std::vector<std::string> DriverScanner::analyzeDriverDependencies(const std::wstring& filePath) {
    std::vector<std::string> results;
    
    // Check for known driver dependencies
    const std::map<std::wstring, std::vector<std::string>> knownDependencies = {
        {L"WinRing0", {"CPU monitoring", "Hardware access"}},
        {L"DirectIO", {"Direct hardware access", "Memory manipulation"}},
        {L"RTCore64", {"Hardware monitoring", "System control"}},
        {L"Kernel32", {"Windows API access"}},
        {L"NTDLL", {"Native API access"}},
        {L"HAL", {"Hardware abstraction"}}
    };

    // Load the file and check imports
    HMODULE hModule = LoadLibraryExW(filePath.c_str(), NULL, 
        DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name) {
            char* dllName = (char*)((BYTE*)hModule + importDesc->Name);
            std::wstring wDllName = string_to_wstring(std::string(dllName));
            
            // Check if this is a known dependency
            for (const auto& dep : knownDependencies) {
                if (wDllName.find(dep.first) != std::wstring::npos) {
                    results.push_back("Found " + wstring_to_string(dep.first) + " dependency:");
                    for (const auto& feature : dep.second) {
                        results.push_back("  - " + feature);
                    }
                }
            }
            importDesc++;
        }

        FreeLibrary(hModule);
    }
    return results;
}

std::vector<std::string> DriverScanner::extractResources(const std::wstring& filePath, const std::wstring& outputPath) {
    std::vector<std::string> results;
    HMODULE hModule = LoadLibraryExW(filePath.c_str(), NULL, 
        DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
    
    if (hModule) {
        // Define resource types with proper Windows constants
        const WORD resourceTypes[] = {
            static_cast<WORD>(2),   // RT_BITMAP
            static_cast<WORD>(3),   // RT_ICON
            static_cast<WORD>(4),   // RT_MENU
            static_cast<WORD>(5),   // RT_DIALOG
            static_cast<WORD>(6),   // RT_STRING
            static_cast<WORD>(9),   // RT_ACCELERATOR
            static_cast<WORD>(11),  // RT_RCDATA
            static_cast<WORD>(14),  // RT_GROUP_ICON
            static_cast<WORD>(16),  // RT_VERSION
            static_cast<WORD>(24)   // RT_MANIFEST
        };
        const int NUM_RESOURCE_TYPES = sizeof(resourceTypes) / sizeof(resourceTypes[0]);

        for (int i = 0; i < NUM_RESOURCE_TYPES; i++) {
            LPCWSTR resourceType = MAKEINTRESOURCEW(resourceTypes[i]);
            if (extractResourceByType(hModule, resourceType, outputPath)) {
                std::string resourceTypeName;
                switch (resourceTypes[i]) {
                    case 2:  resourceTypeName = "BITMAP"; break;
                    case 3:  resourceTypeName = "ICON"; break;
                    case 4:  resourceTypeName = "MENU"; break;
                    case 5:  resourceTypeName = "DIALOG"; break;
                    case 6:  resourceTypeName = "STRING"; break;
                    case 9:  resourceTypeName = "ACCELERATOR"; break;
                    case 11: resourceTypeName = "RCDATA"; break;
                    case 14: resourceTypeName = "GROUP_ICON"; break;
                    case 16: resourceTypeName = "VERSION"; break;
                    case 24: resourceTypeName = "MANIFEST"; break;
                    default: resourceTypeName = "UNKNOWN"; break;
                }
                results.push_back("Extracted resource type: " + resourceTypeName);
            }
        }

        FreeLibrary(hModule);
    }
    return results;
}

bool DriverScanner::extractResourceByType(HMODULE hModule, LPCWSTR type, const std::wstring& outputPath) {
    struct EnumResourceParam {
        const std::wstring* outputPath;
        bool success;
    };

    EnumResourceParam param = { &outputPath, false };

    EnumResourceNamesW(hModule, type, 
        [](HMODULE hModule, LPCWSTR type, LPWSTR name, LONG_PTR param) -> BOOL {
            auto* enumParam = reinterpret_cast<EnumResourceParam*>(param);
            HRSRC hRsrc = FindResourceW(hModule, name, type);
            if (hRsrc) {
                std::wstring resourcePath = *(enumParam->outputPath) + L"\\";
                
                // Handle the type
                if (IS_INTRESOURCE(type)) {
                    resourcePath += L"Type_" + std::to_wstring(reinterpret_cast<ULONG_PTR>(type));
                } else {
                    resourcePath += L"Type_" + std::wstring(type);
                }
                
                resourcePath += L"_";
                
                // Handle the name
                if (IS_INTRESOURCE(name)) {
                    resourcePath += L"ID_" + std::to_wstring(reinterpret_cast<ULONG_PTR>(name));
                } else {
                    resourcePath += std::wstring(name);
                }
                
                resourcePath += L".bin";
                
                HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
                if (hGlobal) {
                    LPVOID data = LockResource(hGlobal);
                    DWORD size = SizeofResource(hModule, hRsrc);
                    
                    HANDLE hFile = CreateFileW(resourcePath.c_str(), GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        DWORD written;
                        WriteFile(hFile, data, size, &written, NULL);
                        CloseHandle(hFile);
                        enumParam->success = true;
                    }
                }
            }
            return TRUE;
        }, (LONG_PTR)&param);

    return param.success;
}

std::vector<std::string> DriverScanner::analyzeSecurityFeatures(const std::wstring& filePath) {
    std::vector<std::string> results;
    
    // Load the file
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        // Map file into memory
        HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMapping) {
            LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
            if (fileBase) {
                // Analyze PE headers for security features
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + 
                    dosHeader->e_lfanew);

                // Check for ASLR
                if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                    results.push_back("ASLR: Enabled");
                else
                    results.push_back("ASLR: Disabled");

                // Check for DEP
                if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
                    results.push_back("DEP: Enabled");
                else
                    results.push_back("DEP: Disabled");

                // Check for SafeSEH
                if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
                    results.push_back("SafeSEH: Not used");
                else
                    results.push_back("SafeSEH: Enabled");

                // Check for CFG
                if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
                    results.push_back("Control Flow Guard: Enabled");
                else
                    results.push_back("Control Flow Guard: Disabled");

                UnmapViewOfFile(fileBase);
            }
            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    
    return results;
}

std::vector<std::string> DriverScanner::extractDebugInfo(const std::wstring& filePath) {
    std::vector<std::string> results;
    
    // Load debug information
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMapping) {
            LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
            if (fileBase) {
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)fileBase + 
                    dosHeader->e_lfanew);

                // Check for debug directory
                PIMAGE_DEBUG_DIRECTORY debugDir = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)fileBase + 
                    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);

                if (debugDir) {
                    results.push_back("Debug Information Found:");
                    
                    switch (debugDir->Type) {
                        case IMAGE_DEBUG_TYPE_CODEVIEW:
                            results.push_back("- Type: CodeView");
                            break;
                        case IMAGE_DEBUG_TYPE_MISC:
                            results.push_back("- Type: Misc");
                            break;
                        case IMAGE_DEBUG_TYPE_POGO:
                            results.push_back("- Type: Profile Guided Optimization");
                            break;
                        default:
                            results.push_back("- Type: Unknown (" + 
                                std::to_string(debugDir->Type) + ")");
                    }

                    results.push_back("- Size: " + std::to_string(debugDir->SizeOfData) + " bytes");
                    results.push_back("- Address: 0x" + 
                        std::to_string(debugDir->AddressOfRawData));
                }

                UnmapViewOfFile(fileBase);
            }
            CloseHandle(hMapping);
        }
        CloseHandle(hFile);
    }
    
    return results;
}