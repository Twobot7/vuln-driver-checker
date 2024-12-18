#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <filesystem>

class DriverScanner {
public:
    struct ImageInfo {
        bool isDLL;
        bool isDriver;
        bool is64Bit;
        std::string subsystem;
        std::string imageCharacteristics;
        std::vector<std::string> importedDlls;
        std::vector<std::string> importedFunctions;
        std::vector<std::string> exportedFunctions;
        std::string entryPoint;
        std::string imageBase;
        std::string imageSize;
        std::vector<std::string> sections;
        std::string timestamp;
        std::string checksum;
    };

    struct ExploitInfo {
        std::string exploitMethod;
        std::string hookingTechnique;
        std::string interceptionMethod;
        std::vector<std::string> requiredTools;
        std::vector<std::string> exploitSteps;
        std::string handleExploitation;
        std::vector<std::string> ioctlCalls;
        std::string privilegeEscalation;
        std::vector<std::string> specificExploits;
    };

    struct DriverInfo {
        std::wstring name;
        std::wstring path;
        std::wstring hash;
        std::wstring vendor;
        std::wstring version;
        std::vector<std::wstring> associatedSoftware;
        bool hasReadWriteCapability;
        bool hasKillProcessCapability;
        bool hasRegistryCapability;
        bool hasFileSystemCapability;
        bool hasNetworkCapability;
        bool isSignedByCertificate;
        bool isMicrosoftSigned;
        FILETIME creationTime;
        FILETIME lastModifiedTime;
        DWORD fileSize;
        std::vector<std::string> suspiciousStrings;
        std::vector<std::string> detectedVulnerabilities;
        ExploitInfo exploitInfo;
        ImageInfo imageInfo;
        std::vector<std::string> securityFeatures;
        std::vector<std::string> debugInformation;
        std::vector<std::string> sdkDependencies;
        std::vector<std::string> driverDependencies;
        std::vector<std::string> extractedResources;
        std::vector<std::string> memoryAnalysis;
    };

    // Debug output formatting
    struct DebugOutput {
        static std::string formatExploitInfo(const ExploitInfo& info);
        static std::string formatVulnerability(const std::string& vuln);
        static std::string formatCapabilities(const DriverInfo& driver);
        static std::string formatImageInfo(const ImageInfo& info);
    };

    DriverScanner();
    ~DriverScanner();

    // Main scanning functions
    std::vector<DriverInfo> scanForDrivers();
    bool isDriverBlocked(const std::wstring& hash);
    bool isDriverLoadedInKernel(const std::wstring& driverName);
    
    // Configuration
    void setCustomScanPath(const std::wstring& path);
    void enableDeepScan(bool enable);
    void setSignatureVerification(bool enable);

    // New methods for analyzing specific files
    DriverInfo analyzeDriverFile(const std::wstring& filePath);
    void analyzeImageInformation(const std::wstring& filePath, DriverInfo& driver);
    std::vector<DriverInfo> scanProgramLocation(const std::wstring& programPath);

    // Memory and program analysis functions
    bool dumpProcessMemory(const std::wstring& processPath, const std::wstring& outputPath);
    std::vector<std::string> analyzeMemoryRegions(const std::wstring& dumpPath);
    std::vector<std::string> analyzeSdkDependencies(const std::wstring& filePath);
    std::vector<std::string> analyzeDriverDependencies(const std::wstring& filePath);
    std::vector<std::string> extractResources(const std::wstring& filePath, const std::wstring& outputPath);
    std::vector<std::string> analyzeSecurityFeatures(const std::wstring& filePath);
    std::vector<std::string> extractDebugInfo(const std::wstring& filePath);

private:
    // Helper methods
    std::wstring calculateFileHash(const std::wstring& filePath);
    bool fetchMsdbxList();
    void checkDriverCapabilities(DriverInfo& driver);
    void identifyAssociatedSoftware(DriverInfo& driver);
    bool checkForReadWriteCapability(const std::vector<BYTE>& driverContent);
    bool checkForKillProcessCapability(const std::vector<BYTE>& driverContent);
    bool checkForRegistryCapability(const std::vector<BYTE>& driverContent);
    bool checkForFileSystemCapability(const std::vector<BYTE>& driverContent);
    bool checkForNetworkCapability(const std::vector<BYTE>& driverContent);
    
    // New analysis methods
    void analyzeDriverStrings(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    void checkVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    bool verifyDigitalSignature(const std::wstring& filePath, DriverInfo& driver);
    void getFileMetadata(const std::wstring& filePath, DriverInfo& driver);
    void determineExploitationMethods(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    bool checkForHandleVulnerabilities(const std::vector<BYTE>& driverContent);
    void analyzeHandleOperations(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    
    // Advanced analysis methods
    void analyzeAdvancedHookingTechniques(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    void determineKernelCallbacks(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    void analyzeIOCTLVulnerabilities(DriverInfo& driver, const std::vector<BYTE>& driverContent);
    std::string generateExploitCode(const DriverInfo& driver, const std::string& technique);
    
    // Data members
    std::vector<std::wstring> blockedHashes;
    std::wstring customScanPath;
    bool deepScanEnabled;
    bool signatureVerificationEnabled;
    
    // Known vulnerability patterns
    const std::vector<std::string> knownVulnPatterns = {
        "memcpy", "strcpy", "strcat", "sprintf", "vsprintf",
        "gets", "scanf", "sscanf", "fscanf", "vfscanf",
        "reallocarray", "alloca"
    };
    
    // Known dangerous capability patterns
    const std::vector<std::string> dangerousAPIs = {
        "ZwMapViewOfSection", "MmMapIoSpace", "MmMapLockedPages",
        "ZwCreateSection", "ZwOpenSection", "ZwAllocateVirtualMemory",
        "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine",
        "PsSetLoadImageNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
        "KeInsertQueueApc", "KeInitializeApc", "KeInsertQueueDpc"
    };

    // Read/Write capability patterns
    const std::vector<std::string> readWritePatterns = {
        "MmMapIoSpace", "MmMapIoSpaceEx", "ZwMapViewOfSection",
        "MmCopyVirtualMemory", "WriteProcessMemory", "ReadProcessMemory",
        "PhysicalMemory", "DirectIo", "DirectRead", "DirectWrite",
        "MapPhysicalMemory", "UnmapPhysicalMemory", "ReadPort", "WritePort",
        "ReadMsr", "WriteMsr", "ReadPci", "WritePci", "IOCTL_READ", "IOCTL_WRITE"
    };

    // Process termination patterns
    const std::vector<std::string> killProcessPatterns = {
        "ZwTerminateProcess", "TerminateProcess", "PsTerminateSystemThread",
        "ZwClose", "KillProcessByName", "PspTerminateProcess"
    };

    // Known exploitation patterns
    const std::vector<std::pair<std::string, std::string>> exploitPatterns = {
        {"ZwMapViewOfSection", "Memory mapping exploitation - Can be used to map physical memory for read/write access"},
        {"MmMapIoSpace", "Direct hardware access exploitation - Can be used to access hardware memory directly"},
        {"ZwCreateSection", "Memory section exploitation - Can be used for code injection"},
        {"ObRegisterCallbacks", "Callback exploitation - Can be used to intercept process/thread operations"},
        {"KeInitializeApc", "APC exploitation - Can be used for usermode code execution"},
        {"KeInsertQueueDpc", "DPC exploitation - Can be used for kernel mode code execution"},
        {"MmCopyVirtualMemory", "Direct memory manipulation - Can be used to read/write other process memory"},
        {"MmGetSystemRoutineAddress", "System function resolution - Can be used to locate and hook system functions"},
        {"PsCreateSystemThread", "Thread creation exploitation - Can be used for persistent code execution"},
        {"IoCreateDevice", "Device creation exploitation - Can be used for communication channel creation"}
    };

    // Advanced hooking patterns
    const std::vector<std::pair<std::string, std::string>> advancedHookPatterns = {
        {"KeServiceDescriptorTable", "SSDT Hook - System service descriptor table manipulation"},
        {"KiSystemCall64", "Syscall Hook - Direct system call interception"},
        {"PsSetLoadImageNotifyRoutine", "Image Load Hook - Intercept module loading"},
        {"PsSetCreateProcessNotifyRoutine", "Process Creation Hook - Monitor process creation"},
        {"CmRegisterCallback", "Registry Operation Hook - Intercept registry access"},
        {"FltRegisterFilter", "Filesystem Mini-filter Hook - Intercept file operations"},
        {"IoRegisterFsRegistrationChange", "Filesystem Hook - Monitor filesystem changes"},
        {"SwapContext", "Context Swap Hook - Intercept thread context switches"},
        {"PspCidTable", "Handle Table Hook - Manipulate process/thread handles"},
        {"ObRegisterCallbacks", "Object Manager Hook - Intercept object operations"}
    };

    // Known handle operation patterns
    const std::vector<std::string> handlePatterns = {
        "ZwOpenProcess",
        "ZwOpenThread",
        "ZwDuplicateObject",
        "ObReferenceObjectByHandle",
        "ObOpenObjectByPointer",
        "PsLookupProcessByProcessId",
        "PsLookupThreadByThreadId"
    };

    // Known IOCTL patterns
    const std::vector<std::string> ioctlPatterns = {
        "IRP_MJ_DEVICE_CONTROL",
        "IOCTL_",
        "DeviceIoControl",
        "METHOD_BUFFERED",
        "METHOD_NEITHER",
        "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT"
    };

    // Privilege escalation patterns
    const std::vector<std::string> privEscPatterns = {
        "SePrivilege",
        "TOKEN_PRIVILEGES",
        "RtlAdjustPrivilege",
        "SeDebugPrivilege",
        "SeLoadDriverPrivilege",
        "SeImpersonatePrivilege"
    };

    // New PE analysis patterns
    const std::vector<std::string> suspiciousPEPatterns = {
        "INIT_POOL_EXECUTABLE",
        "INIT_POOL_MAPPED",
        "PAGE_EXECUTE",
        "PAGE_EXECUTE_READ",
        "PAGE_EXECUTE_READWRITE",
        "PAGE_EXECUTE_WRITECOPY",
        "MmHighestUserAddress",
        "PsInitialSystemProcess",
        "PsLookupProcessByProcessId",
        "ZwOpenProcess"
    };

    std::vector<std::wstring> findDriversInDirectory(const std::wstring& directory);

    // Helper functions for memory analysis
    bool createAndInjectDumpProcess(const std::wstring& processPath, HANDLE& hProcess, HANDLE& hThread);
    bool performMemoryDump(HANDLE hProcess, const std::wstring& outputPath);
    std::vector<std::string> parseMemoryDump(const std::wstring& dumpPath);
    void analyzeMemoryPermissions(HANDLE hProcess, std::vector<std::string>& results);
    
    // Helper functions for SDK/Driver analysis
    std::vector<std::string> extractImportInformation(const std::wstring& filePath);
    std::vector<std::string> findLinkedDrivers(const std::wstring& filePath);
    std::vector<std::string> extractVersionInfo(const std::wstring& filePath);
    
    // Resource analysis helpers
    bool extractResourceByType(HMODULE hModule, LPCWSTR type, const std::wstring& outputPath);
    void saveResourceToFile(HMODULE hModule, HRSRC hRsrc, const std::wstring& outputPath);
    
    // Security analysis helpers
    void checkSecurityFeatures(HANDLE hProcess, std::vector<std::string>& results);
    void analyzePESecurity(const std::wstring& filePath, std::vector<std::string>& results);
    void checkMitigationPolicies(HANDLE hProcess, std::vector<std::string>& results);
};

// Global function declaration
void printDriverInfo(const DriverScanner::DriverInfo& driver, bool detailed = false); 