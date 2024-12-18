#include "driver_scanner.hpp"
#include "string_utils.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <conio.h>
#include <fcntl.h>
#include <io.h>
#include <fstream>
#include <map>
#include <algorithm>
#include <filesystem>
#include <windows.h>
#include <signal.h>
#include <wininet.h>
#include <sstream>
#include <ctime>
#include <regex>

/*
MIT License

Copyright (c) 2024 onbot

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define VERSION "1.0.0"
#define AUTHOR "onbot"
#define LICENSE "MIT License"

// Global flag for cleanup
static bool g_Running = true;
static std::string g_LicenseKey = "";

// License validation functions
std::string generateHWID() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    std::stringstream ss;
    ss << computerName << "_" << sysInfo.dwProcessorType << "_" << sysInfo.dwNumberOfProcessors;
    
    // Get volume serial number
    char windowsPath[MAX_PATH];
    GetWindowsDirectoryA(windowsPath, MAX_PATH);
    char volumeName[MAX_PATH];
    DWORD serialNumber;
    GetVolumeInformationA(windowsPath, volumeName, MAX_PATH, &serialNumber, nullptr, nullptr, nullptr, 0);
    
    ss << "_" << serialNumber;
    
    // Create a hash of the hardware information
    std::string hwid = ss.str();
    size_t hash = std::hash<std::string>{}(hwid);
    
    // Convert to hex string
    std::stringstream hashStream;
    hashStream << std::hex << std::uppercase << hash;
    return hashStream.str();
}

bool validateLicenseKey(const std::string& key) {
    // Basic format check (adjust pattern as needed)
    std::regex keyPattern("^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$");
    if (!std::regex_match(key, keyPattern)) {
        return false;
    }
    
    // Add your license validation logic here
    // This is a simple example - you should implement more secure validation
    std::string hwid = generateHWID();
    
    // Store the key if valid
    g_LicenseKey = key;
    return true;
}

bool checkLicenseFile() {
    std::ifstream licenseFile("license.key");
    if (!licenseFile.is_open()) {
        return false;
    }
    
    std::string key;
    std::getline(licenseFile, key);
    licenseFile.close();
    
    return validateLicenseKey(key);
}

void saveLicenseKey(const std::string& key) {
    std::ofstream licenseFile("license.key");
    if (licenseFile.is_open()) {
        licenseFile << key;
        licenseFile.close();
    }
}

void displayLicenseInfo() {
    std::cout << "Advanced Vulnerable Driver Scanner v" << VERSION << "\n";
    std::cout << "Author: " << AUTHOR << "\n";
    std::cout << "License: " << LICENSE << "\n";
    std::cout << "Hardware ID: " << generateHWID() << "\n";
    if (!g_LicenseKey.empty()) {
        std::cout << "License Key: " << g_LicenseKey << "\n";
    }
    std::cout << "\n";
}

// CTRL+C handler
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        g_Running = false;
        std::cout << "\nReceived exit signal. Cleaning up...\n";
        Sleep(500); // Give time for cleanup messages
        return TRUE;
    }
    return FALSE;
}

void cleanup() {
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    _fcloseall(); // Close all open files
    g_Running = false;
}

void clearScreen() {
    system("cls");
}

void printHeader() {
    std::cout << "=================================================\n";
    std::cout << "        Advanced Vulnerable Driver Scanner        \n";
    std::cout << "=================================================\n\n";
}

void printDebugInfo(const std::string& message) {
    std::cout << "[DEBUG] " << message << "\n";
}

std::string formatFileTime(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    
    char buffer[100];
    sprintf_s(buffer, sizeof(buffer), "%02d/%02d/%d %02d:%02d:%02d",
        st.wMonth, st.wDay, st.wYear,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

void printDetailedScanSummary(const std::vector<DriverScanner::DriverInfo>& drivers) {
    int totalDrivers = drivers.size();
    int unsignedCount = 0;
    int rwCapableCount = 0;
    int killCapableCount = 0;
    int registryCapableCount = 0;
    int fsCapableCount = 0;
    int networkCapableCount = 0;
    int highRiskCount = 0;
    int criticalRiskCount = 0;

    for (const auto& driver : drivers) {
        if (!driver.isSignedByCertificate) unsignedCount++;
        if (driver.hasReadWriteCapability) rwCapableCount++;
        if (driver.hasKillProcessCapability) killCapableCount++;
        if (driver.hasRegistryCapability) registryCapableCount++;
        if (driver.hasFileSystemCapability) fsCapableCount++;
        if (driver.hasNetworkCapability) networkCapableCount++;
        
        // Calculate risk for statistics
        int risk = 0;
        if (!driver.isMicrosoftSigned) risk += 2;
        if (!driver.isSignedByCertificate) risk += 3;
        if (driver.hasReadWriteCapability) risk += 3;
        if (driver.hasKillProcessCapability) risk += 3;
        if (driver.hasRegistryCapability) risk += 1;
        if (driver.hasFileSystemCapability) risk += 1;
        if (driver.hasNetworkCapability) risk += 1;
        if (!driver.detectedVulnerabilities.empty()) {
            int vulnCount = static_cast<int>(driver.detectedVulnerabilities.size());
            risk += (vulnCount > 5) ? 5 : vulnCount;
        }

        if (risk >= 15) criticalRiskCount++;
        else if (risk >= 10) highRiskCount++;
    }

    std::cout << "\n=== DETAILED SCAN SUMMARY ===\n";
    std::cout << "Total Drivers Scanned: " << totalDrivers << "\n";
    std::cout << "\nSIGNATURE STATUS:\n";
    std::cout << "- Unsigned Drivers: " << unsignedCount << " (" 
              << (totalDrivers ? (unsignedCount * 100 / totalDrivers) : 0) << "%)\n";

    std::cout << "\nCAPABILITY ANALYSIS:\n";
    std::cout << "- Memory R/W Capable: " << rwCapableCount << " (" 
              << (totalDrivers ? (rwCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Process Kill Capable: " << killCapableCount << " (" 
              << (totalDrivers ? (killCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Registry Access: " << registryCapableCount << " (" 
              << (totalDrivers ? (registryCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- FileSystem Access: " << fsCapableCount << " (" 
              << (totalDrivers ? (fsCapableCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- Network Capable: " << networkCapableCount << " (" 
              << (totalDrivers ? (networkCapableCount * 100 / totalDrivers) : 0) << "%)\n";

    std::cout << "\nRISK DISTRIBUTION:\n";
    std::cout << "- Critical Risk: " << criticalRiskCount << " (" 
              << (totalDrivers ? (criticalRiskCount * 100 / totalDrivers) : 0) << "%)\n";
    std::cout << "- High Risk: " << highRiskCount << " (" 
              << (totalDrivers ? (highRiskCount * 100 / totalDrivers) : 0) << "%)\n";
}

void printDriverInfo(const DriverScanner::DriverInfo& driver, bool detailed) {
    std::wcout << L"\nDriver: " << driver.name;
    if (!driver.vendor.empty()) {
        std::wcout << L" (by " << driver.vendor << L")";
    }
    std::wcout << L"\n";
    
    std::wcout << L"Version: " << (!driver.version.empty() ? driver.version : L"Unknown") << L"\n";
    std::wcout << L"Path: " << driver.path << L"\n";
    std::wcout << L"Hash: " << driver.hash << L"\n";

    // Display signature status with risk level
    std::cout << "\nSignature Status: " << (driver.isSignedByCertificate ? 
        (driver.isMicrosoftSigned ? "SIGNED (Microsoft)" : "SIGNED (Third Party)") : 
        "UNSIGNED (HIGH RISK)") << "\n";

    // Display file metadata
    SYSTEMTIME creationSysTime, modifiedSysTime;
    FileTimeToSystemTime(&driver.creationTime, &creationSysTime);
    FileTimeToSystemTime(&driver.lastModifiedTime, &modifiedSysTime);
    
    std::cout << "Created: ";
    printf("%02d/%02d/%04d %02d:%02d:%02d\n",
        creationSysTime.wMonth, creationSysTime.wDay, creationSysTime.wYear,
        creationSysTime.wHour, creationSysTime.wMinute, creationSysTime.wSecond);
    
    std::cout << "Last Modified: ";
    printf("%02d/%02d/%04d %02d:%02d:%02d\n",
        modifiedSysTime.wMonth, modifiedSysTime.wDay, modifiedSysTime.wYear,
        modifiedSysTime.wHour, modifiedSysTime.wMinute, modifiedSysTime.wSecond);
    
    std::cout << "Size: " << driver.fileSize << " KB\n";

    if (!driver.associatedSoftware.empty()) {
        std::cout << "\nAssociated Software:\n";
        for (const auto& software : driver.associatedSoftware) {
            std::wcout << L"- " << software << L"\n";
        }
    }

    // Display capabilities with detailed exploitation information
    std::cout << "\n=== CAPABILITIES & EXPLOITATION ===\n";
    std::cout << "Memory Read/Write: " << (driver.hasReadWriteCapability ? "YES (HIGH RISK)" : "No") << "\n";
    if (driver.hasReadWriteCapability) {
        std::cout << "  Exploitation Methods:\n";
        std::cout << "  - Direct Memory Manipulation via DeviceIoControl\n";
        std::cout << "  - Physical Memory Mapping\n";
        std::cout << "  - Kernel Memory Access\n";
        std::cout << "  Example IOCTL Usage:\n";
        std::cout << "  1. Open handle: CreateFile(\"\\\\.\\YourDeviceName\")\n";
        std::cout << "  2. Send IOCTL: DeviceIoControl(handle, IOCTL_CODE, ...)\n";
    }

    std::cout << "Process Termination: " << (driver.hasKillProcessCapability ? "YES (HIGH RISK)" : "No") << "\n";
    if (driver.hasKillProcessCapability) {
        std::cout << "  Exploitation Methods:\n";
        std::cout << "  - Direct Process Termination\n";
        std::cout << "  - Thread Termination\n";
        std::cout << "  - Process Memory Corruption\n";
    }

    std::cout << "Registry Operations: " << (driver.hasRegistryCapability ? "YES" : "No") << "\n";
    if (driver.hasRegistryCapability) {
        std::cout << "  Exploitation Methods:\n";
        std::cout << "  - Registry Key Manipulation\n";
        std::cout << "  - System Settings Modification\n";
    }

    std::cout << "File System Access: " << (driver.hasFileSystemCapability ? "YES" : "No") << "\n";
    if (driver.hasFileSystemCapability) {
        std::cout << "  Exploitation Methods:\n";
        std::cout << "  - File System Filter Operations\n";
        std::cout << "  - Direct File Manipulation\n";
    }

    std::cout << "Network Operations: " << (driver.hasNetworkCapability ? "YES" : "No") << "\n";
    if (driver.hasNetworkCapability) {
        std::cout << "  Exploitation Methods:\n";
        std::cout << "  - Network Traffic Interception\n";
        std::cout << "  - Packet Manipulation\n";
    }

    // Display detailed exploitation information
    if (!driver.exploitInfo.exploitMethod.empty()) {
        std::cout << "\n=== DETAILED EXPLOITATION INFORMATION ===\n";
        std::cout << "Detected Exploitation Methods:\n";
        if (driver.hasReadWriteCapability) 
            std::cout << "- Memory Read/Write Capability: Direct memory manipulation\n";
        if (driver.hasKillProcessCapability)
            std::cout << "- Process Termination: Can kill system processes\n";
        if (driver.hasRegistryCapability)
            std::cout << "- Registry Operations: Can modify system configuration\n";
        std::cout << "- System function resolution - Can be used to locate and hook system functions\n";
    }

    if (!driver.exploitInfo.hookingTechnique.empty()) {
        std::cout << "\n=== HOOKING TECHNIQUES ===\n";
        std::cout << "Memory Manipulation Hooks:\n";
        std::cout << "1. Inline Hooking:\n";
        std::cout << "   - Locate target function in memory\n";
        std::cout << "   - Create trampoline for original code\n";
        std::cout << "   - Replace first bytes with jump to hook\n";
        std::cout << "2. IAT Hooking:\n";
        std::cout << "   - Locate IAT in target module\n";
        std::cout << "   - Replace function pointer\n";
        std::cout << "3. SSDT Hooking:\n";
        std::cout << "   - Modify SSDT entries\n";
        std::cout << "   - Redirect system calls\n";
        std::cout << "Tools: PCHunter, API Monitor, WinDbg\n";
    }

    if (!driver.exploitInfo.handleExploitation.empty()) {
        std::cout << "\n=== HANDLE EXPLOITATION ===\n";
        std::cout << "Handle Manipulation Methods:\n";
        std::cout << "1. Handle Duplication:\n";
        std::cout << "   - Duplicate handles across processes\n";
        std::cout << "   - Escalate handle privileges\n";
        std::cout << "2. Handle Table Manipulation:\n";
        std::cout << "   - Modify handle table entries\n";
        std::cout << "   - Bypass handle security\n";
    }

    if (!driver.exploitInfo.privilegeEscalation.empty()) {
        std::cout << "\n=== PRIVILEGE ESCALATION ===\n";
        std::cout << "Privilege Escalation Methods:\n";
        std::cout << "1. Token Manipulation:\n";
        std::cout << "   - Locate process token\n";
        std::cout << "   - Modify token privileges\n";
        std::cout << "   - Elevate process rights\n";
        std::cout << "2. Process Manipulation:\n";
        std::cout << "   - Terminate security processes\n";
        std::cout << "   - Bypass process protection\n";
    }

    if (!driver.detectedVulnerabilities.empty()) {
        std::cout << "\n=== DETECTED VULNERABILITIES ===\n";
        for (const auto& vuln : driver.detectedVulnerabilities) {
            std::cout << "! " << vuln << "\n";
        }
    }

    if (!driver.exploitInfo.exploitSteps.empty()) {
        std::cout << "\n=== EXPLOITATION STEPS ===\n";
        std::cout << "1. Initial Analysis:\n";
        std::cout << "   - Use DriverView to identify driver loading point\n";
        std::cout << "   - Use IDA Pro/Ghidra to reverse engineer driver\n";
        std::cout << "   - Identify IOCTL codes and handler functions\n";
        std::cout << "2. Setup Environment:\n";
        std::cout << "   - Configure WinDbg kernel debugging\n";
        std::cout << "   - Set up Process Monitor for filtering\n";
        std::cout << "   - Prepare IrpTracker for IRP monitoring\n";
        std::cout << "3. Memory Manipulation:\n";
        std::cout << "   - Map driver in WinDbg (!dl)\n";
        std::cout << "   - Locate target functions (!symbols)\n";
        std::cout << "   - Set breakpoints on critical operations\n";
        std::cout << "   - Use !vtop to translate virtual addresses\n";
        std::cout << "5. Post-Exploitation:\n";
        std::cout << "   - Monitor system integrity\n";
        std::cout << "   - Clean up injected code/hooks\n";
        std::cout << "   - Remove driver artifacts\n";
    }

    if (!driver.exploitInfo.requiredTools.empty()) {
        std::cout << "\n=== REQUIRED TOOLS ===\n";
        std::cout << "- PCHunter\n";
        std::cout << "- API Monitor\n";
        std::cout << "- WinDbg\n";
    }

    // Display memory analysis if available
    if (!driver.memoryAnalysis.empty()) {
        std::cout << "\n=== MEMORY ANALYSIS ===\n";
        for (const auto& analysis : driver.memoryAnalysis) {
            std::cout << analysis << "\n";
        }
    }

    // Display SDK and driver dependencies
    if (!driver.sdkDependencies.empty()) {
        std::cout << "\n=== SDK DEPENDENCIES ===\n";
        for (const auto& sdk : driver.sdkDependencies) {
            std::cout << sdk << "\n";
        }
    }

    if (!driver.driverDependencies.empty()) {
        std::cout << "\n=== DRIVER DEPENDENCIES ===\n";
        for (const auto& dep : driver.driverDependencies) {
            std::cout << dep << "\n";
        }
    }

    // Display image information
    std::cout << "\n=== IMAGE INFORMATION ===\n";
    std::cout << "Architecture: " << (driver.imageInfo.is64Bit ? "64-bit" : "32-bit") << "\n";
    std::cout << "Type: " << (driver.imageInfo.isDriver ? "Kernel Driver" : 
                             (driver.imageInfo.isDLL ? "DLL" : "Executable")) << "\n";
    std::cout << "Subsystem: " << driver.imageInfo.subsystem << "\n";
    std::cout << "Entry Point: " << driver.imageInfo.entryPoint << "\n";
    std::cout << "Image Base: " << driver.imageInfo.imageBase << "\n";
    std::cout << "Image Size: " << driver.imageInfo.imageSize << "\n";

    // Display sections with permissions
    if (!driver.imageInfo.sections.empty()) {
        std::cout << "\n=== SECTIONS ===\n";
        for (const auto& section : driver.imageInfo.sections) {
            std::cout << section << "\n";
        }
    }

    // Display imported functions that could be hooked
    if (!driver.imageInfo.importedFunctions.empty()) {
        std::cout << "\n=== HOOKABLE IMPORTED FUNCTIONS ===\n";
        for (const auto& func : driver.imageInfo.importedFunctions) {
            std::cout << "- " << func << "\n";
        }
    }

    // Display exported functions that could be used
    if (!driver.imageInfo.exportedFunctions.empty()) {
        std::cout << "\n=== USABLE EXPORTED FUNCTIONS ===\n";
        for (const auto& func : driver.imageInfo.exportedFunctions) {
            std::cout << "- " << func << "\n";
        }
    }
}

int main() {
    try {
        // Check license before proceeding
        if (!checkLicenseFile()) {
            std::cout << "=================================================\n";
            std::cout << "        Advanced Vulnerable Driver Scanner        \n";
            std::cout << "=================================================\n\n";
            std::cout << "No valid license found. Please enter your license key.\n";
            std::cout << "Format: XXXX-XXXX-XXXX-XXXX\n";
            std::cout << "Your Hardware ID: " << generateHWID() << "\n\n";
            std::cout << "License Key: ";
            
            std::string licenseKey;
            std::getline(std::cin, licenseKey);
            
            if (!validateLicenseKey(licenseKey)) {
                std::cout << "Invalid license key. Please contact " << AUTHOR << " for a valid license.\n";
                return 1;
            }
            
            saveLicenseKey(licenseKey);
            std::cout << "License validated successfully!\n\n";
        }

        // Initialize console handler
        if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
            std::cerr << "Could not set control handler\n";
            return 1;
        }

        DriverScanner scanner;
        std::vector<DriverScanner::DriverInfo> blockedDrivers;
        std::vector<DriverScanner::DriverInfo> safeDrivers;
        char choice;

        atexit(cleanup); // Register cleanup function

        do {
            if (!g_Running) {
                break; // Exit if CTRL+C was pressed
            }

            clearScreen();
            printHeader();
            
            std::cout << "[1] Scan for vulnerable drivers (Quick Scan)\n";
            std::cout << "[2] Deep scan with vulnerability analysis\n";
            std::cout << "[3] Show blocked drivers\n";
            std::cout << "[4] Show unblocked drivers\n";
            std::cout << "[5] Show high-risk drivers (Both capabilities)\n";
            std::cout << "[6] Show currently loaded drivers\n";
            std::cout << "[7] Scan custom directory\n";
            std::cout << "[8] Show detailed scan report\n";
            std::cout << "[9] Analyze specific driver file\n";
            std::cout << "[0] Exit\n\n";
            std::cout << "Choose an option: ";
            
            choice = _getch();
            
            // Add check for exit condition after each operation
            if (!g_Running) {
                break;
            }

            switch (choice) {
                case '1': {
                    clearScreen();
                    printHeader();
                    std::cout << "Performing quick scan...\n\n";
                    
                    printDebugInfo("Starting quick scan");
                    scanner.enableDeepScan(false);
                    auto drivers = scanner.scanForDrivers();
                    blockedDrivers.clear();
                    safeDrivers.clear();
                    
                    printDebugInfo("Processing scan results");
                    for (const auto& driver : drivers) {
                        if (scanner.isDriverBlocked(driver.hash)) {
                            printDebugInfo("Found blocked driver: " + wstring_to_string(driver.name));
                            blockedDrivers.push_back(driver);
                        } else {
                            safeDrivers.push_back(driver);
                        }
                    }
                    
                    printDetailedScanSummary(drivers);
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '2': {
                    clearScreen();
                    printHeader();
                    std::cout << "Performing deep scan with vulnerability analysis...\n";
                    std::cout << "This may take several minutes...\n\n";
                    
                    printDebugInfo("Starting deep scan");
                    scanner.enableDeepScan(true);
                    scanner.setSignatureVerification(true);
                    auto drivers = scanner.scanForDrivers();
                    blockedDrivers.clear();
                    safeDrivers.clear();
                    
                    printDebugInfo("Processing deep scan results");
                    for (const auto& driver : drivers) {
                        if (scanner.isDriverBlocked(driver.hash)) {
                            printDebugInfo("Found blocked driver: " + wstring_to_string(driver.name));
                            blockedDrivers.push_back(driver);
                        } else {
                            if (driver.hasReadWriteCapability || driver.hasKillProcessCapability) {
                                printDebugInfo("Found potentially dangerous driver: " + 
                                    wstring_to_string(driver.name));
                            }
                            safeDrivers.push_back(driver);
                        }
                    }
                    
                    printDetailedScanSummary(drivers);
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '3': {
                    clearScreen();
                    printHeader();
                    std::cout << "=== BLOCKED DRIVERS ===\n\n";
                    
                    if (blockedDrivers.empty()) {
                        std::cout << "No blocked drivers found. Run a scan first.\n";
                    } else {
                        printDebugInfo("Displaying " + std::to_string(blockedDrivers.size()) + " blocked drivers");
                        for (const auto& driver : blockedDrivers) {
                            printDriverInfo(driver, true);
                        }
                    }
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '4': {
                    clearScreen();
                    printHeader();
                    std::cout << "=== UNBLOCKED DRIVERS ===\n\n";
                    
                    if (safeDrivers.empty()) {
                        std::cout << "No unblocked drivers found. Run a scan first.\n";
                    } else {
                        printDebugInfo("Displaying " + std::to_string(safeDrivers.size()) + " unblocked drivers");
                        for (const auto& driver : safeDrivers) {
                            printDriverInfo(driver, true);
                        }
                    }
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '5': {
                    clearScreen();
                    printHeader();
                    std::cout << "=== HIGH RISK DRIVERS (R/W + KILL PROCESS) ===\n\n";
                    
                    bool found = false;
                    printDebugInfo("Checking for high-risk drivers");
                    
                    for (const auto& driver : safeDrivers) {
                        if (driver.hasReadWriteCapability && driver.hasKillProcessCapability) {
                            if (!found) {
                                std::cout << "!!! WARNING: POTENTIALLY DANGEROUS UNBLOCKED DRIVERS FOUND !!!\n\n";
                                found = true;
                            }
                            printDebugInfo("Found high-risk driver: " + wstring_to_string(driver.name));
                            printDriverInfo(driver, true);
                        }
                    }
                    
                    if (!found) {
                        std::cout << "No high-risk drivers found with both capabilities.\n";
                    }
                    
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '6': {
                    clearScreen();
                    printHeader();
                    std::cout << "=== CURRENTLY LOADED DRIVERS ===\n\n";
                    
                    printDebugInfo("Checking for loaded drivers");
                    bool found = false;
                    
                    for (const auto& driver : safeDrivers) {
                        if (scanner.isDriverLoadedInKernel(driver.name)) {
                            if (!found) {
                                std::cout << "Currently loaded drivers:\n\n";
                                found = true;
                            }
                            printDebugInfo("Found loaded driver: " + wstring_to_string(driver.name));
                            printDriverInfo(driver, true);
                        }
                    }
                    
                    if (!found) {
                        std::cout << "No scanned drivers are currently loaded.\n";
                    }
                    
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '7': {
                    clearScreen();
                    printHeader();
                    std::cout << "Enter path to scan (or press Enter for default): ";
                    std::wstring customPath;
                    std::getline(std::wcin >> std::ws, customPath);
                    
                    if (!customPath.empty()) {
                        printDebugInfo("Setting custom scan path: " + wstring_to_string(customPath));
                        scanner.setCustomScanPath(customPath);
                        
                        // Perform scan with custom path
                        auto drivers = scanner.scanForDrivers();
                        blockedDrivers.clear();
                        safeDrivers.clear();
                        
                        for (const auto& driver : drivers) {
                            if (scanner.isDriverBlocked(driver.hash)) {
                                blockedDrivers.push_back(driver);
                            } else {
                                safeDrivers.push_back(driver);
                            }
                        }
                        
                        printDetailedScanSummary(drivers);
                    }
                    
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '8': {
                    clearScreen();
                    printHeader();
                    std::cout << "=== DETAILED SCAN REPORT ===\n\n";
                    
                    if (blockedDrivers.empty() && safeDrivers.empty()) {
                        std::cout << "No scan data available. Run a scan first.\n";
                    } else {
                        std::vector<DriverScanner::DriverInfo> allDrivers;
                        allDrivers.insert(allDrivers.end(), blockedDrivers.begin(), blockedDrivers.end());
                        allDrivers.insert(allDrivers.end(), safeDrivers.begin(), safeDrivers.end());
                        
                        printDetailedScanSummary(allDrivers);
                        
                        std::cout << "\n=== FULL DRIVER DETAILS ===\n";
                        for (const auto& driver : allDrivers) {
                            printDriverInfo(driver, true);
                        }
                    }
                    
                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
                
                case '9': {
                    clearScreen();
                    printHeader();
                    std::cout << "Enter the full path to the program or driver file: ";
                    std::wstring filePath;
                    std::getline(std::wcin >> std::ws, filePath);

                    if (!filePath.empty()) {
                        printDebugInfo("Analyzing path: " + wstring_to_string(filePath));
                        try {
                            // Check if it's a directory or file
                            if (std::filesystem::is_directory(filePath)) {
                                std::cout << "\nScanning directory for drivers...\n";
                                auto drivers = scanner.scanProgramLocation(filePath);
                                if (drivers.empty()) {
                                    std::cout << "No drivers found in the specified location.\n";
                                } else {
                                    std::cout << "\nFound " << drivers.size() << " driver(s):\n";
                                    for (const auto& driver : drivers) {
                                        printDriverInfo(driver, true);
                                    }
                                }
                            } else {
                                auto driverInfo = scanner.analyzeDriverFile(filePath);
                                printDriverInfo(driverInfo, true);
                                
                                // If it's a program (exe/dll), perform additional analysis
                                auto ext = std::filesystem::path(filePath).extension();
                                if (ext == L".exe" || ext == L".dll") {
                                    std::cout << "\n=== ADDITIONAL PROGRAM ANALYSIS ===\n";
                                    
                                    // Create output directory for dumps
                                    std::filesystem::path outputDir = std::filesystem::path(filePath).parent_path() / "analysis_output";
                                    std::filesystem::create_directories(outputDir);
                                    
                                    // Memory dump analysis
                                    std::cout << "\nPerforming memory analysis...\n";
                                    std::wstring memoryDumpPath = outputDir / L"memory_dump.bin";
                                    if (scanner.dumpProcessMemory(filePath, memoryDumpPath)) {
                                        std::cout << "Memory dump saved to: " << wstring_to_string(memoryDumpPath) << "\n";
                                        
                                        // Analyze memory regions
                                        auto memRegions = scanner.analyzeMemoryRegions(memoryDumpPath);
                                        std::cout << "\nMemory Regions Analysis:\n";
                                        for (const auto& region : memRegions) {
                                            std::cout << "- " << region << "\n";
                                        }
                                    }
                                    
                                    // SDK/Import analysis
                                    std::cout << "\nAnalyzing SDK and Import dependencies...\n";
                                    std::wstring sdkDumpPath = outputDir / L"sdk_analysis.txt";
                                    auto sdkInfo = scanner.analyzeSdkDependencies(filePath);
                                    std::cout << "\nSDK Dependencies:\n";
                                    for (const auto& sdk : sdkInfo) {
                                        std::cout << "- " << sdk << "\n";
                                    }
                                    
                                    // Driver dependency analysis
                                    std::cout << "\nAnalyzing driver dependencies...\n";
                                    std::wstring driverDumpPath = outputDir / L"driver_dependencies.txt";
                                    auto driverDeps = scanner.analyzeDriverDependencies(filePath);
                                    std::cout << "\nDriver Dependencies:\n";
                                    for (const auto& dep : driverDeps) {
                                        std::cout << "- " << dep << "\n";
                                    }
                                    
                                    // Resource analysis
                                    std::cout << "\nAnalyzing embedded resources...\n";
                                    std::wstring resourceDumpPath = outputDir / L"resources";
                                    std::filesystem::create_directories(resourceDumpPath);
                                    auto resources = scanner.extractResources(filePath, resourceDumpPath);
                                    if (!resources.empty()) {
                                        std::cout << "\nExtracted Resources:\n";
                                        for (const auto& res : resources) {
                                            std::cout << "- " << res << "\n";
                                        }
                                    }
                                    
                                    // Security analysis
                                    std::cout << "\nPerforming security analysis...\n";
                                    auto securityInfo = scanner.analyzeSecurityFeatures(filePath);
                                    std::cout << "\nSecurity Features:\n";
                                    for (const auto& feature : securityInfo) {
                                        std::cout << "- " << feature << "\n";
                                    }
                                    
                                    // Check for debug information
                                    std::cout << "\nChecking for debug information...\n";
                                    auto debugInfo = scanner.extractDebugInfo(filePath);
                                    if (!debugInfo.empty()) {
                                        std::cout << "\nDebug Information:\n";
                                        for (const auto& info : debugInfo) {
                                            std::cout << "- " << info << "\n";
                                        }
                                    }
                                    
                                    // Scan program location for associated drivers
                                    std::cout << "\nScanning program location for additional drivers...\n";
                                    auto drivers = scanner.scanProgramLocation(filePath);
                                    if (!drivers.empty()) {
                                        std::cout << "\nFound " << drivers.size() << " associated driver(s):\n";
                                        for (const auto& driver : drivers) {
                                            printDriverInfo(driver, true);
                                        }
                                    }
                                    
                                    std::cout << "\nAnalysis output saved to: " << wstring_to_string(outputDir.wstring()) << "\n";
                                }
                            }
                        }
                        catch (const std::exception& e) {
                            std::cout << "Error analyzing path: " << e.what() << "\n";
                        }
                    }

                    std::cout << "\nPress any key to return to menu...";
                    _getch();
                    break;
                }
            }
            
        } while (choice != '0' && g_Running);

        // Cleanup before exit
        std::cout << "Cleaning up...\n";
        blockedDrivers.clear();
        safeDrivers.clear();
        cleanup();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        cleanup();
        return 1;
    }
    
    std::cout << "Program exited cleanly.\n";
    return 0;
} 