#include "../include/memory.hpp"
#include <TlHelp32.h>
#include <memory>
#include <Psapi.h>
#include <spdlog/spdlog.h>
#include <iostream>
#include <tchar.h>
#include "../include/util.hpp"

struct HandleDisposer {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

std::pair<HANDLE, ULONG> Memory::WaitForProcess(ULONG dwDesiredAccess, BOOL bInheritHandle, std::string procName)
{
    ULONG procId = NULL;
	while (!procId) {
		procId = getProcId(procName);
		if (procId) break;
        Sleep(10);
	}
	HANDLE handle = OpenProcess(dwDesiredAccess, bInheritHandle, procId);
	if (handle == INVALID_HANDLE_VALUE || !handle) {
		spdlog::error("Error getting handle for process: {}", procName);
		return { NULL, NULL };
	}
    else {
        spdlog::info("Opened handle to {} with PID: {}", procName, procId);
        return { handle, procId };
    }
}
bool Memory::handleIsStillValid(HANDLE handle) {
    ULONG procId = NULL;
    procId = GetProcessId(handle);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
    if (process == NULL) {
        return false;
    }
    ULONG exitCode;
    if (GetExitCodeProcess(process, &exitCode)) {
        CloseHandle(process);
        return (exitCode == STILL_ACTIVE);
    }
    CloseHandle(process);
    return true;
}
ULONG Memory::getProcId(std::string name) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(MODULEENTRY32);

    const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

    if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
        return NULL;

    int highestCount = 0;
    ULONG procId = NULL;
    do {
        if (!name.compare(procEntry.szExeFile) && procEntry.cntThreads > highestCount) {
            highestCount = procEntry.cntThreads;
            procId = procEntry.th32ProcessID;
        }
    } while (Process32Next(snapshot_handle.get(), &procEntry));
    return procId;
}

ULONGLONG Memory::getModuleBaseAddr(ULONG procId, const char* modName) {
    ULONGLONG modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!strcmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (ULONGLONG)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}
HMODULE Memory::getLoadedModule(HANDLE handle, const char* modName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(handle));
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!strcmp(modEntry.szModule, modName))
                {
                    return (HMODULE)modEntry.modBaseAddr;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return NULL;
}
HMODULE Memory::findModuleByAddress(HANDLE handle, ULONGLONG address) {
    HMODULE modules[1024];
    ULONG modulesSize;

    if (!EnumProcessModulesEx(handle, modules, sizeof(modules), &modulesSize, LIST_MODULES_ALL))
    {
        return NULL;
    }

    ULONG moduleCount = modulesSize / sizeof(HMODULE);

    for (DWORD i = 0; i < moduleCount; i++)
    {
        MODULEINFO modInfo;
        if (!GetModuleInformation(handle, modules[i], &modInfo, sizeof(modInfo)))
        {
            continue; 
        }

        ULONGLONG baseAddr = reinterpret_cast<ULONGLONG>(modInfo.lpBaseOfDll);
        ULONGLONG endAddr = baseAddr + modInfo.SizeOfImage;

        if (address >= baseAddr && address < endAddr)
        {
            return modules[i]; 
        }
    }

    return NULL; 
}
ULONG Memory::getModuleSize(HANDLE handle, HMODULE module) {
    MODULEINFO moduleInfo;
    if (GetModuleInformation(handle, module, &moduleInfo, sizeof(moduleInfo)))
    {
        return moduleInfo.SizeOfImage;
    }
    return 0; 
}

std::unordered_map<std::string, HMODULE> Memory::getModules(HANDLE handle) {

    std::unordered_map<std::string, HMODULE> map = std::unordered_map<std::string, HMODULE>();
    HMODULE modules[1024];
    ULONG bytes;

    if (EnumProcessModules(handle, modules, sizeof(modules), &bytes)) {
        for (unsigned i = 0; i < (bytes / sizeof(HMODULE)); i++) {
            HMODULE m = modules[i];
            TCHAR szModName[MAX_PATH];
            if (GetModuleBaseName(handle, modules[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                map[std::string(szModName)] = m;
            }
        }
    }

    return map;
}

std::vector<BYTE> Memory::readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, std::string funcName) {
    ULONGLONG estimatedFunctionSize = optionalCheckFuncSize(handle, module, funcName, functionRVA);
    return readFuncBytes(handle, module, functionRVA, estimatedFunctionSize);
}

std::vector<BYTE> Memory::readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, ULONGLONG bytesToRead) {
    LPVOID functionAddress = (BYTE*)module + functionRVA;
	return readFuncBytes(handle, (ULONGLONG)functionAddress, bytesToRead);
}

std::vector<BYTE> Memory::readFuncBytes(HANDLE handle, ULONGLONG functionAddress, ULONGLONG bytesToRead)
{
    std::vector<BYTE> functionBytes;

    functionBytes.resize(bytesToRead);

    ULONGLONG bytesRead;
    if (!ReadProcessMemory(handle, (LPVOID)functionAddress, functionBytes.data(), bytesToRead, &bytesRead)) {
        if (GetLastError() != 299) { //status partial copy
            spdlog::error("Failed to read function bytes. Error: {}", GetLastError());
            return {};
        }
    }

    if (bytesRead != bytesToRead) {
        spdlog::error("Failed to read all function bytes. Only read {} of {} bytes", bytesRead, bytesToRead);
        functionBytes.resize(bytesRead);
    }

    return functionBytes;
}

ULONGLONG Memory::optionalCheckFuncSize(HANDLE handle, HMODULE module, std::string funcName, ULONG functionRVA) {
    //we can possibly get the true function size from the storage in the .pdata section, containing exception info

    //read modules dos header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(handle, module, (LPVOID)&dosHeader, sizeof(dosHeader), 0)) {
        spdlog::error("Failed to read DOS header: {}", GetLastError());
        return 1024;
    }
    //read the ntHeader using the offset provided in the dosHeader
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(handle, (BYTE*)module + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), 0)) {
        spdlog::error("Failed to read NT headers: {}", GetLastError());
        return 1024;
    }


    //check if theres an exception directory (x64)
    if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size > 0) {
        ULONG numEntries = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        IMAGE_RUNTIME_FUNCTION_ENTRY* funcTable = new IMAGE_RUNTIME_FUNCTION_ENTRY[numEntries];

        if (!ReadProcessMemory(handle, (LPVOID)((BYTE*)module + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress), funcTable, sizeof(funcTable), 0)) {
            delete funcTable;
            return 1024;
        }

        //its not common to actually find this entry, most likely we will have to estimate
        for (ULONG i = 0; i < numEntries; i++) {
            if (funcTable[i].BeginAddress == functionRVA) {
                ULONG funcEnd = funcTable[i].EndAddress;
                ULONGLONG size = static_cast<ULONGLONG>(funcEnd) - functionRVA;
                delete funcTable;
                return std::min((ULONGLONG)1024,size);
            }
        }
        delete funcTable;
    }
    return 1024;
}

std::unordered_map<std::string, ULONG> Memory::getExportsFunctions(HANDLE handle, HMODULE module) {

    std::unordered_map< std::string, ULONG> exportMap = std::unordered_map< std::string, ULONG>();

    //read modules dos header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(handle, module, (LPVOID)&dosHeader, sizeof(dosHeader),0)) {
        spdlog::error("Failed to read DOS header: {}", GetLastError());
        return exportMap;
    }

    //read the ntHeader using the offset provided in the dosHeader
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(handle, (BYTE*)module + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders),0)) {
        spdlog::error("Failed to read NT headers: {}", GetLastError());
        return exportMap;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        spdlog::error("Invalid NT header signature!");
        return exportMap;
    }

    // get export directory RVA and size
    ULONG exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ULONG exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (exportDirRVA == 0) {
        spdlog::error("No export directory found");
        return exportMap;
    }

    // read export directory
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(handle, (BYTE*)module + exportDirRVA, &exportDir, sizeof(exportDir),0)) {
        spdlog::error("Failed to read export directory: {}",GetLastError());
        CloseHandle(handle);
        return exportMap;
    }

    if (exportDirSize == 0) {
        spdlog::error("No functions found in export directory");
        return exportMap;
    }
    //
    // Read function address table
    std::vector<ULONG> functions(exportDir.NumberOfFunctions);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfFunctions,
        functions.data(),
        exportDir.NumberOfFunctions * sizeof(ULONG),0)) {
        spdlog::error("Failed to read functions addresses: ", GetLastError());
        return exportMap;
    }

    // Read name pointer table
    std::vector<ULONG> names(exportDir.NumberOfNames);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfNames,
        names.data(),
        exportDir.NumberOfNames * sizeof(ULONG),0)) {
        spdlog::error("Failed to read name pointers: ", GetLastError());
        return exportMap;
    }

    // Read ordinal table
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfNameOrdinals,
        ordinals.data(),
        exportDir.NumberOfNames * sizeof(WORD),0)) {
        spdlog::error("Failed to read ordinals: {}",GetLastError());
        return exportMap;
    }
    //
    // enumerate exports

    // get section headers
    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS),
        sections.data(),
        sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections,
        nullptr)) {
        spdlog::error("Failed to read section headers: {}", GetLastError());
        return exportMap;
    }

    // find executable sections
    std::vector<ULONG> executableRanges;
    for (const auto& section : sections) {
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            executableRanges.push_back(section.VirtualAddress);
            executableRanges.push_back(section.VirtualAddress + section.Misc.VirtualSize);
        }
    }

    for (ULONG i = 0; i < exportDir.NumberOfNames; i++) {

        // read function name
        char functionName[256] = { 0 };
        if (!ReadProcessMemory(handle,
            (BYTE*)module + names[i],
            functionName,
            sizeof(functionName) - 1,0)) {
            spdlog::error("Failed to read function name at index {}",i);
            continue;
        }

        // get function RVA
        ULONG functionRVA = functions[ordinals[i]];
        if (functionRVA == 0) continue;

        bool isExecutable = false;
        for (size_t j = 0; j < executableRanges.size(); j += 2) {
            if (functionRVA >= executableRanges[j] && functionRVA < executableRanges[j + 1]) {
                isExecutable = true;
                break;
            }
        }

        if (isExecutable) {
            exportMap[functionName] = functionRVA;
        }
    }

    return exportMap;
}

std::unordered_map<std::string, IATModule> Memory::getIAT(HANDLE handle) {
    std::unordered_map<std::string, IATModule> iat = std::unordered_map<std::string, IATModule>();
    std::unordered_map<std::string, HMODULE> procModules = getModules(handle);
	for (const auto& moduleElement : procModules) {
		HMODULE module = moduleElement.second;

        IATModule iatModule;
        iatModule.name= moduleElement.first;
		iatModule.moduleIAT = std::unordered_map<std::string, IATModuleEntry>();

        //read modules dos header
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(handle, module, (LPVOID)&dosHeader, sizeof(dosHeader), 0)) {
            spdlog::error("Failed to read DOS header: {}", GetLastError());
            return iat;
        }

        //read the ntHeader using the offset provided in the dosHeader
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(handle, (BYTE*)module + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), 0)) {
            spdlog::error("Failed to read NT headers: {}", GetLastError());
            return iat;
        }

        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
            spdlog::error("Invalid NT header signature!");
            return iat;
        }

        ULONG importDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        ULONG importDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (importDirSize == 0) {
			continue;
        }

        IMAGE_IMPORT_DESCRIPTOR* importDescriptors = new IMAGE_IMPORT_DESCRIPTOR[importDirSize]{ 0 };
        if (!ReadProcessMemory(handle, (BYTE*)module + importDirRVA, 
                            importDescriptors, importDirSize,0)) {
            spdlog::error("Failed to real module import descriptor!");
            continue;
        }




        // iterate through each import descriptor (DLL)
		while (importDescriptors->Name != 0) {

            char dllName[MAX_PATH] = { 0 };
            if (!ReadProcessMemory(handle, (BYTE*)module + importDescriptors->Name, &dllName, MAX_PATH, nullptr)) {
                if (GetLastError() != 299) { //ignore partial read errors, they happen
                    std::cerr << "Failed to read ID DLL name: " << GetLastError() << std::endl;
                    break;
                }
            }

            IATModuleEntry entry;
            entry.name = dllName;

            ULONG thunkRVA = importDescriptors->OriginalFirstThunk ? importDescriptors->OriginalFirstThunk : importDescriptors->FirstThunk;
            ULONG iatRVA = importDescriptors->FirstThunk;

            // read thunk data
            std::vector<IMAGE_THUNK_DATA> thunks;
            IMAGE_THUNK_DATA thunk;
            BYTE* thunkAddr = (BYTE*)module + thunkRVA;

            do {
                if (!ReadProcessMemory(handle, thunkAddr, &thunk,sizeof(IMAGE_THUNK_DATA), 0)) break;
                if (thunk.u1.AddressOfData == 0) break;

                thunks.push_back(thunk);
                thunkAddr += sizeof(IMAGE_THUNK_DATA);
            } while (true);

            // read IAT data
            std::vector<IMAGE_THUNK_DATA> iats;
            BYTE* iatAddr = (BYTE*)module + iatRVA;

            do {
                IMAGE_THUNK_DATA iat;
                if (!ReadProcessMemory(handle, iatAddr, &iat,sizeof(IMAGE_THUNK_DATA), 0)) break;
                if (iat.u1.Function == 0) break;

                iats.push_back(iat);
                iatAddr += sizeof(IMAGE_THUNK_DATA);
            } while (true);

            // match thunks with IAT entries
            for (size_t j = 0; j < thunks.size() && j < iats.size(); j++) {
                ULONGLONG funcAddr = iats[j].u1.Function;
                std::string name;
                if (thunks[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    //i will not be hnadling ordinal functions
                    continue;
                }
                else {
                    IMAGE_IMPORT_BY_NAME importByName;
                    if (ReadProcessMemory(handle, (BYTE*)module + thunks[j].u1.AddressOfData, &importByName,sizeof(IMAGE_IMPORT_BY_NAME),0)) {
                        char funcName[256] = { 0 };
                        if (ReadProcessMemory(handle, (BYTE*)module + thunks[j].u1.AddressOfData + sizeof(WORD),
                            &funcName, sizeof(funcName) - 1,0)) {
							name = funcName;
                        }
                    }
                }
				entry.functions[name] = funcAddr;
                
            }
			iatModule.moduleIAT[dllName] = entry;
			importDescriptors++;
        }
        iat[iatModule.name] = iatModule;
	}

    return iat;
}
BOOL ModifyIATEntry(HANDLE hProcess, HMODULE hModule, LPCSTR szFunctionName, LPVOID lpNewAddress) {
    // Get the DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader), NULL)) {
        return FALSE;
    }

    // Verify it's a PE file
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }

    // Get the NT headers
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), NULL)) {
        return FALSE;
    }

    // Verify PE signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the import directory
    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.Size == 0) {
            return FALSE; // No import directory
        }

    // Read the import descriptor array
    ULONG dwImportDescSize = importDirectory.Size;
    ULONG dwNumEntries = dwImportDescSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    IMAGE_IMPORT_DESCRIPTOR* pImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)malloc(dwImportDescSize);

    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + importDirectory.VirtualAddress, pImportDesc, dwImportDescSize, NULL)) {
        free(pImportDesc);
        return FALSE;
    }

    BOOL bFound = FALSE;

    // Iterate through each import descriptor (DLL)
    for (ULONG i = 0; i < dwNumEntries; i++) {
        if (pImportDesc[i].OriginalFirstThunk == 0 && pImportDesc[i].FirstThunk == 0) {
            continue;
        }

        // Get the IAT and INT (OriginalFirstThunk is the INT, FirstThunk is the IAT)
        ULONG dwIAT = pImportDesc[i].FirstThunk;
        ULONG dwINT = pImportDesc[i].OriginalFirstThunk != 0 ? pImportDesc[i].OriginalFirstThunk : dwIAT;

        // Iterate through each function in this DLL's import
        ULONG dwThunkOffset = 0;
        while (TRUE) {
            IMAGE_THUNK_DATA thunkData;
            if (!ReadProcessMemory(hProcess, (BYTE*)hModule + dwINT + dwThunkOffset, &thunkData, sizeof(thunkData), NULL)) {
                break;
            }

            if (thunkData.u1.AddressOfData == 0) {
                break; // End of list
            }

            // Check if this is imported by name or ordinal
            if (!(thunkData.u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                // Imported by name - read the IMAGE_IMPORT_BY_NAME structure
                IMAGE_IMPORT_BY_NAME importByName;
                if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkData.u1.AddressOfData, &importByName, sizeof(importByName), NULL)) {
                    dwThunkOffset += sizeof(IMAGE_THUNK_DATA);
                    continue;
                }

                // Read the function name
                CHAR szFuncName[256] = { 0 };
                if (!ReadProcessMemory(hProcess, (BYTE*)hModule + thunkData.u1.AddressOfData + offsetof(IMAGE_IMPORT_BY_NAME, Name),
                    szFuncName, sizeof(szFuncName), NULL)) {
                    dwThunkOffset += sizeof(IMAGE_THUNK_DATA);
                    continue;
                }

                // Check if this is the function we're looking for
                if (strcmp(szFuncName, szFunctionName) == 0) {
                    // Found our function - modify the IAT entry
                    ULONG dwIATEntry = dwIAT + dwThunkOffset;
                    LPVOID lpIATAddress = (BYTE*)hModule + dwIATEntry;

                    // Write the new address
                    if (!WriteProcessMemory(hProcess, lpIATAddress, &lpNewAddress, sizeof(lpNewAddress), NULL)) {
                        free(pImportDesc);
                        return FALSE;
                    }

                    bFound = TRUE;
                    break;
                }
            }

            dwThunkOffset += sizeof(IMAGE_THUNK_DATA);
        }

        if (bFound) {
            break;
        }
    }

    free(pImportDesc);
    return bFound;
}
void Memory::setIATAddress(HANDLE handle, std::string moduleName, std::string moduleInIATName, std::string funcName, ULONGLONG newAddress)
{
    std::unordered_map<std::string, HMODULE> procModules = getModules(handle);
	if (!procModules.count(moduleName)) {
		spdlog::error("Module {} not found in process.", moduleName);
		return;
	}
    HMODULE module = procModules.at(moduleName);

    //read modules dos header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(handle, module, (LPVOID)&dosHeader, sizeof(dosHeader), 0)) {
        spdlog::error("Failed to read DOS header: {}", GetLastError());
        return;
    }

    //read the ntHeader using the offset provided in the dosHeader
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadProcessMemory(handle, (BYTE*)module + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), 0)) {
        spdlog::error("Failed to read NT headers: {}", GetLastError());
        return;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        spdlog::error("Invalid NT header signature!");
        return;
    }

    ULONG importDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    ULONG importDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (importDirSize == 0) return;
    

    IMAGE_IMPORT_DESCRIPTOR* importDescriptors = new IMAGE_IMPORT_DESCRIPTOR[importDirSize]{ 0 };
    if (!ReadProcessMemory(handle, (BYTE*)module + importDirRVA,
        importDescriptors, importDirSize, 0)) {
        spdlog::error("Failed to real module import descriptor!");
        return;
    }

    // iterate through each import descriptor (DLL)
    while (importDescriptors->Name != 0) {

        char dllName[MAX_PATH] = { 0 };
        if (!ReadProcessMemory(handle, (BYTE*)module + importDescriptors->Name, &dllName, MAX_PATH, nullptr)) {
            if (GetLastError() != 299) { //ignore partial read errors, they happen
                std::cerr << "Failed to read ID DLL name: " << GetLastError() << std::endl;
                break;
            }
        }
        if(dllName != moduleInIATName) {
            importDescriptors++;
            continue;
        }

        ULONG thunkRVA = importDescriptors->OriginalFirstThunk ? importDescriptors->OriginalFirstThunk : importDescriptors->FirstThunk;
        ULONG iatRVA = importDescriptors->FirstThunk;

        // read thunk data
        std::vector<IMAGE_THUNK_DATA> thunks;
        IMAGE_THUNK_DATA thunk;
        BYTE* thunkAddr = (BYTE*)module + thunkRVA;

        do {
            if (!ReadProcessMemory(handle, thunkAddr, &thunk, sizeof(IMAGE_THUNK_DATA), 0)) break;
            if (thunk.u1.AddressOfData == 0) break;

            thunks.push_back(thunk);
            thunkAddr += sizeof(IMAGE_THUNK_DATA);
        } while (true);

        // read IAT data
        std::vector<IMAGE_THUNK_DATA> iats;
        BYTE* iatAddr = (BYTE*)module + iatRVA;

        do {
            IMAGE_THUNK_DATA iat;
            if (!ReadProcessMemory(handle, iatAddr, &iat, sizeof(IMAGE_THUNK_DATA), 0)) break;
            if (iat.u1.Function == 0) break;

            iats.push_back(iat);
            iatAddr += sizeof(IMAGE_THUNK_DATA);
        } while (true);

        // match thunks with IAT entries
        for (size_t j = 0; j < thunks.size() && j < iats.size(); j++) {
            ULONGLONG funcAddr = iats[j].u1.Function;
            std::string name;
            if (thunks[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                //i will not be hnadling ordinal functions
                continue;
            }
            else {
                IMAGE_IMPORT_BY_NAME importByName;
                if (ReadProcessMemory(handle, (BYTE*)module + thunks[j].u1.AddressOfData, &importByName, sizeof(IMAGE_IMPORT_BY_NAME), 0)) {
                    char fn[256] = { 0 };
                    if (ReadProcessMemory(handle, (BYTE*)module + thunks[j].u1.AddressOfData + sizeof(WORD),
                        &fn, sizeof(fn) - 1, 0)) {
                        name = fn;
                    }
                    // Check if this is the function we're looking for
                    if (strcmp(fn, funcName.c_str()) == 0) {
                        // Found our function - modify the IAT entry
                        ULONG IATEntry = iatRVA + j*sizeof(IMAGE_THUNK_DATA);
                        LPVOID IATAddress = (BYTE*)module + IATEntry;

                        ULONG oldProt;
                        if (!VirtualProtectEx(handle, IATAddress, sizeof(LPVOID), PAGE_READWRITE, &oldProt)) {
                            spdlog::error("Failed to virtual protect IAT entry. Error: {}", GetLastError());
                        }

                        if (!WriteProcessMemory(handle, IATAddress, &newAddress, sizeof(newAddress), NULL)) {
							spdlog::error("Failed to write IAT entry. Error: {}", GetLastError());
                        }
                        else {
							spdlog::info("IAT entry for function {} in {} in {}'s IAT table modified to {}", funcName, moduleInIATName, moduleName, Util::toHexString(newAddress));
                        }

                        VirtualProtectEx(handle, IATAddress, sizeof(LPVOID), oldProt, &oldProt);

                        break;
                    }
                }
            }

        }
        importDescriptors++;
    }
    
}