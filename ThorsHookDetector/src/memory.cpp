#include "../include/memory.hpp"
#include <TlHelp32.h>
#include <memory>
#include <Psapi.h>
#include <spdlog/spdlog.h>
#include <iostream>

struct HandleDisposer {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};
using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

ULONG Memory::getProcId(std::string name) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(MODULEENTRY32);

    const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

    if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
        return NULL;

    while (Process32Next(snapshot_handle.get(), &procEntry) == TRUE) {
        if (name.compare(procEntry.szExeFile) == NULL) {
            return procEntry.th32ProcessID;
        }
    }
    return NULL;
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
HMODULE Memory::getLoadedModule(HMODULE parentModule, const char* modName) {
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), parentModule, &moduleInfo, sizeof(moduleInfo))) {
        return NULL;
    }


    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32)) {
        CloseHandle(hModuleSnap);
        return NULL;
    }

    HMODULE foundModule = NULL;
    do {

        if ((ULONGLONG)me32.modBaseAddr >= (ULONGLONG)moduleInfo.lpBaseOfDll &&
            (ULONGLONG)me32.modBaseAddr < (ULONGLONG)moduleInfo.lpBaseOfDll + moduleInfo.SizeOfImage) {


            if (_stricmp(me32.szModule, modName) == 0) {
                foundModule = (HMODULE)me32.modBaseAddr;
                break;
            }
        }
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return foundModule;
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

    std::vector<BYTE> functionBytes;

    LPVOID functionAddress = (BYTE*)module + functionRVA;

    functionBytes.resize(bytesToRead);

    ULONG_PTR bytesRead;
    if (!ReadProcessMemory(handle, functionAddress, functionBytes.data(), bytesToRead, &bytesRead)) {
        if (GetLastError() != 299) { //status partial copy
            spdlog::error("Failed to read function bytes. Error: {}", GetLastError());
            return {};
        }
    }

    if (bytesRead != bytesToRead) {
        spdlog::error("Failed to read all function bytes. Only read {} of {} bytes",bytesRead,bytesToRead);
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

    std::unordered_map< std::string, ULONG> exportMap = std::unordered_map< std::string, DWORD>();

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
    DWORD exportDirRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportDirSize = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

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


    //
    // Read function address table
    std::vector<DWORD> functions(exportDir.NumberOfFunctions);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfFunctions,
        functions.data(),
        exportDir.NumberOfFunctions * sizeof(DWORD),0)) {
        spdlog::error("Failed to read function addresses: ", GetLastError());
        return exportMap;
    }

    // Read name pointer table
    std::vector<DWORD> names(exportDir.NumberOfNames);
    if (!ReadProcessMemory(handle,
        (BYTE*)module + exportDir.AddressOfNames,
        names.data(),
        exportDir.NumberOfNames * sizeof(DWORD),0)) {
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
    std::vector<DWORD> executableRanges;
    for (const auto& section : sections) {
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            executableRanges.push_back(section.VirtualAddress);
            executableRanges.push_back(section.VirtualAddress + section.Misc.VirtualSize);
        }
    }

    for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {

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
        DWORD functionRVA = functions[ordinals[i]];
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

std::unordered_map<std::string, IATModuleEntry> Memory::getIAT(HANDLE handle, HMODULE module) {

    std::unordered_map<std::string, IATModuleEntry> iat = std::unordered_map<std::string, IATModuleEntry>();
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

    // get the import directory
    IMAGE_DATA_DIRECTORY importDirectory = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.Size == 0) {
        std::cerr << "No import directory found" << std::endl;
        return iat;
    }

    // read the import descriptor array
    IMAGE_IMPORT_DESCRIPTOR* importDescriptors = (IMAGE_IMPORT_DESCRIPTOR*)malloc(importDirectory.Size);
    LPVOID importDescAddr = (LPVOID)((DWORD_PTR)module + importDirectory.VirtualAddress);
    if (!ReadProcessMemory(handle, importDescAddr, importDescriptors, importDirectory.Size, nullptr)) {
        std::cerr << "Failed to read import descriptors: " << GetLastError() << std::endl;
        free(importDescriptors);
        return iat;
    }
     



    // iterate through each import descriptor (DLL)
    for (int i = 0; importDescriptors[i].Characteristics != 0; i++) {

        char dllName[MAX_PATH] = { 0 };
        LPVOID dllNameAddr = (LPVOID)((ULONGLONG)handle + importDescriptors[i].Name);
        if (!ReadProcessMemory(handle, dllNameAddr, &dllName, MAX_PATH, nullptr)) {
            if (GetLastError() != 299) { //ignore partial read errors, they happen
                std::cerr << "Failed to read ID DLL name: " << GetLastError() << std::endl;
                continue;
            }
        }
        HMODULE childModule = getLoadedModule(module, dllName);
        if (!childModule) {
            std::cout << "failed to get child module" << std::endl;
            continue;
        }
        // get the original thunk (INT) and the IAT
        IMAGE_THUNK_DATA* originalThunk = nullptr;
        IMAGE_THUNK_DATA* iatThunk = nullptr;

        if (importDescriptors[i].OriginalFirstThunk) {
            originalThunk = (IMAGE_THUNK_DATA*)malloc(sizeof(IMAGE_THUNK_DATA));
            LPVOID originalThunkAddr = (LPVOID)((ULONGLONG)handle + importDescriptors[i].OriginalFirstThunk);
            if (!ReadProcessMemory(handle, originalThunkAddr, originalThunk, sizeof(IMAGE_THUNK_DATA), nullptr)) {
                std::cerr << "Failed to read original thunk for ID DLL " << GetLastError() << std::endl;
                free(originalThunk);
                continue;
            }
        }

        iatThunk = (IMAGE_THUNK_DATA*)malloc(sizeof(IMAGE_THUNK_DATA));
        LPVOID iatThunkAddr = (LPVOID)((DWORD_PTR)module + importDescriptors[i].FirstThunk);
        if (!ReadProcessMemory(handle, iatThunkAddr, iatThunk, sizeof(IMAGE_THUNK_DATA), nullptr)) {
            std::cerr << "ReadProcessMemory failed for IAT thunk: " << GetLastError() << std::endl;
            free(originalThunk);
            free(iatThunk);
            continue;
        }

        IATModuleEntry entry = {};
        entry.name = dllName;
        entry.module = childModule;
        // iterate through each function in the IAT
        std::unordered_map<std::string, ULONGLONG> functionAddresses = std::unordered_map<std::string, ULONGLONG>();

        for (int j = 0; originalThunk ? (originalThunk[j].u1.AddressOfData != 0) : (iatThunk[j].u1.Function != 0); j++) {

            ULONGLONG addr = (ULONGLONG)iatThunk[j].u1.Function;

            // check if function is imported by ordinal or by name
            char* funcName = 0;
            if (originalThunk && (originalThunk[j].u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) {
                // import by name - read the IMAGE_IMPORT_BY_NAME structure
                IMAGE_IMPORT_BY_NAME importByName;
                LPVOID importByNameAddr = (LPVOID)((DWORD_PTR)module + originalThunk[j].u1.AddressOfData);
                if (ReadProcessMemory(handle, importByNameAddr, &importByName, sizeof(IMAGE_IMPORT_BY_NAME), nullptr)) {
                    funcName = (char*)importByName.Name;
                }
            }
            else {
                //im not gonna handle ordinal function imports
            }
            if (funcName) {
                functionAddresses[std::string(funcName)] = addr;
            }
        }
        entry.functions = functionAddresses;

        free(originalThunk);
        free(iatThunk);
    }

    free(importDescriptors);

    return iat;
}


