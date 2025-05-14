#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <unordered_map>

struct IATModuleEntry {
	std::string name;
	std::unordered_map<std::string, ULONGLONG> functions;
};
struct IATModule {
	std::string name;
	std::unordered_map<std::string, IATModuleEntry> moduleIAT;
};

namespace Memory {

	std::pair<HANDLE,ULONG> WaitForProcess(_In_ DWORD dwDesiredAccess, _In_ BOOL bInheritHandle, std::string procName);
	ULONG getProcId(std::string name);
	bool handleIsStillValid(HANDLE handle);

	ULONGLONG getModuleBaseAddr(ULONG procId, const char* modName);
	HMODULE getLoadedModule(HANDLE handle, const char* modName);

	//key - modName, value - module
	std::unordered_map<std::string,HMODULE> getModules(HANDLE handle);

	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, std::string funcName);
	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, ULONGLONG bytesToRead);
	std::vector<BYTE> readFuncBytes(HANDLE handle, ULONGLONG functionAddress, ULONGLONG bytesToRead);

	//checks the pdata section for exception info for a function that may be stored there
	ULONGLONG optionalCheckFuncSize(HANDLE handle, HMODULE module, std::string funcName, ULONG functionRVA);

	//key - funcName, value - funcRVA
	std::unordered_map<std::string, ULONG> getExportsFunctions(HANDLE handle, HMODULE module);

	//key moduleName
	std::unordered_map<std::string, IATModule> getIAT(HANDLE handle);
	void setIATAddress(HANDLE handle, std::string module, std::string moduleInIAT, std::string funcName, ULONGLONG newAddress);

}