#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <string>
#include <unordered_map>

struct IATModuleEntry {
	std::string name;
	HMODULE module;
	std::unordered_map<std::string, ULONGLONG> functions;
};
namespace Memory {

	ULONG getProcId(std::string name);
	ULONGLONG getModuleBaseAddr(ULONG procId, const char* modName);
	HMODULE getLoadedModule(HMODULE parentModule, const char* modName);

	//key - modName, value - module
	std::unordered_map<std::string,HMODULE> getModules(HANDLE handle);

	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, std::string funcName);
	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, ULONGLONG bytesToRead);

	ULONGLONG optionalCheckFuncSize(HANDLE handle, HMODULE module, std::string funcName, ULONG functionRVA);

	//key - funcName, value - funcRVA
	std::unordered_map<std::string, ULONG> getExportsFunctions(HANDLE handle, HMODULE module);

	//key moduleName
	std::unordered_map<std::string, IATModuleEntry> getIAT(HANDLE handle, HMODULE module);

}