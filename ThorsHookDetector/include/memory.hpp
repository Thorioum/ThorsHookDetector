#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <unordered_map>

namespace Memory {

	ULONG getProcId(std::string name);
	ULONGLONG getModuleBaseAddr(ULONG procId, const char* modName);

	//key - modName, value - module
	std::unordered_map<std::string,HMODULE> getModules(HANDLE handle);

	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, std::string funcName);
	std::vector<BYTE> readFuncBytes(HANDLE handle, HMODULE module, ULONG functionRVA, ULONGLONG bytesToRead);

	ULONGLONG estimateFuncSize(HANDLE handle, HMODULE module, std::string funcName, ULONG functionRVA);

	//key - funcName, value - funcRVA
	std::unordered_map<std::string, ULONG> getExportsFunctions(HANDLE handle, HMODULE module);
}