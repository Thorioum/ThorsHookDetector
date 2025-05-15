#pragma once
#include "memory.hpp"
class Decompiler;

namespace GeneralHookHandler {

	void scanForHooks(std::string procName, HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff);
	void writeBytes(HANDLE handle, ULONGLONG address, std::vector<BYTE> bytes, ULONGLONG size);
	void writeBytes(HANDLE handle, ULONGLONG address, BYTE*, ULONGLONG size);

}

namespace InlineHookHandler {
	
	struct InlineHookedFunction {
		ULONGLONG funcRVA; //taken from EAT, relative to the module base address
		std::vector<BYTE> originalBytes;
		std::vector<BYTE> hookedBytes;
	};
	struct Result {
		//key - moduleName, value - map of function names and their original+hooked bytes  -- these are modules loaded into the proccess thats iterated
		std::unordered_map<std::string, std::unordered_map<std::string, InlineHookedFunction>> hookedFuncs;
	};
	Result scanForHooks(HANDLE procHandle, Decompiler* decompiler, std::vector<std::string> ignoredModules);

}

//values in the EAT are addresses relative to base address of the specific module their in
namespace EATHookHandler {
	struct EATHookedFunction {
		ULONGLONG originalRVA;
		ULONGLONG hookedRVA;
	};
	struct Result {
		//key - moduleName, value - the modules EAT table (key - funcName, value - original+hooked function address)
		std::unordered_map<std::string, std::unordered_map<std::string, EATHookedFunction>> hookedFuncs;
	};
	Result scanForHooks(HANDLE procHandle, Decompiler* decompiler, std::vector<std::string> ignoredModules);
}

//values in the IAT are addresses relative to base address of the process
namespace IATHookHandler {
	struct IATHookedFunction {
		ULONGLONG originalAddress;
		ULONGLONG hookedAddress;
	};
	struct Result {
		//key - moduleName, value - the modules IAT table (key - moduleName, value - map of exported function addresses in that module (key - funcName, value - original+hooked function address)
		std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, IATHookedFunction>>> hookedFuncs;
	};
	Result scanForHooks(HANDLE procHandle, Decompiler* decompiler, std::vector<std::string> ignoredModules);

}