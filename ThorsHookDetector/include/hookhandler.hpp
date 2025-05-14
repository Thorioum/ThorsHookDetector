#pragma once
#include "memory.hpp"
class Decompiler;

namespace GeneralHookHandler {

	void scanForHooks(std::string procName, HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff);
	void writeBytes(HANDLE handle, ULONGLONG address, std::vector<BYTE> bytes, ULONGLONG size);
	void writeBytes(HANDLE handle, ULONGLONG address, BYTE*, ULONGLONG size);

}
namespace InlineHookHandler {
	struct HookedFunction {
		ULONGLONG funcRVA;
		std::vector<BYTE> originalBytes;
		std::vector<BYTE> hookedBytes;
	};
	struct Result {
		std::vector<std::string> ignoredModules;
		//key - moduleName, value - map of function names and their original+hooked bytes  -- these are modules loaded into the proccess thats iterated
		std::unordered_map<std::string, std::unordered_map<std::string, HookedFunction>> hookedFuncs;
	};
	Result scanForHooks(HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff);

}

namespace IATHookHandler {
	struct IATHookedFunction {
		ULONGLONG originalAddress;
		ULONGLONG hookedAddress;
	};
	struct Result {
		//key - moduleName, value - the modules IAT table (key - moduleName, value - map of exported function addresses in that module (key - funcName, value - original+hooked function address)
		std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, IATHookedFunction>>> hookedFuncs;
	};
	Result scanForHooks(std::string procName, HANDLE procHandle, std::vector<std::string> ignoredModules, Decompiler* decompiler);

}