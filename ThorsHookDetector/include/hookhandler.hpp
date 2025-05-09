#pragma once
#include "memory.hpp"
class Decompiler;
namespace InlineHookHandler {
	
	void scanForHooks(HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff);

}

namespace IATHookHandler {

	void scanForHooks(std::string procName, HANDLE procHandle, Decompiler* decompiler);

}