#pragma once
#include "memory.hpp"
class Decompiler;
namespace InlineHookHandler {
	
	void scanForHooks(HANDLE procHandle, Decompiler* decompiler);

}

namespace IATHookHandler {

	void scanForHooks(HANDLE procHandle, Decompiler* decompiler);

}