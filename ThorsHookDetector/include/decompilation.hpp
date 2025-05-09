#pragma once
#include <vector>
#include <capstone/capstone.h>
#define NOMINMAX
#include <wtypes.h>
#include <string>

struct Decompilation {
	cs_insn* insn;
	size_t count;
	ULONGLONG baseAddr;
};

class Decompiler {
public:
	Decompiler() = delete;
	Decompiler(cs_arch arch, cs_mode mode);
	~Decompiler();

	Decompilation decompile(std::vector<BYTE>& code, ULONGLONG baseAddr);

	void printDecompilation(Decompilation decomp);
	bool printDecompilationDiff(std::string moduleName, std::string funcName, Decompilation decomp1, Decompilation decomp2);

private:
	std::pair<bool, size_t> linesToPrint(Decompilation decomp1, Decompilation decomp2, bool print, size_t lines);
	ULONGLONG estimateFuncSize(const std::vector<BYTE>& code, ULONGLONG baseAddr);
private:
	csh handle = NULL;
	cs_arch arch;
	cs_mode mode;
};