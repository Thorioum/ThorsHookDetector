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
	Decompiler(cs_arch arch);
	~Decompiler();

	Decompilation decompile(std::vector<BYTE>& code, ULONGLONG baseAddr, bool is64Bit);

	void printDecompilation(Decompilation decomp, ULONGLONG relativeBase);
	bool printDecompilationDiff(std::string moduleName, std::string funcName, Decompilation decomp1, Decompilation decomp2, ULONGLONG relativeBase);

private:
	std::pair<bool, size_t> linesToPrint(Decompilation decomp1, Decompilation decomp2, bool print, size_t lines, ULONGLONG relativeBase);
	ULONGLONG estimateFuncSize(const std::vector<BYTE>& code, ULONGLONG baseAddr, bool is64Bit);
	csh getHandle(bool is64Bit) const;
	std::string printLine(cs_insn& insn, std::string prefix, ULONGLONG base) const;
private:
	csh handle32 = NULL;
	csh handle64 = NULL;
	cs_arch arch;
};