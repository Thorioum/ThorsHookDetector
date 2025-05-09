#pragma once
#include <vector>
#include <capstone/capstone.h>
#define NOMINMAX
#include <wtypes.h>
class Decompiler {
public:
	Decompiler() = delete;
	Decompiler(cs_arch arch, cs_mode mode);
	~Decompiler();

	void printDecompilation(const std::vector<BYTE>& code, ULONGLONG baseAddr);
	void printDecompilationDiff(const std::vector<BYTE>& code, const std::vector<BYTE>& originalCode, ULONGLONG codeBaseAddr, ULONGLONG originalBaseAddr);

private:
	int linesToPrint(cs_insn* insn1, cs_insn* insn2, size_t count1, size_t count2, ULONGLONG codeBaseAddr, ULONGLONG originalBaseAddr, bool print, size_t lines);
private:
	csh handle = NULL;
	cs_arch arch;
	cs_mode mode;
};