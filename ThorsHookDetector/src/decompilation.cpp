#include "../include/decompilation.hpp"
#include "../include/memory.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

Decompiler::Decompiler(cs_arch arch) {
	this->arch = arch;
    cs_err err;
	if ((err = cs_open(arch, CS_MODE_32, &handle32)) != CS_ERR_OK) {
		spdlog::error("Failed to initialize 32x Capstone: {}", cs_strerror(err));
	}
    if ((err = cs_open(arch, CS_MODE_64, &handle64)) != CS_ERR_OK) {
        spdlog::error("Failed to initialize 64x Capstone: {}", cs_strerror(err));
    }
	cs_option(handle32, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle32, CS_OPT_SKIPDATA, CS_OPT_ON);

    cs_option(handle64, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle64, CS_OPT_SKIPDATA, CS_OPT_ON);
}
Decompiler::~Decompiler() {
	cs_close(&handle32);
    cs_close(&handle64);
}

void Decompiler::printDecompilation(Decompilation decomp, ULONGLONG relativeBase) {

    cs_insn* insn = decomp.insn;
    size_t count = decomp.count;

    std::cout << std::left
        << std::setw(10) << "ADDRESS"
        << std::setw(32) << "BYTES"
        << std::setw(20) << "MNEMONIC"
        << "OPERANDS" << std::endl;

    std::cout << std::string(80, '-') << std::endl;


    for (size_t i = 0; i < count; i++) {

        printLine(insn[i], "", relativeBase);

    }
}
ULONGLONG Decompiler::estimateFuncSize(const std::vector<BYTE>& c, ULONGLONG baseAddr, bool is64Bit) {
    std::vector<BYTE> code;
    std::copy(c.begin(), c.end(), std::back_inserter(code));
    cs_insn* insn;
    size_t bytes_to_keep = 0;
    // Use code.data() to get the raw pointer and code.size() for the size
    size_t count = cs_disasm(getHandle(is64Bit), code.data(), code.size(), baseAddr, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            bytes_to_keep += insn[i].size;

            // Check for return instruction
            bool is_return = false;
            if (insn[i].detail) {
                for (uint8_t g = 0; g < insn[i].detail->groups_count; g++) {
                    if (insn[i].detail->groups[g] == CS_GRP_RET) {
                        is_return = true;
                        break;
                    }
                }
            }

            // Architecture-specific checks
            switch (arch) {
            case CS_ARCH_X86:
                if (insn[i].id == X86_INS_RET ||
                    insn[i].id == X86_INS_RETF) {
                    is_return = true;
                }
                break;
            case CS_ARCH_ARM64:
                if (insn[i].id == ARM64_INS_RET) {
                    is_return = true;
                }
                break;
                // Add other architectures as needed
            default:
                break;
            }

            if (is_return) {
                break;
            }
        }
        cs_free(insn, count);
    }

    return bytes_to_keep+1;
}

Decompilation Decompiler::decompile(std::vector<BYTE>& code, ULONGLONG baseAddr, bool is64Bit) {
    ULONGLONG sizeEstimate = estimateFuncSize(code, baseAddr,is64Bit);
    code.resize(sizeEstimate);
    cs_insn* insn;
    size_t count = cs_disasm(getHandle(is64Bit), code.data(), code.size(), baseAddr, 0, &insn);
    if (count == 0) {
        spdlog::error("Failed to disassemble bytes");
        return {0};
    }
    return Decompilation(insn, count, baseAddr);
}

void setColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}
void resetColor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

std::pair<bool,size_t> Decompiler::linesToPrint(Decompilation decomp1, Decompilation decomp2, bool print, size_t lines, ULONGLONG relativeBase) {
    size_t count1 = decomp1.count;
    size_t count2 = decomp2.count;
    cs_insn* insn1 = decomp1.insn;
    cs_insn* insn2 = decomp2.insn;
    ULONGLONG baseAddr1 = decomp1.baseAddr;
    ULONGLONG baseAddr2 = decomp2.baseAddr;

    

    if (print) {
        std::cout << std::string(80, '-') << std::endl;

        std::cout << std::left
            << std::setw(31) << "    ADDRESS"
            << std::setw(26) << "BYTES"
            << std::setw(15) << "MNEMONIC"
            << "OPERANDS" << std::endl;

        std::cout << std::string(80, '-') << std::endl;
    }

    size_t i = 0, j = 0;
    size_t lastModification = -1;
    while ((i < count1 || j < count2) && std::max(i,j) < lines) {
        if (i < count1 && j < count2 && insn1[i].address - baseAddr1 == insn2[j].address - baseAddr2) {
            // Addresses match, compare the instructions
            if (insn1[i].size == insn2[j].size &&
                memcmp(insn1[i].bytes, insn2[j].bytes, insn1[i].size) == 0) {
                // Instructions match
                if (print) {
                    printLine(insn1[i], "", relativeBase);

                }
                i++;
                j++;
            }
            else {
                // Instructions at same address differ
                if (print) {
                    setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    printLine(insn1[i], "+", relativeBase);
                    resetColor();

                    setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    printLine(insn2[j], "-", relativeBase);
                    resetColor();
                }
                lastModification = i;
                i++;
                j++;
            }
        }
        else {
            // Addresses don't match - one code has extra instructions
            if (j >= count2 || (i < count1 && (j >= count2 ||
                (insn1[i].address - baseAddr1) < (insn2[j].address - baseAddr2)))) {
                if (print) {

                    setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    printLine(insn1[i],"+", relativeBase);
                    resetColor();

                }
                lastModification = i;
                i++;
            }
            else {
                if (print) {
                    
                    setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					printLine(insn2[j], "-", relativeBase);
                    resetColor();
                }

                j++;
            }
        }
    }
    if (print) {
        std::cout << std::string(80, '-') << std::endl;
        return { false,0 };
    }
    else {
        return { lastModification != -1,std::min(lastModification + 12,std::max(count1,count2)) };
    }
}
bool Decompiler::printDecompilationDiff(std::string moduleName, std::string funcName, Decompilation decomp1, Decompilation decomp2, ULONGLONG relativeBase) {

    std::pair<bool,size_t> linesToRead = linesToPrint(decomp1,decomp2,false,16,relativeBase);
    if (!linesToRead.first) return false; //is not modified
    if(!funcName.empty()) spdlog::info("[{}] Found modified function!: {}",moduleName, funcName);
    linesToPrint(decomp1, decomp2, true,linesToRead.second, relativeBase);
    if ((decomp1.count - linesToRead.second) != 0) std::cout << "------ (" << std::dec << (decomp1.count - linesToRead.second) << ") lines remaining. . . ------" << std::endl;
    return true;
}
csh Decompiler::getHandle(bool is64Bit) const
{
    if (is64Bit) {
        return handle64;
    }
    return handle32;
}
std::string Decompiler::printLine(cs_insn& insn, std::string prefix, ULONGLONG base) const
{
    std::string bytes_str;
    for (size_t k = 0; k < insn.size; k++) {
        char byte[4];
        snprintf(byte, sizeof(byte), "%02x ", insn.bytes[k]);
        bytes_str += byte;
    }
    std::ostringstream extraBaseStream;
    extraBaseStream << std::hex << insn.address;
    if(base) extraBaseStream << " (" << std::hex << (insn.address - base) << ")";
    
	std::string addr = extraBaseStream.str();

    std::cout << std::setw(1) << prefix << std::hex << std::setw(30) << addr
        << std::setw(26) << bytes_str
        << std::setw(15) << insn.mnemonic
        << insn.op_str << std::endl;

    return std::string();
}