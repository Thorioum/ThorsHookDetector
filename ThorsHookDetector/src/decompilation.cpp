#include "../include/decompilation.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

Decompiler::Decompiler(cs_arch arch, cs_mode mode) {
	this->mode = mode;
	this->arch = arch;
    cs_err err;
	if ((err = cs_open(arch, mode, &handle)) != CS_ERR_OK) {
		spdlog::error("Failed to initialize Capstone: {}", cs_strerror(err));
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
}
Decompiler::~Decompiler() {
	cs_close(&handle);
}

void Decompiler::printDecompilation(Decompilation decomp) {
    if (handle == NULL) return;

    cs_insn* insn = decomp.insn;
    size_t count = decomp.count;

    std::cout << std::left
        << std::setw(10) << "ADDRESS"
        << std::setw(32) << "BYTES"
        << std::setw(20) << "MNEMONIC"
        << "OPERANDS" << std::endl;

    std::cout << std::string(80, '-') << std::endl;


    for (size_t i = 0; i < count; i++) {

        std::string bytes_str;
        for (size_t j = 0; j < insn[i].size; j++) {
            char byte[4];
            snprintf(byte, sizeof(byte), "%02x ", insn[i].bytes[j]);
            bytes_str += byte;
        }

        std::cout << std::hex << std::setw(10) << insn[i].address
            << std::setw(32) << bytes_str
            << std::setw(20) << insn[i].mnemonic
            << insn[i].op_str << std::endl;
    }
}
ULONGLONG Decompiler::estimateFuncSize(const std::vector<BYTE>& c, ULONGLONG baseAddr) {
    std::vector<BYTE> code;
    std::copy(c.begin(), c.end(), std::back_inserter(code));
    cs_insn* insn;
    size_t bytes_to_keep = 0;
    // Use code.data() to get the raw pointer and code.size() for the size
    size_t count = cs_disasm(handle, code.data(), code.size(), baseAddr, 0, &insn);

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

Decompilation Decompiler::decompile(std::vector<BYTE>& code, ULONGLONG baseAddr) {
    ULONGLONG sizeEstimate = estimateFuncSize(code, baseAddr);
    code.resize(sizeEstimate);
    cs_insn* insn;
    size_t count = cs_disasm(handle, code.data(), code.size(), baseAddr, 0, &insn);
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
std::pair<bool,size_t> Decompiler::linesToPrint(Decompilation decomp1, Decompilation decomp2, bool print, size_t lines = 16) {
    size_t count1 = decomp1.count;
    size_t count2 = decomp2.count;
    cs_insn* insn1 = decomp1.insn;
    cs_insn* insn2 = decomp2.insn;
    ULONGLONG baseAddr1 = decomp1.baseAddr;
    ULONGLONG baseAddr2 = decomp2.baseAddr;

    

    if (print) {
        std::cout << std::left
            << std::setw(10) << "ADDRESS"
            << std::setw(32) << "BYTES"
            << std::setw(20) << "MNEMONIC"
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
                    std::string bytes_str;
                    for (size_t k = 0; k < insn1[i].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn1[i].bytes[k]);
                        bytes_str += byte;
                    }

                    std::cout << std::hex << std::setw(10) << insn1[i].address
                        << std::setw(32) << bytes_str
                        << std::setw(20) << insn1[i].mnemonic
                        << insn1[i].op_str << std::endl;
                }
                i++;
                j++;
            }
            else {
                // Instructions at same address differ
                // Print code version (green)
                if (print) {
                    std::string bytes_str1;
                    for (size_t k = 0; k < insn1[i].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn1[i].bytes[k]);
                        bytes_str1 += byte;
                    }

                    setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "+"
                        << std::hex << std::setw(10) << insn1[i].address
                        << std::setw(32) << bytes_str1
                        << std::setw(20) << insn1[i].mnemonic
                        << insn1[i].op_str << std::endl;
                    resetColor();

                    // Print original version (red)
                    std::string bytes_str2;
                    for (size_t k = 0; k < insn2[j].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn2[j].bytes[k]);
                        bytes_str2 += byte;
                    }

                    setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cout << "-"
                        << std::hex << std::setw(10) << insn2[j].address
                        << std::setw(32) << bytes_str2
                        << std::setw(20) << insn2[j].mnemonic
                        << insn2[j].op_str << std::endl;
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
                // Extra instruction in code (green)
                if (print) {
                    std::string bytes_str;
                    for (size_t k = 0; k < insn1[i].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn1[i].bytes[k]);
                        bytes_str += byte;
                    }
                    setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
                    std::cout << "+"
                        << std::hex << std::setw(10) << insn1[i].address
                        << std::setw(32) << bytes_str
                        << std::setw(20) << insn1[i].mnemonic
                        << insn1[i].op_str << std::endl;
                    resetColor();

                }
                lastModification = i;
                i++;
            }
            else {
                // Extra instruction in original (red)
                if (print) {
                    std::string bytes_str;
                    for (size_t k = 0; k < insn2[j].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn2[j].bytes[k]);
                        bytes_str += byte;
                    }
                    setColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
                    std::cout << "-"
                        << std::hex << std::setw(10) << insn2[j].address
                        << std::setw(32) << bytes_str
                        << std::setw(20) << insn2[j].mnemonic
                        << insn2[j].op_str << std::endl;
                    resetColor();
                }

                j++;
            }
        }
    }
    if (print) {
        return { false,0 };
    }
    else {
        return { lastModification != -1,std::min(lastModification + 12,std::max(count1,count2)) };
    }
}
bool Decompiler::printDecompilationDiff(std::string moduleName, std::string funcName, Decompilation decomp1, Decompilation decomp2) {

    std::pair<bool,size_t> linesToRead = linesToPrint(decomp1,decomp2,false);
    if (!linesToRead.first) return false; //is not modified
    if(!funcName.empty()) spdlog::info("[{}] Found modified function!: {}",moduleName, funcName);
    linesToPrint(decomp1, decomp2, true,linesToRead.second);
    if ((decomp1.count - linesToRead.second) != 0) std::cout << "------ (" << (decomp1.count - linesToRead.second) << ") lines remaining. . . ------" << std::endl;
    return true;
}
