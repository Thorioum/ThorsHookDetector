#include "../include/decompilation.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"

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

void Decompiler::printDecompilation(const std::vector<BYTE>& code, ULONGLONG address) {
    if (handle == NULL) return;

    cs_insn* insn;
    size_t count = cs_disasm(handle, code.data(), code.size(), address, 0, &insn);

    if (count > 0) {

        std::cout << std::left
            << std::setw(10) << "ADDRESS"
            << std::setw(20) << "BYTES"
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
                << std::setw(20) << bytes_str
                << std::setw(20) << insn[i].mnemonic
                << insn[i].op_str << std::endl;
        }


        cs_free(insn, count);
    }
    else {
        spdlog::error("Failed to disassemble bytes");
    }
}

static bool compare(cs_insn* insn1, cs_insn* insn2, int i, int j) {
    std::string string1;
    for (size_t m = 0; m < insn1[i].size; m++) {
        char byte[4];
        snprintf(byte, sizeof(byte), "%02x ", insn1[i].bytes[m]);
        string1 += byte;
    }

    std::string string2;
    for (size_t m = 0; m < insn2[j].size; m++) {
        char byte[4];
        snprintf(byte, sizeof(byte), "%02x ", insn1[j].bytes[m]);
        string2 += byte;
    }

    return strcmp(string1.c_str(), string2.c_str()) != 0;

}
int Decompiler::linesToPrint(cs_insn* insn1, cs_insn* insn2, size_t count1, size_t count2, ULONGLONG codeBaseAddr, ULONGLONG originalBaseAddr, bool print, size_t lines = 16) {

    if (count1 == 0 || count2 == 0) {
        spdlog::error("Failed to disassemble one or both byte blocks");
        if (count1 > 0) cs_free(insn1, count1);
        if (count2 > 0) cs_free(insn2, count2);
        return 0;
    }

    if (print) {
        std::cout << std::left
            << std::setw(10) << "ADDRESS"
            << std::setw(32) << "BYTES"
            << std::setw(20) << "MNEMONIC"
            << "OPERANDS" << std::endl;

        std::cout << std::string(80, '-') << std::endl;
    }

    size_t i = 0, j = 0;
    size_t lastModification = 0;
    while ((i < count1 || j < count2) && std::max(i,j) < lines) {
        if (i < count1 && j < count2 && insn1[i].address - codeBaseAddr == insn2[j].address - originalBaseAddr && std::max(i, j)) {
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

                    std::cout << COLOR_GREEN << "+"
                        << std::hex << std::setw(10) << insn1[i].address
                        << std::setw(32) << bytes_str1
                        << std::setw(20) << insn1[i].mnemonic
                        << insn1[i].op_str << COLOR_RESET << std::endl;

                    // Print original version (red)
                    std::string bytes_str2;
                    for (size_t k = 0; k < insn2[j].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn2[j].bytes[k]);
                        bytes_str2 += byte;
                    }

                    std::cout << COLOR_RED << "-"
                        << std::hex << std::setw(10) << insn2[j].address
                        << std::setw(32) << bytes_str2
                        << std::setw(20) << insn2[j].mnemonic
                        << insn2[j].op_str << COLOR_RESET << std::endl;
                }
                lastModification = i;
                i++;
                j++;
            }
        }
        else {
            // Addresses don't match - one code has extra instructions
            if (j >= count2 || (i < count1 && (j >= count2 ||
                (insn1[i].address - codeBaseAddr) < (insn2[j].address - originalBaseAddr)))) {
                // Extra instruction in code (green)
                if (print) {
                    std::string bytes_str;
                    for (size_t k = 0; k < insn1[i].size; k++) {
                        char byte[4];
                        snprintf(byte, sizeof(byte), "%02x ", insn1[i].bytes[k]);
                        bytes_str += byte;
                    }

                    std::cout << COLOR_GREEN << "+"
                        << std::hex << std::setw(10) << insn1[i].address
                        << std::setw(32) << bytes_str
                        << std::setw(20) << insn1[i].mnemonic
                        << insn1[i].op_str << COLOR_RESET << std::endl;
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

                    std::cout << COLOR_RED << "-"
                        << std::hex << std::setw(10) << insn2[j].address
                        << std::setw(32) << bytes_str
                        << std::setw(20) << insn2[j].mnemonic
                        << insn2[j].op_str << COLOR_RESET << std::endl;
                }
                j++;
            }
        }
    }
    if (print) {
        return 0;
    }
    else {
        return std::min(lastModification+12,std::max(count1,count2));
    }
}
void Decompiler::printDecompilationDiff(const std::vector<BYTE>& code, const std::vector<BYTE>& originalCode, ULONGLONG codeBaseAddr, ULONGLONG originalBaseAddr) {
    cs_insn* insn1, * insn2;
    size_t count1 = cs_disasm(handle, code.data(), code.size(), codeBaseAddr, 0, &insn1);
    size_t count2 = cs_disasm(handle, originalCode.data(), originalCode.size(), originalBaseAddr, 0, &insn2);
    size_t linesToRead = linesToPrint(insn1, insn2,count1,count2, codeBaseAddr, originalBaseAddr,false);
    linesToPrint(insn1, insn2,count1,count2, codeBaseAddr, originalBaseAddr, true,linesToRead);

    cs_free(insn1, count1);
    cs_free(insn2, count2);
}
