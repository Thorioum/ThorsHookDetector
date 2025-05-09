// ThorsHookDetector.cpp : Defines the entry point for the application.
//

#include "argparse/argparse.hpp"
#include "spdlog/spdlog.h"
#include "../include/hookhandler.hpp"
#include "../include/decompilation.hpp"

int main(int argc, char* argv[])
{
	argparse::ArgumentParser parser("Thors-Hook-Detector");

	parser.add_description(
		"A program that analyzes the modules and IAT for hooks created by the process.\nWill only check locally loadable modules, if you want to compare with more add dlls to the same directory as this executable");
	parser.add_epilog("https://thorioum.net");

	parser.add_argument("-p", "--process").required().help("the process to scan").default_value("RobloxPlayerBeta.exe");

    try
    {
        parser.parse_args(argc, argv);
    }
    catch (const std::exception& ex)
    {
        spdlog::error("Error Parsing Args: {}", ex.what());
        return 1;
    }

    HANDLE handle;
    Decompiler* decompiler = new Decompiler(CS_ARCH_X86, CS_MODE_64);
    try
    {
        std::string procName = parser.get< std::string >("process");
        ULONG procId = Memory::getProcId(procName);

        spdlog::info("Opening handle to {}. . .", procName);
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
        
        if (handle == INVALID_HANDLE_VALUE) {
            spdlog::error("Error getting handle for process: {}", procName);
        }


        spdlog::info("Beginning inline analysis. . .");
        InlineHookHandler::scanForHooks(handle, decompiler);
        spdlog::info("Beginning IAT analysis. . .");
        IATHookHandler::scanForHooks(handle, decompiler);
        spdlog::info("All Analysis Complete");

    }
    catch (const std::exception& ex)
    {
        spdlog::error("Error during execution: {}", ex.what());
    }

    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle(handle);
    }
    delete decompiler;

	return 0;
}
