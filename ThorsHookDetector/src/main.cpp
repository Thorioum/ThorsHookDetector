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

	parser.add_argument("-p", "--process").required().help("the process to scan").default_value("firefox.exe");
    parser.add_argument("-l", "--loadlibs").flag().default_value< bool >(true).help("for every module in the target process, this process will try to load its modules with LoadLibrary. this may increase the amount of modules now loaded it can compare with, but if dll's are different versions it will incorrect detect functions as hooks when in reality they are different functions entirely");
    parser.add_argument("-d", "--ignorediff").flag().default_value< bool >(false).help("without this set to true, modules detected with different function offsets than the locally loaded one will be skipped on the premis that the process module is most likely a different version");

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
        bool loadlibs = parser.get< bool >("loadlibs");
        bool ignordiff = parser.get< bool >("ignorediff");

        ULONG procId = Memory::getProcId(procName);

        spdlog::info("Opening handle to {}. . .", procName);
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procId);
        
        if (handle == INVALID_HANDLE_VALUE || !handle) {
            spdlog::error("Error getting handle for process: {}", procName);
        }
        else {
            spdlog::info("Beginning inline analysis. . .");
            InlineHookHandler::scanForHooks(handle, decompiler, loadlibs, ignordiff);
            spdlog::info("Beginning IAT analysis. . .");
            IATHookHandler::scanForHooks(procName, handle, decompiler);
            spdlog::info("All Analysis Complete");
        }

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
