#include "../include/hookhandler.hpp"
#include "../include/util.hpp"
#include "../include/decompilation.hpp"

#include <spdlog/spdlog.h>
#include <iostream>
void InlineHookHandler::scanForHooks(HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff) {
	HANDLE localHandle = GetCurrentProcess();

	std::unordered_map<std::string,HMODULE> procModules = Memory::getModules(procHandle);
	//attempt to load all process modules into current process before parsing local modules
	if(loadlibs) for (auto& m : procModules) LoadLibrary(m.first.c_str());	
	std::unordered_map<std::string,HMODULE> localModules = Memory::getModules(localHandle);

	spdlog::info("Found {} modules in process with {} matching locally.", procModules.size(), Util::countMatchingKeys(procModules, localModules));
	for (auto& procModuleElement : procModules) {

		//check if this module has been also loaded locally
		//we can now compare the functions and their bytes in our unaltered version, and the processes modules
		if (!localModules.count(procModuleElement.first)) continue;

		spdlog::info("[] Processing Module \"{}\"", procModuleElement.first);

		HMODULE procModule = procModuleElement.second;
		std::unordered_map<std::string, ULONG> procModuleFunctions = Memory::getExportsFunctions(procHandle, procModule);
		HMODULE localModule = localModules.at(procModuleElement.first); 
		std::unordered_map<std::string, ULONG> localModuleFunctions = Memory::getExportsFunctions(localHandle, localModule);


		for (auto& procFuncElement : procModuleFunctions) {
			//new function?
			if (!localModuleFunctions.count(procFuncElement.first)) {
				spdlog::info("Found new function in \"{}\"!: \"{}\"", procModuleElement.first, procFuncElement.first);
				ULONG procFuncRVA = procFuncElement.second;
				auto procFuncBytes = Memory::readFuncBytes(procHandle, procModule, procFuncRVA, procFuncElement.first);
				Decompilation decomp = decompiler->decompile(procFuncBytes, procFuncRVA);
				decompiler->printDecompilation(decomp);
				cs_free(decomp.insn, decomp.count);
				continue;
			}

			ULONG procFuncRVA = procFuncElement.second;
			ULONG localFuncRVA = localModuleFunctions.at(procFuncElement.first);

			auto procFuncBytes = Memory::readFuncBytes(procHandle, procModule, procFuncRVA, procFuncElement.first);
			auto localFuncBytes = Memory::readFuncBytes(localHandle, localModule, localFuncRVA, procFuncElement.first);
			
			//modified..
			if(Util::byteVectorsEqual(procFuncBytes, localFuncBytes)) continue;

			//this code will check if the function (usually unestimated size) byte vectors are equal
			//if not, somewhere theres modification
			//the bytes will then be dissasembled then resized, trimming at a ret instruction for a better size estimate
			//it is then checked once more whether the new more accurate resized functions are equal
			//if not, they are printed
			Decompilation decomp1 = decompiler->decompile(procFuncBytes, procFuncRVA);
			Decompilation decomp2 = decompiler->decompile(localFuncBytes, localFuncRVA);
			if (!decomp1.insn || !decomp2.insn) continue;
			if (procFuncRVA != localFuncRVA && !ignorediff) {
				spdlog::info("Skipping module \"{}\", as RVAs dont match. (Different DLL version?)", procModuleElement.first);
				break;
			}
			if (decompiler->printDecompilationDiff(procModuleElement.first, procFuncElement.first, decomp1, decomp2)) {
				
			}
			cs_free(decomp1.insn, decomp1.count);
			cs_free(decomp2.insn, decomp2.count);
			
		}
		Sleep(5);
	}
}

void IATHookHandler::scanForHooks(std::string procName, HANDLE procHandle, Decompiler* decompiler) {

	std::unordered_map<std::string, HMODULE> procModules = Memory::getModules(procHandle);
	std::unordered_map<std::string, IATModuleEntry> iat = Memory::getIAT(procHandle, procModules.at(procName));
	for (const auto& entryElement : iat) {
		std::string name = entryElement.first;
		IATModuleEntry entry = entryElement.second;
		std::cout << "--" << name;
		for (const auto& entryElement2 : entry.functions) {
			std::cout << "[0x" << std::hex << entryElement2.second << "] " << entryElement2.first;
		}
	}
}
