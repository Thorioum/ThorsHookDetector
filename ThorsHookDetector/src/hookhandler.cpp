#include "../include/hookhandler.hpp"
#include "../include/util.hpp"
#include "../include/decompilation.hpp"

#include <spdlog/spdlog.h>
#include <iostream>
void InlineHookHandler::scanForHooks(HANDLE procHandle, Decompiler* decompiler) {
	HANDLE localHandle = GetCurrentProcess();

	std::unordered_map<std::string,HMODULE> procModules = Memory::getModules(procHandle);
	std::unordered_map<std::string,HMODULE> localModules = Memory::getModules(localHandle);

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

			if (!localModuleFunctions.count(procFuncElement.first)) {
				spdlog::info("Found new function in \"{}\"!: \"{}\"", procModuleElement.first, procFuncElement.first);
				//dump bytes here
				continue;
			}

			ULONG procFuncRVA = procFuncElement.second;
			ULONG localFuncRVA = localModuleFunctions.at(procFuncElement.first);

			auto procFuncBytes = Memory::readFuncBytes(procHandle, procModule, procFuncRVA, procFuncElement.first);
			auto localFuncBytes = Memory::readFuncBytes(localHandle, localModule, localFuncRVA, procFuncElement.first);
			
			//modified..
			if (!Util::byteVectorsEqual(procFuncBytes, localFuncBytes)) {
				spdlog::info("Found modified function!: {}", procFuncElement.first);
				decompiler->printDecompilationDiff(procFuncBytes, localFuncBytes, procFuncRVA, localFuncRVA);
			}
		}
	}
}

void IATHookHandler::scanForHooks(HANDLE procHandle, Decompiler* decompiler) {

}
