#include "../include/hookhandler.hpp"
#include "../include/util.hpp"
#include "../include/decompilation.hpp"

#include <spdlog/spdlog.h>
#include <iostream>
#include <winternl.h>
#include <TlHelp32.h>

InlineHookHandler::Result InlineHookHandler::scanForHooks(HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff) {
	InlineHookHandler::Result result;
	result.hookedFuncs = std::unordered_map<std::string, std::unordered_map<std::string, HookedFunction>>();
	result.ignoredModules = std::vector<std::string>();

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
				if (ignorediff) {
					spdlog::info("Found new function in \"{}\"!: \"{}\"", procModuleElement.first, procFuncElement.first);
					ULONG procFuncRVA = procFuncElement.second;
					auto procFuncBytes = Memory::readFuncBytes(procHandle, procModule, procFuncRVA, procFuncElement.first);
					Decompilation decomp = decompiler->decompile(procFuncBytes, procFuncRVA);
					decompiler->printDecompilation(decomp);
					cs_free(decomp.insn, decomp.count);
				}
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
			//it is then checked once more whether the new more accurate resized functions are equal in bytes/dissasembly
			//if not, they are printed and collected
			Decompilation decomp1 = decompiler->decompile(procFuncBytes, procFuncRVA);
			Decompilation decomp2 = decompiler->decompile(localFuncBytes, localFuncRVA);

			if (!decomp1.insn || !decomp2.insn) {
				spdlog::error("Failed to decompile function: {}. Error: {}", procFuncElement.first, GetLastError());
				continue;
			}
			if (procFuncRVA != localFuncRVA && !ignorediff) {
				spdlog::info("Skipping module \"{}\", as RVAs dont match. (Different DLL version?)", procModuleElement.first);
				result.ignoredModules.push_back(procModuleElement.first);
				break;
			}
			if (decompiler->printDecompilationDiff(procModuleElement.first, procFuncElement.first, decomp1, decomp2)) {
				std::string moduleKey = procModuleElement.first;
				std::string funcKey = procFuncElement.first;
				if (!result.hookedFuncs.count(moduleKey)) {
					result.hookedFuncs[moduleKey] = std::unordered_map<std::string, HookedFunction>();
				}
				HookedFunction hookFunc = {
					procFuncRVA,
					std::vector<BYTE>(localFuncBytes),
					std::vector<BYTE>(procFuncBytes)
				};
				result.hookedFuncs[moduleKey][funcKey] = hookFunc;
			}
			cs_free(decomp1.insn, decomp1.count);
			cs_free(decomp2.insn, decomp2.count);
			
		}
		Sleep(5);
	}
	return result;
}

IATHookHandler::Result IATHookHandler::scanForHooks(std::string procName, HANDLE procHandle, std::vector<std::string> ignoredModules, Decompiler* decompiler) {
	Result result;
	result.hookedFuncs = std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_map<std::string, IATHookedFunction>>>();

	std::unordered_map<std::string, HMODULE> localModules = Memory::getModules(GetCurrentProcess());
	std::unordered_map<std::string, HMODULE> procModules = Memory::getModules(procHandle);

	std::unordered_map<std::string, IATModule> procIAT = Memory::getIAT(procHandle);
	
	for (const auto& entryElement : procIAT) {
		IATModule entry = entryElement.second;

		for (const auto& entryElement2 : entry.moduleIAT) {
			if (!localModules.count(entryElement2.first) || !procModules.count(entryElement2.first)) continue;
			HMODULE localModule = localModules.at(entryElement2.first);
			HMODULE procModule = procModules.at(entryElement2.first);

			if (std::find(ignoredModules.begin(), ignoredModules.end(),entryElement2.first) != ignoredModules.end()) continue;

			for (const auto& entryElement3 : entryElement2.second.functions) {
				FARPROC procModuleFuncAddr = (FARPROC)entryElement3.second;
				FARPROC localModuleFuncAddr = GetProcAddress(localModule, entryElement3.first.c_str());
				ULONGLONG procModuleFuncRVA = (ULONGLONG)procModuleFuncAddr - (ULONGLONG)procModule;
				ULONGLONG localModuleFuncRVA = (ULONGLONG)localModuleFuncAddr - (ULONGLONG)localModule;

				if (procModuleFuncRVA == localModuleFuncRVA) continue; 
				
				if (!result.hookedFuncs.count(entryElement.first)) result.hookedFuncs[entryElement.first] = std::unordered_map<std::string, std::unordered_map<std::string, IATHookedFunction>>();
				if (!result.hookedFuncs[entryElement.first].count(entryElement2.first)) result.hookedFuncs[entryElement.first][entryElement2.first] = std::unordered_map<std::string, IATHookedFunction>();
				result.hookedFuncs[entryElement.first][entryElement2.first][entryElement3.first] = { 
					/*correct address*/((ULONGLONG)procModule + localModuleFuncRVA),/*correct base (the one given to us by external proc) + the correct rva (which we got from the local module)*/ 
					/*hooked address*/((ULONGLONG)(LONGLONG)procModuleFuncAddr)
				};
				spdlog::info("Found hook in {}'s IAT Table from module {}!: [{}] 0x{} -> 0x{}", entryElement.first, entryElement2.first, entryElement3.first, Util::toHexString((ULONGLONG)localModuleFuncAddr), Util::toHexString((ULONGLONG)procModuleFuncAddr));
			}
		}
	}

	return result;
}

void GeneralHookHandler::scanForHooks(std::string procName, HANDLE procHandle, Decompiler* decompiler, bool loadlibs, bool ignorediff) {
	spdlog::info("Beginning inline analysis. . .");

	InlineHookHandler::Result inlineResult = InlineHookHandler::scanForHooks(procHandle, decompiler, loadlibs, ignorediff);

	spdlog::info("Beginning IAT analysis. . .");

	IATHookHandler::Result iatResult = IATHookHandler::scanForHooks(procName, procHandle, inlineResult.ignoredModules, decompiler);
	if (iatResult.hookedFuncs.empty()) {
		spdlog::info("No hooks found in the IAT tables of all scanned modules.");
	}

	spdlog::info("All analysis completed!");
	spdlog::info("---");
	spdlog::info("---");
	spdlog::info("Command List:");
	spdlog::info("---");
	spdlog::info("---");

	spdlog::info("--- restore-inline <Module Name> <Function Name>");
	spdlog::info("uses results from the inline hook analysis and restores the functions bytes back to the original");
	spdlog::info("--- restore-inline-all (OPTIONAL)<Module Name>");
	spdlog::info("uses results from ALL FUNCTIONS in the inline hook analysis (in specific module if specified) and restores the functions bytes back to the original");

	spdlog::info("--- restore-iat <Module Name> <Module Name> <Function Name>");
	spdlog::info("uses results from iat hook analysis to restore addresses in the IAT table back from the hooked function to the original");
	spdlog::info("--- restore-iat-all");
	spdlog::info("uses results from ALL FUNCTIONS in iat hook analysis to restore addresses in the IAT table back from the hooked function to the original");

	spdlog::info("--- decompile <Relative Virtual Address> || <Module Name> <Function Name>");
	spdlog::info("decompiles the function at the specified address");

	std::cout << "Type command here: ";
	std::unordered_map<std::string, HMODULE> procModules = Memory::getModules(procHandle);

	std::string input;
	while (std::getline(std::cin, input)) {
		// Log the user input
		if (!Memory::handleIsStillValid(procHandle)) {
			spdlog::error("Process handle no longer valid. Exiting.");
			break;
		}
		if (!input.empty()) {
			std::vector<std::string> args = Util::split(input, ' ');
			std::string command = args.at(0);
			args.erase(args.begin());
			if (command == "break" || command == "exit" || command == "return" || command == "stop") {
				break;
			}
			else if (command == "restore-inline") {
				if (args.size() != 2) {
					spdlog::error("Invalid command format. Usage: restore <Module Name> <Function Name>");
					goto continueBlock;
				}
				std::string moduleName = args.at(0);
				std::string functionName = args.at(1);
				if (!procModules.count(moduleName)) {
					spdlog::error("Module {} not found in process.", moduleName);
					goto continueBlock;
				}
				if (!inlineResult.hookedFuncs.count(moduleName)) {
					spdlog::error("Module {} not found in hooked function results.", moduleName);
					goto continueBlock;
				}
				if (!inlineResult.hookedFuncs[moduleName].count(functionName)) {
					spdlog::error("Could not find function \"{}\" in hooked function results.",functionName);
					goto continueBlock;
				}

				HMODULE module = procModules[moduleName];

				if (inlineResult.hookedFuncs.count(moduleName) && inlineResult.hookedFuncs[moduleName].count(functionName)) {
					InlineHookHandler::HookedFunction hookedFunc = inlineResult.hookedFuncs[moduleName][functionName];

					spdlog::info("Opening a new handle to write with. . .");

					HANDLE writeHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Memory::getProcId(procName));

					LPVOID functionAddress = (BYTE*)module + inlineResult.hookedFuncs[moduleName][functionName].funcRVA;
					writeBytes(writeHandle, (ULONGLONG)functionAddress, hookedFunc.originalBytes, hookedFunc.hookedBytes.size());

					CloseHandle(writeHandle);

				}
				else {
					spdlog::error("Function {} not found in module {}.", functionName, moduleName);
				}
			}
			else if (command == "restore-inline-all") {
				std::string specificModuleName = "";
				if (args.size() > 0) {
					specificModuleName = args.at(0);
				}

				for (const auto& moduleElement : inlineResult.hookedFuncs) {
					if (specificModuleName != "" && moduleElement.first != specificModuleName) continue;

					std::string moduleName = moduleElement.first;
					HMODULE module = procModules[moduleName];

					spdlog::info("Restoring all functions in module {}. . .", moduleName);
					for (const auto& funcElement : inlineResult.hookedFuncs[moduleName]) {
						std::string functionName = funcElement.first;
						InlineHookHandler::HookedFunction hookedFunc = funcElement.second;

						HANDLE writeHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Memory::getProcId(procName));

						spdlog::info("Restoring function {}. . .", functionName);
						LPVOID functionAddress = (BYTE*)module + hookedFunc.funcRVA;
						writeBytes(writeHandle, (ULONGLONG)functionAddress, hookedFunc.originalBytes, hookedFunc.hookedBytes.size());

						CloseHandle(writeHandle);
					}
				}
			}
			else if (command == "restore-iat") {
				if (args.size() != 3) {
					spdlog::error("Invalid command format. Usage: restore-iat <Module Name> <Module Name> <Function Name>");
					goto continueBlock;
				}
				std::string moduleName = args.at(0);
				std::string moduleNameIAT = args.at(1);
				std::string functionName = args.at(2);
				if (!procModules.count(moduleName)) {
					spdlog::error("Module {} not found in process.", moduleName);
					goto continueBlock;
				}
				if (!iatResult.hookedFuncs.count(moduleName)) {
					spdlog::error("Module {} not found in hooked function results.", moduleName);
					goto continueBlock;
				}
				if (!iatResult.hookedFuncs[moduleName].count(moduleNameIAT)) {
					spdlog::error("Could not find module \"{}\" in hooked function results.", moduleNameIAT);
					goto continueBlock;
				}
				if (!iatResult.hookedFuncs[moduleName][moduleNameIAT].count(functionName)) {
					spdlog::error("Could not find function \"{}\" in hooked function results.",functionName);
					goto continueBlock;
				}

				IATHookHandler::IATHookedFunction hookedFunc = iatResult.hookedFuncs[moduleName][moduleNameIAT][functionName];

				spdlog::info("Opening a new handle to write with. . .");
				HANDLE writeHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Memory::getProcId(procName));

				spdlog::info("Restoring function {}. . .", functionName);
				Memory::setIATAddress(writeHandle, moduleName, moduleNameIAT, functionName, hookedFunc.originalAddress);

				CloseHandle(writeHandle);
			}
			else if (command == "restore-iat-all") {
				for (const auto& moduleElement : iatResult.hookedFuncs) {
					std::string moduleName = moduleElement.first;
					if (!procModules.count(moduleName)) {
						spdlog::error("Module {} not found in process.", moduleName);
						continue;
					}
					for (const auto& moduleElement2 : moduleElement.second) {
						std::string moduleNameIAT = moduleElement2.first;

						for (const auto& funcElement : moduleElement2.second) {
							std::string functionName = funcElement.first;

							IATHookHandler::IATHookedFunction hookedFunc = funcElement.second;

							spdlog::info("Opening a new handle to write with. . .");
							HANDLE writeHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Memory::getProcId(procName));

							spdlog::info("Restoring function {}. . .", functionName);
							Memory::setIATAddress(writeHandle, moduleName, moduleNameIAT, functionName, hookedFunc.originalAddress);

							CloseHandle(writeHandle);
						}
					}
				}
			}
			else if (command == "decompile") {
				if (args.size() != 1 && args.size() != 2) {
					spdlog::error("Invalid command format. Usage: decompile <Relative Virtual Address> || <Module Name> <Function Name> || <Module Name> <Relative Virtual Address>");
					goto continueBlock;
				}
				if (args.size() == 1) {
					try {
						ULONGLONG address = std::stoull(args.at(0), nullptr, 16);
						auto funcBytes = Memory::readFuncBytes(procHandle, address, 1024);
						Decompilation decomp = decompiler->decompile(funcBytes, address);
						decompiler->printDecompilation(decomp);
						cs_free(decomp.insn, decomp.count);
					}
					catch (const std::exception& ex) {
						spdlog::error("Error reading bytes from address: {}. Error: {}", args.at(0), ex.what());
						goto continueBlock;
					}
				}
				else {
					std::string moduleName = args.at(0);
					if (!procModules.count(moduleName)) {
						spdlog::error("Module {} not found in process.", moduleName);
						goto continueBlock;
					}
					HMODULE procModule = procModules[moduleName];

					std::string func = args.at(1);
					ULONG funcRVA = 0;
					try {
						funcRVA = std::stoull(func, nullptr, 16);
					}
					catch (const std::exception& ex) {
						std::unordered_map<std::string, ULONG> procModuleFunctions = Memory::getExportsFunctions(procHandle, procModule);
						if (!procModuleFunctions.count(func)) {
							spdlog::error("Function {} not found in function.", func);
							goto continueBlock;
						}
						funcRVA = procModuleFunctions.at(func);
					}
					
					std::vector<BYTE> funcBytes = Memory::readFuncBytes(procHandle, procModule, funcRVA, func);
					Decompilation decomp = decompiler->decompile(funcBytes, funcRVA);
					decompiler->printDecompilation(decomp);
					cs_free(decomp.insn, decomp.count);
				}
				}
			else {
				spdlog::error("Unknown command: {}", command);
			}
		}
		continueBlock:
		std::cout << "\nType Command Here: ";
	}
}

void GeneralHookHandler::writeBytes(HANDLE handle, ULONGLONG address, std::vector<BYTE> bytes, ULONGLONG size) {
	writeBytes(handle, address, bytes.data(), size);
}
void GeneralHookHandler::writeBytes(HANDLE handle, ULONGLONG address, BYTE* bytes, ULONGLONG size) {
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(handle, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi))) return;
	ULONGLONG protectSize = mbi.RegionSize;

	ULONG oldProtect;
	if (!(VirtualProtectEx(handle, &mbi.BaseAddress, protectSize, PAGE_EXECUTE_READWRITE, &oldProtect))) {
		spdlog::info("Error changing memory protection! Error: {}", GetLastError());
	}

	if (!WriteProcessMemory(handle, (LPVOID)address, bytes, size, 0)) {
		spdlog::info("Error writing bytes in module! Error: {}", GetLastError());
	}
	else {
		spdlog::info("Successfully wrote new bytes to {}.", Util::toHexString(address));
	}

	VirtualProtectEx(handle, &mbi.BaseAddress, protectSize, oldProtect, &oldProtect);
}