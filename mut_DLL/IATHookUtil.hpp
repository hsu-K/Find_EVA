#pragma once
#include "syscalls.h"


ULONG_PTR GetJumpAddr(void* hookFuncAddr) {
	BYTE jumpInstruction[5]; // 跳轉指令通常是 5 個字節
	SIZE_T bytesRead;
	ULONG_PTR targetAddr = 0;
	// 使用 ReadProcessMemory 讀取跳轉指令
	ReadProcessMemory(GetCurrentProcess(), hookFuncAddr, jumpInstruction, sizeof(jumpInstruction), &bytesRead);
	if (jumpInstruction[0] == 0xe9) { // e9 是相對跳轉指令
		// 計算目標地址
		ULONG_PTR offset = *(INT32*)&jumpInstruction[1]; // 取得偏移量
		targetAddr = (ULONG_PTR)hookFuncAddr + 5 + offset; // 跳轉指令長度是 5
		//std::cout << "最終函數地址: " << std::hex << targetAddr << std::endl;
	}
	else {
		//std::cout << "不是跳轉指令" << std::endl;
	}

	//*targetFunAddrPtr = (ULONG_PTR)hookFuncAddr;
	/*直接使用(ULONG_PTR)hookFuncAddr
	得到的會是一個間接跳轉指令，需要計算最終的目標位置*/
	// Initialize targetAddr to 0 before using it
	if (targetAddr) {
		return targetAddr;
	}
	return (ULONG_PTR)hookFuncAddr;
}

// 虛假的GetProcAddress
FARPROC WINAPI HookGetProcAddress( HMODULE hModule, LPCSTR lpProcName) {
	if (_stricmp(lpProcName, "NtOpenKey") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenKey); }
	if (_stricmp(lpProcName, "NtOpenKeyEx") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenKeyEx); }
	if (_stricmp(lpProcName, "NtQueryValueKey") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryValueKey); }
	if (_stricmp(lpProcName, "NtCreateKey") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateKey); }
	if (_stricmp(lpProcName, "NtEnumerateKey") == 0) { return (FARPROC)GetJumpAddr(HookNtEnumerateKey); }
	if (_stricmp(lpProcName, "NtEnumerateValueKey") == 0) { return (FARPROC)GetJumpAddr(HookNtEnumerateValueKey); }
	if (_stricmp(lpProcName, "NtCreateFile") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateFile); }
	if (_stricmp(lpProcName, "NtQueryAttributesFile") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryAttributesFile); }
	if (_stricmp(lpProcName, "NtDeviceIoControlFile") == 0) { return (FARPROC)GetJumpAddr(HookNtDeviceIoControlFile); }
	if (_stricmp(lpProcName, "NtQueryVolumeInformationFile") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryVolumeInformationFile); }
	if (_stricmp(lpProcName, "NtQuerySystemInformation") == 0) { return (FARPROC)GetJumpAddr(HookNtQuerySystemInformation); }
	if (_stricmp(lpProcName, "NtQuerySystemInformationEx") == 0) { return (FARPROC)GetJumpAddr(HookNtQuerySystemInformationEx); }
	if (_stricmp(lpProcName, "NtPowerInformation") == 0) { return (FARPROC)GetJumpAddr(HookNtPowerInformation); }
	if (_stricmp(lpProcName, "NtQueryLicenseValue") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryLicenseValue); }
	if (_stricmp(lpProcName, "NtQueryDirectoryFile") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryDirectoryFile); }
	if (_stricmp(lpProcName, "NtQueryInformationProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryInformationProcess); }
	if (_stricmp(lpProcName, "NtQueryDirectoryObject") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryDirectoryObject); }
	if (_stricmp(lpProcName, "NtCreateMutant") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateMutant); }
	if (_stricmp(lpProcName, "GetAdaptersAddresses") == 0) { return (FARPROC)GetJumpAddr(HookGetAdaptersAddresses); }
	if (_stricmp(lpProcName, "Process32FirstW") == 0) { return (FARPROC)GetJumpAddr(HookProcess32FirstW); }
	if (_stricmp(lpProcName, "Process32NextW") == 0) { return (FARPROC)GetJumpAddr(HookProcess32NextW); }
	if (_stricmp(lpProcName, "CoCreateInstance") == 0) { return (FARPROC)GetJumpAddr(HookCoCreateInstance); }
	if (_stricmp(lpProcName, "GetModuleHandleW") == 0) { return (FARPROC)GetJumpAddr(HookGetModuleHandleW); }
	if (_stricmp(lpProcName, "GetModuleHandleA") == 0) { return (FARPROC)GetJumpAddr(HookGetModuleHandleA); }
	if (_stricmp(lpProcName, "GetModuleHandleExW") == 0) { return (FARPROC)GetJumpAddr(HookGetModuleHandleExW); }
	if (_stricmp(lpProcName, "GetModuleHandleExA") == 0) { return (FARPROC)GetJumpAddr(HookGetModuleHandleExA); }
	if (_stricmp(lpProcName, "GetAdaptersInfo") == 0) { return (FARPROC)GetJumpAddr(HookGetAdaptersInfo); }
	if (_stricmp(lpProcName, "SetupDiGetDeviceRegistryPropertyW") == 0) { return (FARPROC)GetJumpAddr(HookSetupDiGetDeviceRegistryPropertyW); }
	if (_stricmp(lpProcName, "SetupDiGetDeviceRegistryPropertyA") == 0) { return (FARPROC)GetJumpAddr(HookSetupDiGetDeviceRegistryPropertyA); }
	if (_stricmp(lpProcName, "GetLastInputInfo") == 0) { return (FARPROC)GetJumpAddr(HookGetLastInputInfo); }
	if (_stricmp(lpProcName, "EnumServicesStatusExA") == 0) { return (FARPROC)GetJumpAddr(HookEnumServicesStatusExA); }
	if (_stricmp(lpProcName, "EnumServicesStatusExW") == 0) { return (FARPROC)GetJumpAddr(HookEnumServicesStatusExW); }
	if (_stricmp(lpProcName, "InternetCheckConnectionA") == 0) { return (FARPROC)GetJumpAddr(HookInternetCheckConnectionA); }
	if (_stricmp(lpProcName, "InternetCheckConnectionW") == 0) { return (FARPROC)GetJumpAddr(HookInternetCheckConnectionW); }
	if (_stricmp(lpProcName, "GetWindowRect") == 0) { return (FARPROC)GetJumpAddr(HookGetWindowRect); }
	if (_stricmp(lpProcName, "GetMonitorInfoA") == 0) { return (FARPROC)GetJumpAddr(HookGetMonitorInfoA); }
	if (_stricmp(lpProcName, "GetMonitorInfoW") == 0) { return (FARPROC)GetJumpAddr(HookGetMonitorInfoW); }
	if (_stricmp(lpProcName, "FindWindowA") == 0) { return (FARPROC)GetJumpAddr(HookFindWindowA); }
	if (_stricmp(lpProcName, "FindWindowW") == 0) { return (FARPROC)GetJumpAddr(HookFindWindowW); }
	if (_stricmp(lpProcName, "FindWindowExA") == 0) { return (FARPROC)GetJumpAddr(HookFindWindowExA); }
	if (_stricmp(lpProcName, "FindWindowExW") == 0) { return (FARPROC)GetJumpAddr(HookFindWindowExW); }
	if (_stricmp(lpProcName, "GetCursorPos") == 0) { return (FARPROC)GetJumpAddr(HookGetCursorPos); }
	if (_stricmp(lpProcName, "GetSystemMetrics") == 0) { return (FARPROC)GetJumpAddr(HookGetSystemMetrics); }
	if (_stricmp(lpProcName, "SystemParametersInfoA") == 0) { return (FARPROC)GetJumpAddr(HookSystemParametersInfoA); }
	if (_stricmp(lpProcName, "SystemParametersInfoW") == 0) { return (FARPROC)GetJumpAddr(HookSystemParametersInfoW); }
	if (_stricmp(lpProcName, "GetAsyncKeyState") == 0) { return (FARPROC)GetJumpAddr(HookGetAsyncKeyState); }
	if (_stricmp(lpProcName, "GetForegroundWindow") == 0) { return (FARPROC)GetJumpAddr(HookGetForegroundWindow); }
	if (_stricmp(lpProcName, "LoadLibraryExW") == 0) { return (FARPROC)GetJumpAddr(HookLoadLibraryExW); }
	if (_stricmp(lpProcName, "LoadLibraryExA") == 0) { return (FARPROC)GetJumpAddr(HookLoadLibraryExA); }
	if (_stricmp(lpProcName, "LoadLibraryW") == 0) { return (FARPROC)GetJumpAddr(HookLoadLibraryW); }
	if (_stricmp(lpProcName, "LoadLibraryA") == 0) { return (FARPROC)GetJumpAddr(HookLoadLibraryA); }

	// activity
	if (_stricmp(lpProcName, "NtOpenFile") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenFile); }
	if (_stricmp(lpProcName, "NtReadFile") == 0) { return (FARPROC)GetJumpAddr(HookNtReadFile); }
	if (_stricmp(lpProcName, "NtWriteFile") == 0) { return (FARPROC)GetJumpAddr(HookNtWriteFile); }
	if (_stricmp(lpProcName, "NtDeleteFile") == 0) { return (FARPROC)GetJumpAddr(HookNtDeleteFile); }
	if (_stricmp(lpProcName, "NtQueryInformationFile") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryInformationFile); }
	if (_stricmp(lpProcName, "NtSetInformationFile") == 0) { return (FARPROC)GetJumpAddr(HookNtSetInformationFile); }
	if (_stricmp(lpProcName, "NtOpenDirectoryObject") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenDirectoryObject); }
	if (_stricmp(lpProcName, "NtCreateDirectoryObject") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateDirectoryObject); }
	if (_stricmp(lpProcName, "NtCreateUserProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateUserProcess); }
	if (_stricmp(lpProcName, "NtCreateProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateProcess); }
	if (_stricmp(lpProcName, "NtCreateProcessEx") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateProcessEx); }
	if (_stricmp(lpProcName, "NtSuspendProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtSuspendProcess); }
	if (_stricmp(lpProcName, "NtTerminateProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtTerminateProcess); }
	if (_stricmp(lpProcName, "NtMapViewOfSection") == 0) { return (FARPROC)GetJumpAddr(HookNtMapViewOfSection); }
	if (_stricmp(lpProcName, "NtUnmapViewOfSection") == 0) { return (FARPROC)GetJumpAddr(HookNtUnmapViewOfSection); }
	if (_stricmp(lpProcName, "NtMakeTemporaryObject") == 0) { return (FARPROC)GetJumpAddr(HookNtMakeTemporaryObject); }
	if (_stricmp(lpProcName, "NtMakePermanentObject") == 0) { return (FARPROC)GetJumpAddr(HookNtMakePermanentObject); }
	if (_stricmp(lpProcName, "NtWriteVirtualMemory") == 0) { return (FARPROC)GetJumpAddr(HookNtWriteVirtualMemory); }
	if (_stricmp(lpProcName, "NtSetInformationProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtSetInformationProcess); }
	if (_stricmp(lpProcName, "NtGetNextProcess") == 0) { return (FARPROC)GetJumpAddr(HookNtGetNextProcess); }
	if (_stricmp(lpProcName, "NtReplaceKey") == 0) { return (FARPROC)GetJumpAddr(HookNtReplaceKey); }
	if (_stricmp(lpProcName, "NtRenameKey") == 0) { return (FARPROC)GetJumpAddr(HookNtRenameKey); }
	if (_stricmp(lpProcName, "NtSaveKey") == 0) { return (FARPROC)GetJumpAddr(HookNtSaveKey); }
	if (_stricmp(lpProcName, "NtSaveKeyEx") == 0) { return (FARPROC)GetJumpAddr(HookNtSaveKeyEx); }
	if (_stricmp(lpProcName, "NtSetValueKey") == 0) { return (FARPROC)GetJumpAddr(HookNtSetValueKey); }
	if (_stricmp(lpProcName, "NtDeleteKey") == 0) { return (FARPROC)GetJumpAddr(HookNtDeleteKey); }
	if (_stricmp(lpProcName, "NtDeleteValueKey") == 0) { return (FARPROC)GetJumpAddr(HookNtDeleteValueKey); }
	if (_stricmp(lpProcName, "NtOpenTimer") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenTimer); }
	if (_stricmp(lpProcName, "NtQueryTimer") == 0) { return (FARPROC)GetJumpAddr(HookNtQueryTimer); }
	if (_stricmp(lpProcName, "NtCreateTimer") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateTimer); }
	if (_stricmp(lpProcName, "NtQuerySystemTime") == 0) { return (FARPROC)GetJumpAddr(HookNtQuerySystemTime); }
	if (_stricmp(lpProcName, "NtOpenEvent") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenEvent); }
	if (_stricmp(lpProcName, "NtNotifyChangeKey") == 0) { return (FARPROC)GetJumpAddr(HookNtNotifyChangeKey); }
	if (_stricmp(lpProcName, "NtOpenSemaphore") == 0) { return (FARPROC)GetJumpAddr(HookNtOpenSemaphore); }
	if (_stricmp(lpProcName, "NtCreateSemaphore") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateSemaphore); }
	if (_stricmp(lpProcName, "NtLockFile") == 0) { return (FARPROC)GetJumpAddr(HookNtLockFile); }

	if (_stricmp(lpProcName, "NtDelayExecution") == 0) { return (FARPROC)GetJumpAddr(HookNtDelayExecution); }

	// thread test
	if (_stricmp(lpProcName, "NtCreateThread") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateThread); }
	if (_stricmp(lpProcName, "NtCreateThreadEx") == 0) { return (FARPROC)GetJumpAddr(HookNtCreateThreadEx); }

	// 若都不符合則用原本的GetProcAddress來找函數
	return OgGetProcAddress(hModule, lpProcName);
}

bool InstallIATHook(const char* dllName, const char* funcName, void* hookFuncAddr) {

	// 定位PE文件的導入表
	// 取得當前進程的句柄
	HMODULE hModule = GetModuleHandleA(NULL);

	PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)hModule;
#ifdef _WIN64
	PIMAGE_NT_HEADERS64 ptrNtHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)hModule + (ULONG_PTR)ptrDosHeader->e_lfanew);
#else
	PIMAGE_NT_HEADERS ptrNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + (ULONG_PTR)ptrDosHeader->e_lfanew);
#endif
	PIMAGE_OPTIONAL_HEADER ptrOptionHeader = &(ptrNtHeader->OptionalHeader);
	IMAGE_DATA_DIRECTORY directory = ptrOptionHeader->DataDirectory[1];
	PIMAGE_IMPORT_DESCRIPTOR pImageDescripor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hModule + (ULONG_PTR)directory.VirtualAddress);

	while (pImageDescripor->Name) {
		const char* iatDllName = (const char*)((ULONG_PTR)hModule + (ULONG_PTR)pImageDescripor->Name);
		if (_stricmp(dllName, iatDllName) == 0) {
			PIMAGE_THUNK_DATA pInt = (PIMAGE_THUNK_DATA)((ULONG_PTR)hModule + (ULONG_PTR)pImageDescripor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)((ULONG_PTR)hModule + (ULONG_PTR)pImageDescripor->FirstThunk);

			while (pInt->u1.Function) {
				PIMAGE_IMPORT_BY_NAME pImageByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)hModule + (ULONG_PTR)pInt->u1.Function);
				if (_stricmp((const char*)pImageByName->Name, funcName) == 0) {
					// 取得目標的Iat的位址
					ULONG_PTR* targetFunAddrPtr = (ULONG_PTR*)pIat;

					// 修改記憶體區段為可寫
					DWORD oldProtect = 0;
					VirtualProtect(targetFunAddrPtr, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &oldProtect);
					//*targetFunAddrPtr = (ULONG_PTR)hookFuncAddr;

					*targetFunAddrPtr = GetJumpAddr(hookFuncAddr);

					VirtualProtect(targetFunAddrPtr, sizeof(ULONG_PTR), oldProtect, &oldProtect);

					return true;

				}
				pInt++;
				pIat++;
			}
			//cout << "找不到對應函數名" << funcName << endl;
			return false;

		}
		pImageDescripor++;
	}
	//cout << "找不到對應DLL" << dllName << endl;
	return false;
}