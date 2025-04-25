// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include "include_x86/detours.h"
#include <WinNT.h>
#include <Windows.h>
#include <winternl.h> // ntstatus, pio_status_block
#include <stdlib.h> // malloc
#include "communication.h"
#include "syscalls.h"
#include <iostream>
//#include <intrin.h> // ReturnAddress

#include "CoreUtil.hpp"
#include "RegHook.hpp"
#include "FileHook.hpp"
#include "ProcessHook.hpp"
#include "NetworkHook.hpp"
#include "SystemHook.hpp"
#include "UIHook.hpp"
#include "MemoryHook.hpp"
#include "SyncHook.hpp"
#include "IATHookUtil.hpp"
#include "GlobalMutation.hpp"

using namespace std;

//#define __DEBUG_PRINT

#pragma comment(lib, "include_x86/detours.lib")

HANDLE hPipe;
DWORD dwTlsIndex;

// thread local storage would result in inconsistent views of ticks between threads
volatile ULONG TimeShift = 0;
double dFreq = 1;

BYTE* TargetBase = NULL;
BYTE* TargetEnd = NULL;

// chld
LPVOID pLoadLibraryA = NULL;

UINT64 ImageBase = 0;

int GetKeyNameFromHandle(HANDLE key, wchar_t* dest, PULONG size)
{
	if (key == NULL) {
		return 0;
	}

	PKEY_NAME_INFORMATION buf = (PKEY_NAME_INFORMATION)malloc(528); // KEY_NAME_INFORMATION (8) + MAX_PATH (260) * WCHAR (2) 
	if (buf == NULL) {
		return 0;
	}

	ULONG retlen;
	NTSTATUS status;

	status = NtQueryKey(key, KeyNameInformation, buf, 528, &retlen);
	if (NT_SUCCESS(status)) {
		// buf->Name is NOT null terminated
		size_t widec = buf->NameLength / sizeof(wchar_t);
		if (widec + 1 < MAX_CTX_LEN) {
			memcpy(dest, buf->Name, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		else {
			widec = MAX_CTX_LEN - 1;
			memcpy(dest, buf->Name, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		*size = widec;
		free(buf);
		return 1;
	}

	return 0;
}

int GetFileNameFromHandle(HANDLE file, wchar_t* dest, PULONG size)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	PFILE_NAME_INFORMATION buf;
	size_t nameInfoLen = sizeof(FILE_NAME_INFORMATION) + (350 * sizeof(WCHAR));

	if (file == NULL) {
		return 0;
	}

	buf = (PFILE_NAME_INFORMATION)malloc(nameInfoLen);
	if (buf == NULL) {
		return 0;
	}

	status = OgNtQueryInformationFile(file, &ioStatusBlock, buf, nameInfoLen, (FILE_INFORMATION_CLASS)9); // FileNameInformation
	if (NT_SUCCESS(status)) {
		size_t widec = buf->FileNameLength / sizeof(wchar_t);
		if (widec + 1 < MAX_CTX_LEN) {
			memcpy(dest, buf->FileName, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		else {
			widec = MAX_CTX_LEN - 1;
			memcpy(dest, buf->FileName, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		*size = widec;
		free(buf);
		return 1;
	}

	return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	LPVOID lpvData;
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	{
		// 禁用執行緒通知
		DisableThreadLibraryCalls(hModule); // disable notifications
#ifdef __DEBUG_PRINT
		printf("Enviral DLL Loaded\n");
#endif

		
		// 等待Pipe連接
		if (!WaitNamedPipe(szPipeName, 20000)) {
			fprintf(stderr, "Pipe wait failed: %x\n", GetLastError());
			return -1;
		}
#ifdef __DEBUG_PRINT
		printf("[Pipe C] WaitNamedPipe succeeded!\n");
#endif

		// pipe (createfile is connect)
		// 創建管道配置
		hPipe = CreateFile(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "Could not create client pipe: %x\n", GetLastError());
			return -1;
		}
#ifdef __DEBUG_PRINT
		printf("[Pipe C] Client connected to pipe: %p\n", hPipe);
#endif

		// 將Pipe設置為read模式
		DWORD dwMode = PIPE_READMODE_MESSAGE;
		BOOL set = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
		if (!set) {
			fprintf(stderr, "Could not set pipe to read message mode\n");
			return -1;
		}

		// read (mut)
		DWORD dwMutationCount;
		DWORD dwRead;
		// if NumBytesToRead is < the next message, readfile returns ERROR_MORE_DATA
		//從pipe讀取到Mutation的數量總數
		BOOL rd = ReadFile(hPipe, &dwMutationCount, sizeof(dwMutationCount), &dwRead, NULL);
		if (rd) {

#ifdef __DEBUG_PRINT
			printf("[Pipe C] Mutation count: %lu\n", dwMutationCount);
#endif
			for (DWORD i = 0; i < dwMutationCount; i++) {
				Mutation mut;
				// 從pipe讀取Mutation
				rd = ReadFile(hPipe, &mut, sizeof(Mutation), &dwRead, NULL);
				if (!rd) {
					fprintf(stderr, "[Pipe C] Could not read generated mutation.\n");
				}
#ifdef __DEBUG_PRINT // debug
				printf("[Pipe C] Received a mutation for call: %s\n", DebugCallNames[mut.rec.call]);
#endif
				// 將Mutatin紀錄下來
				StoreMutation(&mut);
			}

		}
		else {
			DWORD err = GetLastError();
			fprintf(stderr, "Mutation Read Failed: %x\n", err);
		}
		



		// Get the start address of the executable module

		WCHAR FileName[MAX_PATH];
		// 取得主執行程式的位置檔案名稱
		GetModuleFileNameW(NULL, FileName, MAX_PATH);

		// 取得目標程式的範圍，讓Hook時更方便
		DWORD pid = GetCurrentProcessId();
		MODULEENTRY32 ModuleEntry = { 0 };
		HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (!SnapShot) return NULL;
		ModuleEntry.dwSize = sizeof(ModuleEntry);
		if (!Module32First(SnapShot, &ModuleEntry)) return NULL;
		do {
			if (wcsstr(FileName, ModuleEntry.szModule)) {
				// get module address
				//printf("ModuleName: %ws\n", ModuleEntry.szModule);
				ImageBase = (UINT64)ModuleEntry.modBaseAddr;
				//printf("Module Base Addr: %p\n", ModuleEntry.modBaseAddr);
				//printf("Module Base Size: %lu\n", ModuleEntry.modBaseSize);
				TargetBase = ModuleEntry.modBaseAddr;
				TargetEnd = ModuleEntry.modBaseAddr + ModuleEntry.modBaseSize;
				break;
			}
		} while (Module32Next(SnapShot, &ModuleEntry));
		CloseHandle(SnapShot);
#ifdef __DEBUG_PRINT
		printf("Info: Module address (%ws) range: %p ~ %p\n", ModuleEntry.szModule, TargetBase, TargetEnd);
#endif
		// Load the Performance Counter Frequency
		// 獲取高精度計時器的頻率
		LARGE_INTEGER freq;
		if (QueryPerformanceFrequency(&freq)) {
			dFreq = double(freq.QuadPart) / 1000.0;
#ifdef __DEBUG_PRINT
			printf("Performance Counter Frequency = %f\n", dFreq);
#endif
		}

		// seed random
		srand(756669);

		// 從Win的DLL使用GetProcAddress動態導入函數
		HMODULE nt = GetModuleHandleA("ntdll.dll");
		if (nt == NULL) return FALSE;

		HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
		if (k32 == NULL) return FALSE;

		pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");

		/* win32k.sys functions are not exposed (kernel only), so we can hook the Win32 API */
		/* The calls in user32.dll are accessible and do not need native API hook */

		/* GetTickCount cannot be hooked, since it does not contain the necessary preamble (too few bytes in the function) */
		// for some reason on 32bit it can be hooked

		// evasive
		// 取得原本的API CALL
		OgGetProcAddress = (ProtoGetProcAddress)GetProcAddress(k32, "GetProcAddress");
		OgNtOpenKey = (ProtoNtOpenKey)GetProcAddress(nt, "NtOpenKey");
		OgNtOpenKeyEx = (ProtoNtOpenKeyEx)GetProcAddress(nt, "NtOpenKeyEx");
		OgNtQueryValueKey = (ProtoNtQueryValueKey)GetProcAddress(nt, "NtQueryValueKey");
		OgNtCreateKey = (ProtoNtCreateKey)GetProcAddress(nt, "NtCreateKey");
		OgNtEnumerateKey = (ProtoNtEnumerateKey)GetProcAddress(nt, "NtEnumerateKey");
		OgNtEnumerateValueKey = (ProtoNtEnumerateValueKey)GetProcAddress(nt, "NtEnumerateValueKey");
		OgNtCreateFile = (ProtoNtCreateFile)GetProcAddress(nt, "NtCreateFile");
		OgNtQueryAttributesFile = (ProtoNtQueryAttributesFile)GetProcAddress(nt, "NtQueryAttributesFile");
		OgNtDeviceIoControlFile = (ProtoNtDeviceIoControlFile)GetProcAddress(nt, "NtDeviceIoControlFile");
		OgNtQueryVolumeInformationFile = (ProtoNtQueryVolumeInformationFile)GetProcAddress(nt, "NtQueryVolumeInformationFile");
		OgNtQuerySystemInformation = (ProtoNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
		OgNtQuerySystemInformationEx = (ProtoNtQuerySystemInformationEx)GetProcAddress(nt, "NtQuerySystemInformationEx");
		OgNtPowerInformation = (ProtoNtPowerInformation)GetProcAddress(nt, "NtPowerInformation");
		OgNtQueryLicenseValue = (ProtoNtQueryLicenseValue)GetProcAddress(nt, "NtQueryLicenseValue");
		OgNtQueryDirectoryFile = (ProtoNtQueryDirectoryFile)GetProcAddress(nt, "NtQueryDirectoryFile");
		OgNtQueryInformationProcess = (ProtoNtQueryInformationProcess)GetProcAddress(nt, "NtQueryInformationProcess");
		OgNtQueryDirectoryObject = (ProtoNtQueryDirectoryObject)GetProcAddress(nt, "NtQueryDirectoryObject");
		OgNtCreateMutant = (ProtoNtCreateMutant)GetProcAddress(nt, "NtCreateMutant");
		OgNtOpenMutant = (ProtoNtOpenMutant)GetProcAddress(nt, "NtOpenMutant");
		// activity
		OgNtOpenFile = (ProtoNtOpenFile)GetProcAddress(nt, "NtOpenFile");
		OgNtReadFile = (ProtoNtReadFile)GetProcAddress(nt, "NtReadFile");
		OgNtWriteFile = (ProtoNtWriteFile)GetProcAddress(nt, "NtWriteFile");
		OgNtDeleteFile = (ProtoNtDeleteFile)GetProcAddress(nt, "NtDeleteFile");
		OgNtQueryInformationFile = (ProtoNtQueryInformationFile)GetProcAddress(nt, "NtQueryInformationFile");
		OgNtSetInformationFile = (ProtoNtSetInformationFile)GetProcAddress(nt, "NtSetInformationFile");
		OgNtOpenDirectoryObject = (ProtoNtOpenDirectoryObject)GetProcAddress(nt, "NtOpenDirectoryObject");
		OgNtCreateDirectoryObject = (ProtoNtCreateDirectoryObject)GetProcAddress(nt, "NtCreateDirectoryObject");
		OgNtCreateUserProcess = (ProtoNtCreateUserProcess)GetProcAddress(nt, "NtCreateUserProcess");
		OgNtCreateProcess = (ProtoNtCreateProcess)GetProcAddress(nt, "NtCreateProcess");
		OgNtCreateProcessEx = (ProtoNtCreateProcessEx)GetProcAddress(nt, "NtCreateProcessEx");
		OgNtSuspendProcess = (ProtoNtSuspendProcess)GetProcAddress(nt, "NtSuspendProcess");
		OgNtTerminateProcess = (ProtoNtTerminateProcess)GetProcAddress(nt, "NtTerminateProcess");
		OgNtMapViewOfSection = (ProtoNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
		OgNtUnmapViewOfSection = (ProtoNtUnmapViewOfSection)GetProcAddress(nt, "NtUnmapViewOfSection");
		OgNtMakeTemporaryObject = (ProtoNtMakeTemporaryObject)GetProcAddress(nt, "NtMakeTemporaryObject");
		OgNtMakePermanentObject = (ProtoNtMakePermanentObject)GetProcAddress(nt, "NtMakePermanentObject");
		OgNtWriteVirtualMemory = (ProtoNtWriteVirtualMemory)GetProcAddress(nt, "NtWriteVirtualMemory");
		OgNtSetInformationProcess = (ProtoNtSetInformationProcess)GetProcAddress(nt, "NtSetInformationProcess");
		OgNtGetNextProcess = (ProtoNtGetNextProcess)GetProcAddress(nt, "NtGetNextProcess");
		OgNtReplaceKey = (ProtoNtReplaceKey)GetProcAddress(nt, "NtReplaceKey");
		OgNtRenameKey = (ProtoNtRenameKey)GetProcAddress(nt, "NtRenameKey");
		OgNtSaveKey = (ProtoNtSaveKey)GetProcAddress(nt, "NtSaveKey");
		OgNtSaveKeyEx = (ProtoNtSaveKeyEx)GetProcAddress(nt, "NtSaveKeyEx");
		OgNtSetValueKey = (ProtoNtSetValueKey)GetProcAddress(nt, "NtSetValueKey");
		OgNtDeleteKey = (ProtoNtDeleteKey)GetProcAddress(nt, "NtDeleteKey");
		OgNtDeleteValueKey = (ProtoNtDeleteValueKey)GetProcAddress(nt, "NtDeleteValueKey");
		OgNtOpenTimer = (ProtoNtOpenTimer)GetProcAddress(nt, "NtOpenTimer");
		OgNtQueryTimer = (ProtoNtQueryTimer)GetProcAddress(nt, "NtQueryTimer");
		OgNtCreateTimer = (ProtoNtCreateTimer)GetProcAddress(nt, "NtCreateTimer");
		OgNtQuerySystemTime = (ProtoNtQuerySystemTime)GetProcAddress(nt, "NtQuerySystemTime");
		OgNtOpenEvent = (ProtoNtOpenEvent)GetProcAddress(nt, "NtOpenEvent");
		OgNtNotifyChangeKey = (ProtoNtNotifyChangeKey)GetProcAddress(nt, "NtNotifyChangeKey");
		OgNtOpenSemaphore = (ProtoNtOpenSemaphore)GetProcAddress(nt, "NtOpenSemaphore");
		OgNtCreateSemaphore = (ProtoNtCreateSemaphore)GetProcAddress(nt, "NtCreateSemaphore");
		OgNtLockFile = (ProtoNtLockFile)GetProcAddress(nt, "NtLockFile");
		// edge case
		OgProcess32FirstW = (ProtoProcess32FirstW)GetProcAddress(k32, "Process32FirstW");
		OgProcess32NextW = (ProtoProcess32NextW)GetProcAddress(k32, "Process32NextW");

		// child process management
		OgCreateProcessInternalW = (ProtoCreateProcessInternalW)GetProcAddress(k32, "CreateProcessInternalW");
		// util
		NtQueryKey = (ProtoNtQueryKey)GetProcAddress(nt, "NtQueryKey");
		OgNtDelayExecution = (ProtoNtDelayExecution)GetProcAddress(nt, "NtDelayExecution");

		// thread test
		OgNtCreateThread = (ProtoNtCreateThread)GetProcAddress(nt, "NtCreateThread");
		OgNtCreateThreadEx = (ProtoNtCreateThreadEx)GetProcAddress(nt, "NtCreateThreadEx");

		HMODULE u32 = GetModuleHandleA("user32.dll");
		if (u32 == NULL) {
			return false;
		}
		OgMessageBoxW = (ProtoMessageBoxW)GetProcAddress(u32, "MessageBoxW");
		OgMessageBoxA = (ProtoMessageBoxA)GetProcAddress(u32, "MessageBoxA");
		OgMessageBoxExW = (ProtoMessageBoxExW)GetProcAddress(u32, "MessageBoxExW");
		OgMessageBoxExA = (ProtoMessageBoxExA)GetProcAddress(u32, "MessageBoxExA");

		//DetourSetIgnoreTooSmall(TRUE);
		// 掛載Detours的Hook
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// 為GetProcAddress掛上IAT Hook
		InstallIATHook("kernel32.dll", "GetProcAddress", HookGetProcAddress);

		// 測試mesasgebox
		DetourAttach(&(PVOID&)OgMessageBoxW, HookMessageBoxW);
		DetourAttach(&(PVOID&)OgMessageBoxA, HookMessageBoxA);
		DetourAttach(&(PVOID&)OgMessageBoxExW, HookMessageBoxExW);
		DetourAttach(&(PVOID&)OgMessageBoxExA, HookMessageBoxExA);

		// evasive 掛上Detour勾子
		DetourAttach(&(PVOID&)OgNtOpenKey, HookNtOpenKey);
		DetourAttach(&(PVOID&)OgNtOpenKeyEx, HookNtOpenKeyEx);
		DetourAttach(&(PVOID&)OgNtQueryValueKey, HookNtQueryValueKey);
		DetourAttach(&(PVOID&)OgNtCreateKey, HookNtCreateKey);
		DetourAttach(&(PVOID&)OgNtEnumerateKey, HookNtEnumerateKey);
		DetourAttach(&(PVOID&)OgNtEnumerateValueKey, HookNtEnumerateValueKey);
		DetourAttach(&(PVOID&)OgNtCreateFile, HookNtCreateFile);
		DetourAttach(&(PVOID&)OgNtQueryAttributesFile, HookNtQueryAttributesFile);
		DetourAttach(&(PVOID&)OgNtDeviceIoControlFile, HookNtDeviceIoControlFile);
		DetourAttach(&(PVOID&)OgNtQueryVolumeInformationFile, HookNtQueryVolumeInformationFile);
		DetourAttach(&(PVOID&)OgNtQuerySystemInformation, HookNtQuerySystemInformation);
		DetourAttach(&(PVOID&)OgNtQuerySystemInformationEx, HookNtQuerySystemInformationEx);
		DetourAttach(&(PVOID&)OgNtPowerInformation, HookNtPowerInformation);
		DetourAttach(&(PVOID&)OgNtQueryLicenseValue, HookNtQueryLicenseValue);
		DetourAttach(&(PVOID&)OgNtQueryDirectoryFile, HookNtQueryDirectoryFile);
		DetourAttach(&(PVOID&)OgNtQueryInformationProcess, HookNtQueryInformationProcess);
		DetourAttach(&(PVOID&)OgNtQueryDirectoryObject, HookNtQueryDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateMutant, HookNtCreateMutant);
		DetourAttach(&(PVOID&)OgNtOpenMutant, HookNtOpenMutant);
		DetourAttach(&(PVOID&)OgGetAdaptersAddresses, HookGetAdaptersAddresses);
		DetourAttach(&(PVOID&)OgProcess32FirstW, HookProcess32FirstW);
		DetourAttach(&(PVOID&)OgProcess32NextW, HookProcess32NextW);
		DetourAttach(&(PVOID&)OgCoCreateInstance, HookCoCreateInstance);
		DetourAttach(&(PVOID&)OgGetModuleHandleW, HookGetModuleHandleW);
		DetourAttach(&(PVOID&)OgGetModuleHandleA, HookGetModuleHandleA);
		DetourAttach(&(PVOID&)OgGetModuleHandleExW, HookGetModuleHandleExW);
		DetourAttach(&(PVOID&)OgGetModuleHandleExA, HookGetModuleHandleExA);
		DetourAttach(&(PVOID&)OgGetAdaptersInfo, HookGetAdaptersInfo);
		DetourAttach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyW, HookSetupDiGetDeviceRegistryPropertyW);
		DetourAttach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyA, HookSetupDiGetDeviceRegistryPropertyA);
		DetourAttach(&(PVOID&)OgGetLastInputInfo, HookGetLastInputInfo);
		DetourAttach(&(PVOID&)OgEnumServicesStatusExA, HookEnumServicesStatusExA);
		DetourAttach(&(PVOID&)OgEnumServicesStatusExW, HookEnumServicesStatusExW);
		DetourAttach(&(PVOID&)OgInternetCheckConnectionA, HookInternetCheckConnectionA);
		DetourAttach(&(PVOID&)OgInternetCheckConnectionW, HookInternetCheckConnectionW);
		DetourAttach(&(PVOID&)OgGetWindowRect, HookGetWindowRect);
		DetourAttach(&(PVOID&)OgGetMonitorInfoA, HookGetMonitorInfoA);
		DetourAttach(&(PVOID&)OgGetMonitorInfoW, HookGetMonitorInfoW);
		DetourAttach(&(PVOID&)OgFindWindowA, HookFindWindowA);
		DetourAttach(&(PVOID&)OgFindWindowW, HookFindWindowW);
		DetourAttach(&(PVOID&)OgFindWindowExA, HookFindWindowExA);
		DetourAttach(&(PVOID&)OgFindWindowExW, HookFindWindowExW);
		DetourAttach(&(PVOID&)OgGetCursorPos, HookGetCursorPos);
		DetourAttach(&(PVOID&)OgGetSystemMetrics, HookGetSystemMetrics);
		DetourAttach(&(PVOID&)OgSystemParametersInfoA, HookSystemParametersInfoA);
		DetourAttach(&(PVOID&)OgSystemParametersInfoW, HookSystemParametersInfoW);
		DetourAttach(&(PVOID&)OgGetAsyncKeyState, HookGetAsyncKeyState);
		DetourAttach(&(PVOID&)OgGetForegroundWindow, HookGetForegroundWindow);
		DetourAttach(&(PVOID&)OgLoadLibraryExW, HookLoadLibraryExW);
		DetourAttach(&(PVOID&)OgLoadLibraryExA, HookLoadLibraryExA);
		DetourAttach(&(PVOID&)OgLoadLibraryW, HookLoadLibraryW);
		DetourAttach(&(PVOID&)OgLoadLibraryA, HookLoadLibraryA);

		// evasive但非NT

		InstallIATHook("kernel32.dll", "GetModuleHandleW", HookGetModuleHandleW);
		InstallIATHook("kernel32.dll", "LoadLibraryExW", HookLoadLibraryExW);
		InstallIATHook("kernel32.dll", "LoadLibraryExA", HookLoadLibraryExA);
		InstallIATHook("kernel32.dll", "LoadLibraryW", HookLoadLibraryW);

		// 如果沒有呼叫就掛不上鉤子
		InstallIATHook("kernel32.dll", "Process32FirstW", HookProcess32FirstW);
		InstallIATHook("kernel32.dll", "Process32NextW", HookProcess32NextW);
		InstallIATHook("kernel32.dll", "GetModuleHandleA", HookGetModuleHandleA);
		InstallIATHook("kernel32.dll", "GetModuleHandleExW", HookGetModuleHandleExW);
		InstallIATHook("kernel32.dll", "GetModuleHandleExA", HookGetModuleHandleExA);
		InstallIATHook("user32.dll", "GetLastInputInfo", HookGetLastInputInfo);
		InstallIATHook("user32.dll", "GetWindowRect", HookGetWindowRect);
		InstallIATHook("user32.dll", "GetMonitorInfoA", HookGetMonitorInfoA);
		InstallIATHook("user32.dll", "GetMonitorInfoW", HookGetMonitorInfoW);
		InstallIATHook("user32.dll", "FindWindowA", HookFindWindowA);
		InstallIATHook("user32.dll", "FindWindowW", HookFindWindowW);
		InstallIATHook("user32.dll", "FindWindowExA", HookFindWindowExA);
		InstallIATHook("user32.dll", "FindWindowExW", HookFindWindowExW);
		InstallIATHook("user32.dll", "GetCursorPos", HookGetCursorPos);
		InstallIATHook("user32.dll", "GetSystemMetrics", HookGetSystemMetrics);
		InstallIATHook("user32.dll", "SystemParametersInfoA", HookSystemParametersInfoA);
		InstallIATHook("user32.dll", "SystemParametersInfoW", HookSystemParametersInfoW);
		InstallIATHook("user32.dll", "GetAsyncKeyState", HookGetAsyncKeyState);
		InstallIATHook("user32.dll", "GetForegroundWindow", HookGetForegroundWindow);
		InstallIATHook("kernel32.dll", "LoadLibraryA", HookLoadLibraryA);

		// 未測試
		InstallIATHook("iphlpapi.dll", "GetAdaptersAddresses", HookGetAdaptersAddresses);
		InstallIATHook("ole32.dll", "CoCreateInstance", HookCoCreateInstance);
		InstallIATHook("iphlpapi.dll", "GetAdaptersInfo", HookGetAdaptersInfo);
		InstallIATHook("setupapi.dll", "SetupDiGetDeviceRegistryPropertyW", HookSetupDiGetDeviceRegistryPropertyW);
		InstallIATHook("setupapi.dll", "SetupDiGetDeviceRegistryPropertyA", HookSetupDiGetDeviceRegistryPropertyA);
		InstallIATHook("advapi32.dll", "EnumServicesStatusExA", HookEnumServicesStatusExA);
		InstallIATHook("advapi32.dll", "EnumServicesStatusExW", HookEnumServicesStatusExW);
		InstallIATHook("wininet.dll", "InternetCheckConnectionA", HookInternetCheckConnectionA);
		InstallIATHook("wininet.dll", "InternetCheckConnectionW", HookInternetCheckConnectionW);


		// 不會突變且是NT的函數，掛上Detour
		DetourAttach(&(PVOID&)OgNtOpenFile, HookNtOpenFile);
		DetourAttach(&(PVOID&)OgNtReadFile, HookNtReadFile);
		//DetourAttach(&(PVOID&)OgNtWriteFile, HookNtWriteFile);
		DetourAttach(&(PVOID&)OgNtDeleteFile, HookNtDeleteFile);
		DetourAttach(&(PVOID&)OgNtQueryInformationFile, HookNtQueryInformationFile);
		DetourAttach(&(PVOID&)OgNtSetInformationFile, HookNtSetInformationFile);
		DetourAttach(&(PVOID&)OgNtOpenDirectoryObject, HookNtOpenDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateDirectoryObject, HookNtCreateDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateUserProcess, HookNtCreateUserProcess);
		DetourAttach(&(PVOID&)OgNtCreateProcess, HookNtCreateProcess);
		DetourAttach(&(PVOID&)OgNtCreateProcessEx, HookNtCreateProcessEx);
		DetourAttach(&(PVOID&)OgNtSuspendProcess, HookNtSuspendProcess);
		DetourAttach(&(PVOID&)OgNtTerminateProcess, HookNtTerminateProcess);
		DetourAttach(&(PVOID&)OgNtMapViewOfSection, HookNtMapViewOfSection);
		DetourAttach(&(PVOID&)OgNtUnmapViewOfSection, HookNtUnmapViewOfSection);
		DetourAttach(&(PVOID&)OgNtMakeTemporaryObject, HookNtMakeTemporaryObject);
		DetourAttach(&(PVOID&)OgNtMakePermanentObject, HookNtMakePermanentObject);
		DetourAttach(&(PVOID&)OgNtWriteVirtualMemory, HookNtWriteVirtualMemory);
		DetourAttach(&(PVOID&)OgNtSetInformationProcess, HookNtSetInformationProcess);
		DetourAttach(&(PVOID&)OgNtGetNextProcess, HookNtGetNextProcess);
		DetourAttach(&(PVOID&)OgNtReplaceKey, HookNtReplaceKey);
		DetourAttach(&(PVOID&)OgNtRenameKey, HookNtRenameKey);
		DetourAttach(&(PVOID&)OgNtSaveKey, HookNtSaveKey);
		DetourAttach(&(PVOID&)OgNtSaveKeyEx, HookNtSaveKeyEx);
		DetourAttach(&(PVOID&)OgNtSetValueKey, HookNtSetValueKey);
		DetourAttach(&(PVOID&)OgNtDeleteKey, HookNtDeleteKey);
		DetourAttach(&(PVOID&)OgNtDeleteValueKey, HookNtDeleteValueKey);
		DetourAttach(&(PVOID&)OgNtOpenTimer, HookNtOpenTimer);
		DetourAttach(&(PVOID&)OgNtQueryTimer, HookNtQueryTimer);
		DetourAttach(&(PVOID&)OgNtCreateTimer, HookNtCreateTimer);
		DetourAttach(&(PVOID&)OgNtQuerySystemTime, HookNtQuerySystemTime);
		DetourAttach(&(PVOID&)OgNtOpenEvent, HookNtOpenEvent);
		DetourAttach(&(PVOID&)OgNtNotifyChangeKey, HookNtNotifyChangeKey);
		DetourAttach(&(PVOID&)OgNtOpenSemaphore, HookNtOpenSemaphore);
		DetourAttach(&(PVOID&)OgNtCreateSemaphore, HookNtCreateSemaphore);
		DetourAttach(&(PVOID&)OgNtLockFile, HookNtLockFile);

		DetourAttach(&(PVOID&)OgNtDelayExecution, HookNtDelayExecution);

		// thread test
		DetourAttach(&(PVOID&)OgNtCreateThread, HookNtCreateThread);
		DetourAttach(&(PVOID&)OgNtCreateThreadEx, HookNtCreateThreadEx);

		// 以下是不會突變且非NT的函數，直接使用Detours攔截
		DetourAttach(&(PVOID&)OgGetSystemTime, HookGetSystemTime);
		DetourAttach(&(PVOID&)OgGetLocalTime, HookGetLocalTime);
		DetourAttach(&(PVOID&)OgFindResourceExW, HookFindResourceExW);
		DetourAttach(&(PVOID&)OgFindResourceExA, HookFindResourceExA);

		// network activity
		DetourAttach(&(PVOID&)OgURLDownloadToFileW, HookURLDownloadToFileW);
		DetourAttach(&(PVOID&)OgInternetOpenA, HookInternetOpenA);
		DetourAttach(&(PVOID&)OgInternetConnectA, HookInternetConnectA);
		DetourAttach(&(PVOID&)OgInternetConnectW, HookInternetConnectW);
		DetourAttach(&(PVOID&)OgInternetOpenUrlA, HookInternetOpenUrlA);
		DetourAttach(&(PVOID&)OgHttpOpenRequestA, HookHttpOpenRequestA);
		DetourAttach(&(PVOID&)OgHttpOpenRequestW, HookHttpOpenRequestW);
		DetourAttach(&(PVOID&)OgHttpSendRequestA, HookHttpSendRequestA);
		DetourAttach(&(PVOID&)OgHttpSendRequestW, HookHttpSendRequestW);
		DetourAttach(&(PVOID&)OgInternetReadFile, HookInternetReadFile);
		DetourAttach(&(PVOID&)OgDnsQuery_A, HookDnsQuery_A);
		DetourAttach(&(PVOID&)OgDnsQuery_W, HookDnsQuery_W);
		DetourAttach(&(PVOID&)OgGetAddrInfoW, HookGetAddrInfoW);
		DetourAttach(&(PVOID&)OgWSAStartup, HookWSAStartup);
		DetourAttach(&(PVOID&)Oggethostbyname, Hookgethostbyname);
		DetourAttach(&(PVOID&)Ogsocket, Hooksocket);
		DetourAttach(&(PVOID&)Ogconnect, Hookconnect);
		DetourAttach(&(PVOID&)Ogsend, Hooksend);
		DetourAttach(&(PVOID&)Ogsendto, Hooksendto);
		DetourAttach(&(PVOID&)Ogrecv, Hookrecv);
		DetourAttach(&(PVOID&)Ogrecvfrom, Hookrecvfrom);
		DetourAttach(&(PVOID&)Ogbind, Hookbind);
		DetourAttach(&(PVOID&)OgWSARecv, HookWSARecv);
		DetourAttach(&(PVOID&)OgWSARecvFrom, HookWSARecvFrom);
		DetourAttach(&(PVOID&)OgWSASend, HookWSASend);
		DetourAttach(&(PVOID&)OgWSASendTo, HookWSASendTo);
		DetourAttach(&(PVOID&)OgWSASocketW, HookWSASocketW);

		// child process management
		DetourAttach(&(PVOID&)OgCreateProcessInternalW, HookCreateProcessInternalW);
#ifdef __32BIT_SYS
		DetourAttach(&(PVOID&)OgGetTickCount, HookGetTickCount);
#endif

		DetourAttach(&(PVOID&)OgQueryPerformanceCounter, HookQueryPerformanceCounter);


		LONG err = DetourTransactionCommit();
		if (err != NO_ERROR) {
			fprintf(stderr, "DetourTransactionCommit FAILED\n");
			return FALSE;
		}

		// 申請Thread Local Storage的索引，為之後可能有DLL_THREAD_ATTACH做準備
		if ((dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
			fprintf(stderr, "Fatal error: Out of TLX Indexes");
			return FALSE;
		}
#ifdef __DEBUG_PRINT
		printf("Created TLSIndex: %lu\n", dwTlsIndex);
#endif
	}
	// fall through !
	case DLL_THREAD_ATTACH:
	{
#ifdef __DEBUG_PRINT
		printf("Initialiazing TLS index for thread!\n");
#endif
		// init the TLS index for this thread.
		lpvData = (LPVOID)LocalAlloc(LPTR, sizeof(BOOL));
		if (lpvData != NULL) {
			// 將分配的記憶體與線程關聯，讓每個線程都獲得自己的獨立儲存空間
			TlsSetValue(dwTlsIndex, lpvData);
		}
		break;
	}
	case DLL_THREAD_DETACH:
	{
		// free memory for TLS index for this thread.
		lpvData = TlsGetValue(dwTlsIndex);
		if (lpvData != NULL)
			LocalFree((HLOCAL)lpvData);
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		// cleanup
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourDetach(&(PVOID&)OgMessageBoxW, HookMessageBoxW);
		DetourDetach(&(PVOID&)OgMessageBoxA, HookMessageBoxA);
		DetourDetach(&(PVOID&)OgMessageBoxExW, HookMessageBoxExW);
		DetourDetach(&(PVOID&)OgMessageBoxExA, HookMessageBoxExA);

		DetourDetach(&(PVOID&)OgNtOpenKey, HookNtOpenKey);
		DetourDetach(&(PVOID&)OgNtOpenKeyEx, HookNtOpenKeyEx);
		DetourDetach(&(PVOID&)OgNtQueryValueKey, HookNtQueryValueKey);
		DetourDetach(&(PVOID&)OgNtCreateKey, HookNtCreateKey);
		DetourDetach(&(PVOID&)OgNtEnumerateKey, HookNtEnumerateKey);
		DetourDetach(&(PVOID&)OgNtEnumerateValueKey, HookNtEnumerateValueKey);
		DetourDetach(&(PVOID&)OgNtCreateFile, HookNtCreateFile);
		DetourDetach(&(PVOID&)OgNtQueryAttributesFile, HookNtQueryAttributesFile);
		DetourDetach(&(PVOID&)OgNtDeviceIoControlFile, HookNtDeviceIoControlFile);
		DetourDetach(&(PVOID&)OgNtQueryVolumeInformationFile, HookNtQueryVolumeInformationFile);
		DetourDetach(&(PVOID&)OgNtQuerySystemInformation, HookNtQuerySystemInformation);
		DetourDetach(&(PVOID&)OgNtQuerySystemInformationEx, HookNtQuerySystemInformationEx);
		DetourDetach(&(PVOID&)OgNtPowerInformation, HookNtPowerInformation);
		DetourDetach(&(PVOID&)OgNtQueryLicenseValue, HookNtQueryLicenseValue);
		DetourDetach(&(PVOID&)OgNtQueryDirectoryFile, HookNtQueryDirectoryFile);
		DetourDetach(&(PVOID&)OgNtQueryInformationProcess, HookNtQueryInformationProcess);
		DetourDetach(&(PVOID&)OgNtQueryDirectoryObject, HookNtQueryDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateMutant, HookNtCreateMutant);
		DetourDetach(&(PVOID&)OgNtOpenMutant, HookNtOpenMutant);
		DetourDetach(&(PVOID&)OgGetAdaptersAddresses, HookGetAdaptersAddresses);
		DetourDetach(&(PVOID&)OgProcess32FirstW, HookProcess32FirstW);
		DetourDetach(&(PVOID&)OgProcess32NextW, HookProcess32NextW);
		DetourDetach(&(PVOID&)OgCoCreateInstance, HookCoCreateInstance);
		DetourDetach(&(PVOID&)OgGetModuleHandleW, HookGetModuleHandleW);
		DetourDetach(&(PVOID&)OgGetModuleHandleA, HookGetModuleHandleA);
		DetourDetach(&(PVOID&)OgGetModuleHandleExW, HookGetModuleHandleExW);
		DetourDetach(&(PVOID&)OgGetModuleHandleExA, HookGetModuleHandleExA);
		DetourDetach(&(PVOID&)OgGetAdaptersInfo, HookGetAdaptersInfo);
		DetourDetach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyW, HookSetupDiGetDeviceRegistryPropertyW);
		DetourDetach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyA, HookSetupDiGetDeviceRegistryPropertyA);
		DetourDetach(&(PVOID&)OgGetLastInputInfo, HookGetLastInputInfo);
		DetourDetach(&(PVOID&)OgEnumServicesStatusExA, HookEnumServicesStatusExA);
		DetourDetach(&(PVOID&)OgEnumServicesStatusExW, HookEnumServicesStatusExW);
		DetourDetach(&(PVOID&)OgInternetCheckConnectionA, HookInternetCheckConnectionA);
		DetourDetach(&(PVOID&)OgInternetCheckConnectionW, HookInternetCheckConnectionW);
		DetourDetach(&(PVOID&)OgGetWindowRect, HookGetWindowRect);
		DetourDetach(&(PVOID&)OgGetMonitorInfoA, HookGetMonitorInfoA);
		DetourDetach(&(PVOID&)OgGetMonitorInfoW, HookGetMonitorInfoW);
		DetourDetach(&(PVOID&)OgFindWindowA, HookFindWindowA);
		DetourDetach(&(PVOID&)OgFindWindowW, HookFindWindowW);
		DetourDetach(&(PVOID&)OgFindWindowExA, HookFindWindowExA);
		DetourDetach(&(PVOID&)OgFindWindowExW, HookFindWindowExW);
		DetourDetach(&(PVOID&)OgGetCursorPos, HookGetCursorPos);
		DetourDetach(&(PVOID&)OgGetSystemMetrics, HookGetSystemMetrics);
		DetourDetach(&(PVOID&)OgSystemParametersInfoA, HookSystemParametersInfoA);
		DetourDetach(&(PVOID&)OgSystemParametersInfoW, HookSystemParametersInfoW);
		DetourDetach(&(PVOID&)OgGetAsyncKeyState, HookGetAsyncKeyState);
		DetourDetach(&(PVOID&)OgGetForegroundWindow, HookGetForegroundWindow);
		DetourDetach(&(PVOID&)OgLoadLibraryExW, HookLoadLibraryExW);
		DetourDetach(&(PVOID&)OgLoadLibraryExA, HookLoadLibraryExA);
		DetourDetach(&(PVOID&)OgLoadLibraryW, HookLoadLibraryW);
		DetourDetach(&(PVOID&)OgLoadLibraryA, HookLoadLibraryA);

		DetourDetach(&(PVOID&)OgNtOpenFile, HookNtOpenFile);
		DetourDetach(&(PVOID&)OgNtReadFile, HookNtReadFile);
		DetourDetach(&(PVOID&)OgNtWriteFile, HookNtWriteFile);
		DetourDetach(&(PVOID&)OgNtDeleteFile, HookNtDeleteFile);
		DetourDetach(&(PVOID&)OgNtQueryInformationFile, HookNtQueryInformationFile);
		DetourDetach(&(PVOID&)OgNtSetInformationFile, HookNtSetInformationFile);
		DetourDetach(&(PVOID&)OgNtOpenDirectoryObject, HookNtOpenDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateDirectoryObject, HookNtCreateDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateUserProcess, HookNtCreateUserProcess);
		DetourDetach(&(PVOID&)OgNtCreateProcess, HookNtCreateProcess);
		DetourDetach(&(PVOID&)OgNtCreateProcessEx, HookNtCreateProcessEx);
		DetourDetach(&(PVOID&)OgNtSuspendProcess, HookNtSuspendProcess);
		DetourDetach(&(PVOID&)OgNtTerminateProcess, HookNtTerminateProcess);
		DetourDetach(&(PVOID&)OgNtMapViewOfSection, HookNtMapViewOfSection);
		DetourDetach(&(PVOID&)OgNtUnmapViewOfSection, HookNtUnmapViewOfSection);
		DetourDetach(&(PVOID&)OgNtMakeTemporaryObject, HookNtMakeTemporaryObject);
		DetourDetach(&(PVOID&)OgNtMakePermanentObject, HookNtMakePermanentObject);
		DetourDetach(&(PVOID&)OgNtWriteVirtualMemory, HookNtWriteVirtualMemory);
		DetourDetach(&(PVOID&)OgNtSetInformationProcess, HookNtSetInformationProcess);
		DetourDetach(&(PVOID&)OgNtGetNextProcess, HookNtGetNextProcess);
		DetourDetach(&(PVOID&)OgNtReplaceKey, HookNtReplaceKey);
		DetourDetach(&(PVOID&)OgNtRenameKey, HookNtRenameKey);
		DetourDetach(&(PVOID&)OgNtSaveKey, HookNtSaveKey);
		DetourDetach(&(PVOID&)OgNtSaveKeyEx, HookNtSaveKeyEx);
		DetourDetach(&(PVOID&)OgNtSetValueKey, HookNtSetValueKey);
		DetourDetach(&(PVOID&)OgNtDeleteKey, HookNtDeleteKey);
		DetourDetach(&(PVOID&)OgNtDeleteValueKey, HookNtDeleteValueKey);
		DetourDetach(&(PVOID&)OgNtOpenTimer, HookNtOpenTimer);
		DetourDetach(&(PVOID&)OgNtQueryTimer, HookNtQueryTimer);
		DetourDetach(&(PVOID&)OgNtCreateTimer, HookNtCreateTimer);
		DetourDetach(&(PVOID&)OgNtQuerySystemTime, HookNtQuerySystemTime);
		DetourDetach(&(PVOID&)OgNtOpenEvent, HookNtOpenEvent);
		DetourDetach(&(PVOID&)OgNtNotifyChangeKey, HookNtNotifyChangeKey);
		DetourDetach(&(PVOID&)OgNtOpenSemaphore, HookNtOpenSemaphore);
		DetourDetach(&(PVOID&)OgNtCreateSemaphore, HookNtCreateSemaphore);
		DetourDetach(&(PVOID&)OgNtLockFile, HookNtLockFile);

		DetourDetach(&(PVOID&)OgNtDelayExecution, HookNtDelayExecution);

		// thread test
		DetourDetach(&(PVOID&)OgNtCreateThread, HookNtCreateThread);
		DetourDetach(&(PVOID&)OgNtCreateThreadEx, HookNtCreateThreadEx);

		DetourDetach(&(PVOID&)OgGetSystemTime, HookGetSystemTime);
		DetourDetach(&(PVOID&)OgGetLocalTime, HookGetLocalTime);
		DetourDetach(&(PVOID&)OgFindResourceExW, HookFindResourceExW);
		DetourDetach(&(PVOID&)OgFindResourceExA, HookFindResourceExA);
		DetourDetach(&(PVOID&)OgURLDownloadToFileW, HookURLDownloadToFileW);
		DetourDetach(&(PVOID&)OgInternetOpenA, HookInternetOpenA);
		DetourDetach(&(PVOID&)OgInternetConnectA, HookInternetConnectA);
		DetourDetach(&(PVOID&)OgInternetConnectW, HookInternetConnectW);
		DetourDetach(&(PVOID&)OgInternetOpenUrlA, HookInternetOpenUrlA);
		DetourDetach(&(PVOID&)OgHttpOpenRequestA, HookHttpOpenRequestA);
		DetourDetach(&(PVOID&)OgHttpOpenRequestW, HookHttpOpenRequestW);
		DetourDetach(&(PVOID&)OgHttpSendRequestA, HookHttpSendRequestA);
		DetourDetach(&(PVOID&)OgHttpSendRequestW, HookHttpSendRequestW);
		DetourDetach(&(PVOID&)OgInternetReadFile, HookInternetReadFile);
		DetourDetach(&(PVOID&)OgDnsQuery_A, HookDnsQuery_A);
		DetourDetach(&(PVOID&)OgDnsQuery_W, HookDnsQuery_W);
		DetourDetach(&(PVOID&)OgGetAddrInfoW, HookGetAddrInfoW);
		DetourDetach(&(PVOID&)OgWSAStartup, HookWSAStartup);
		DetourDetach(&(PVOID&)Oggethostbyname, Hookgethostbyname);
		DetourDetach(&(PVOID&)Ogsocket, Hooksocket);
		DetourDetach(&(PVOID&)Ogconnect, Hookconnect);
		DetourDetach(&(PVOID&)Ogsend, Hooksend);
		DetourDetach(&(PVOID&)Ogsendto, Hooksendto);
		DetourDetach(&(PVOID&)Ogrecv, Hookrecv);
		DetourDetach(&(PVOID&)Ogrecvfrom, Hookrecvfrom);
		DetourDetach(&(PVOID&)Ogbind, Hookbind);
		DetourDetach(&(PVOID&)OgWSARecv, HookWSARecv);
		DetourDetach(&(PVOID&)OgWSARecvFrom, HookWSARecvFrom);
		DetourDetach(&(PVOID&)OgWSASend, HookWSASend);
		DetourDetach(&(PVOID&)OgWSASendTo, HookWSASendTo);
		DetourDetach(&(PVOID&)OgWSASocketW, HookWSASocketW);

		DetourDetach(&(PVOID&)OgCreateProcessInternalW, HookCreateProcessInternalW);
#ifdef __32BIT_SYS
		DetourDetach(&(PVOID&)OgGetTickCount, HookGetTickCount);
#endif
		DetourDetach(&(PVOID&)OgQueryPerformanceCounter, HookQueryPerformanceCounter);

		DetourTransactionCommit();

		CloseHandle(hPipe);

		// Release the allocated memory for this thread.
		lpvData = TlsGetValue(dwTlsIndex);
		if (lpvData != NULL)
			LocalFree((HLOCAL)lpvData);

		// Release the TLS index.
		TlsFree(dwTlsIndex);
	}
	default: break;
	} // end switch

	return TRUE;
}

