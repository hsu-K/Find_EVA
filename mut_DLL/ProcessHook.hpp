#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

extern LPVOID pLoadLibraryA;


// Process
NTSTATUS NTAPI HookNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
	NTSTATUS ret;
	// Mutation types: MUT_HIDE (hides all...)
	BOOL* flag = NULL;
	//if (ProcessInformationClass == ProcessBasicInformation) {
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)ProcessInformationClass;
		RecordCall(Call::cNtQueryInformationProcess, CTX_NUM, &ctxVal, Hash, RetAddr);

		Mutation* mut = FindMutation(mutNtQueryInformationProcess, CTX_NUM, &ctxVal, Hash); // ctx matches the class
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_HIDE) { // ctx only ProcessBasicInformation
				ret = OgNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
				if (NT_SUCCESS(ret)) {
					PPROCESS_BASIC_INFORMATION PBI = (PPROCESS_BASIC_INFORMATION)ProcessInformation;
					if (PBI != NULL) {
						PPEB PEB = (PPEB)PBI->PebBaseAddress;
						PPEB_LDR_DATA PLDR = (PPEB_LDR_DATA)PEB->Ldr;

						PLIST_ENTRY head = &PLDR->InMemoryOrderModuleList;
						PLIST_ENTRY curr = head->Flink;
						while (curr != head) {
							LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
							if (entry) {
								// if dll name contains "Enviral" or "VBox" or "vbox"
								if (wcsstr(entry->FullDllName.Buffer, L"vbox") != NULL ||
									wcsstr(entry->FullDllName.Buffer, L"VBox") != NULL ||
									wcsstr(entry->FullDllName.Buffer, L"Enviral") != NULL) {
									// wrap around forward link
									PLIST_ENTRY prev = curr->Blink;
									prev->Flink = curr->Flink;
									// wrap around backlink
									PLIST_ENTRY next = curr->Flink;
									next->Blink = prev;
								}
							}
							curr = curr->Flink;
						}
					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
			else if (mut->mutType == MUT_FAIL) {
				ReturnLength = 0;
				if (flag) (*flag) = FALSE;
				return STATUS_INVALID_PARAMETER;
			}
		}
	}
	//}

	ret = OgNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	//  SIMPLE_LOG(BOOL, Process32FirstW, hSnapshot, lppe)
	BOOL ret;
	// Mutation types: MUT_HIDE (contain "vbox")
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cProcess32FirstW, CTX_NONE, NULL, Hash, RetAddr);
		if (mutProcess32FirstW != NULL) {
			if (mutProcess32FirstW->mutType == MUT_HIDE) {
				ret = OgProcess32FirstW(hSnapshot, lppe);
				if (ret && wcsstr(_wcslwr(lppe->szExeFile), L"vbox")) {
					if (flag) (*flag) = FALSE;
					return HookProcess32NextW(hSnapshot, lppe);
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}

	ret = OgProcess32FirstW(hSnapshot, lppe);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	//  SIMPLE_LOG(BOOL, Process32NextW, hSnapshot, lppe)
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_HIDE (contain "vbox")
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cProcess32NextW, CTX_NONE, NULL, Hash, RetAddr);
		if (mutProcess32NextW != NULL) {
			if (mutProcess32NextW->mutType == MUT_HIDE) {
				ret = OgProcess32NextW(hSnapshot, lppe);
				if (ret && wcsstr(_wcslwr(lppe->szExeFile), L"vbox")) {
					if (flag) (*flag) = FALSE;
					return HookProcess32NextW(hSnapshot, lppe);
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
			else if (mutProcess32NextW->mutType == MUT_FAIL) {
				// no need to memset, call not performed
				if (flag) (*flag) = FALSE;
				SetLastError(ERROR_NO_MORE_FILES);
				return FALSE;
			}
		}
	}

	ret = OgProcess32NextW(hSnapshot, lppe);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtSetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	// SIMPLE_LOG(NTSTATUS, NtSetInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtSetInformationProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	return ret;
}

NTSTATUS NTAPI HookNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtGetNextProcess, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtGetNextProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
	return ret;
}


// not mut
NTSTATUS NTAPI HookNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList)
{
	NTSTATUS ret;

	// unfortunately, the process flags are not passed to NtCreateUserProcess, so we cannot inject the DLL from here
	// we can still use it to track process creation activity however
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtCreateUserProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
	return ret;
}

NTSTATUS NTAPI HookNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtCreateProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	return ret;
}

NTSTATUS NTAPI HookNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateProcessEx, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtCreateProcessEx, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
	return ret;
}

NTSTATUS NTAPI HookNtSuspendProcess(HANDLE ProcessHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtSuspendProcess, ProcessHandle)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtSuspendProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtSuspendProcess(ProcessHandle);
	return ret;
}

NTSTATUS NTAPI HookNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	// SIMPLE_LOG(NTSTATUS, NtTerminateProcess, ProcessHandle, ExitStatus)
	NTSTATUS ret;
	// processhandle == NULL -> current process exits
	// printf("NtTerminateProcess -- Handle:%p Exit:%x\n", ProcessHandle, ExitStatus);
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtTerminateProcess, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtTerminateProcess(ProcessHandle, ExitStatus);
	return ret;
}

BOOL WINAPI HookCreateProcessInternalW(HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
	BOOL ret;
#ifdef __DEBUG_PRINT
	printf("Hook::: CreateProcessInternalW: %x\n", dwCreationFlags);
#endif
	UINT64 Hash;
	UINT64 RetAddr = 0;
	SkipActivity(&Hash, &RetAddr);

	dwCreationFlags |= CREATE_SUSPENDED;
	ret = OgCreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
	if (ret) {
#ifdef __DEBUG_PRINT
		printf("Created process - PID:%lu HANDLE:%p\n", lpProcessInformation->dwProcessId, lpProcessInformation->hProcess);
#endif

		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)(lpProcessInformation->dwProcessId);
		RecordCall(Call::cCreateProcessInternalW, CTX_NUM, &ctxVal, Hash, RetAddr);

		size_t lendll = sizeof(TARGET_DLL); //strlen(TARGET_DLL);
		LPVOID dllname = VirtualAllocEx(lpProcessInformation->hProcess, NULL, lendll, MEM_COMMIT, PAGE_READWRITE);
		if (dllname == NULL) {
			return FALSE;
		}
		if (!WriteProcessMemory(lpProcessInformation->hProcess, dllname, TARGET_DLL, lendll, NULL)) {
			return FALSE;
		}
		HANDLE hThread = CreateRemoteThread(lpProcessInformation->hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllname, NULL, NULL);
		if (hThread == NULL) {
			return FALSE;
		}
		WaitForSingleObject(hThread, INFINITE); // INFINITE?
		ResumeThread(lpProcessInformation->hThread);
		VirtualFreeEx(lpProcessInformation->hProcess, dllname, 0, MEM_RELEASE);
	}
	return ret;
}


// Module
//not mut
HMODULE WINAPI HookGetModuleHandleW(LPCWSTR lpModuleName)
{
	HMODULE ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpModuleName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleW, CTX_STR, &ctxVal, Hash, RetAddr);

			/*
			Mutation* mut = FindMutation(mutGetModuleHandleW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
			*/
		}
	}

	ret = OgGetModuleHandleW(lpModuleName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookGetModuleHandleA(LPCSTR lpModuleName)
{
	HMODULE ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpModuleName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleA, CTX_STR, &ctxVal, Hash, RetAddr);
			/*
			Mutation* mut = FindMutation(mutGetModuleHandleA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
			*/
		}
	}

	ret = OgGetModuleHandleA(lpModuleName);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
{
	BOOL ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpModuleName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleExW, CTX_STR, &ctxVal, Hash, RetAddr);

			/*
			Mutation* mut = FindMutation(mutGetModuleHandleExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (phModule != NULL) phModule = NULL;
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return FALSE;
				}
			}*/
		}
	}

	ret = OgGetModuleHandleExW(dwFlags, lpModuleName, phModule);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookGetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule)
{
	BOOL ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();

			ContextValue ctxVal;
			size_t widec = strlen(lpModuleName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleExA, CTX_STR, &ctxVal, Hash, RetAddr);
			/*
			Mutation* mut = FindMutation(mutGetModuleHandleExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (phModule != NULL) phModule = NULL;
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return FALSE;
				}
			}*/
		}
	}

	ret = OgGetModuleHandleExA(dwFlags, lpModuleName, phModule);
	if (flag) (*flag) = FALSE;
	return ret;
}

// Library
HMODULE WINAPI HookLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE ret;

	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpLibFileName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryExW, CTX_STR, &ctxVal, Hash, RetAddr);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutLoadLibraryExW, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpLibFileName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryExA, CTX_STR, &ctxVal, Hash, RetAddr);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutLoadLibraryExA, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}


HMODULE WINAPI HookLoadLibraryW(LPCWSTR lpLibFileName)
{
	HMODULE ret;

	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpLibFileName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryW, CTX_STR, &ctxVal, Hash, RetAddr);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutLoadLibraryW, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryW(lpLibFileName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookLoadLibraryA(LPCSTR lpLibFileName)
{
	HMODULE ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpLibFileName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryA, CTX_STR, &ctxVal, Hash, RetAddr);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutLoadLibraryA, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryA(lpLibFileName);
	if (flag) (*flag) = FALSE;
	return ret;
}

// Thread
// not mut
NTSTATUS NTAPI HookNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateThread, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtCreateThread, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
	return ret;
}
NTSTATUS NTAPI HookNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtCreateThreadEx, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	/*if (NT_SUCCESS(ret)) {
		if (SkipActivity(&Hash)) {
			printf("Thread Created In Hook. Current TID: %lu\n", GetCurrentThreadId());
			CLIENT_ID* cid = (CLIENT_ID*)AttributeList->Attributes[0].Value;
			if (cid != NULL) {
				printf("CLIENT_ID P:%p U:%p TID:%lu\n", cid->UniqueProcess, cid->UniqueThread, (DWORD)cid->UniqueThread);
				//DWORD newTid = GetThreadId(cid->UniqueThread);
				//printf("Newly Created TID: %lu\n", newTid);
			}
			//printf("pValue: %p\n", AttributeList->Attributes[0].Value);
		}
	}*/
	return ret;
}
