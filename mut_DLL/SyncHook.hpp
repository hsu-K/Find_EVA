#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"


NTSTATUS NTAPI HookNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateMutant, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED

	// malware tries to create mutexes of installed programs to detect it being active.
	// if the mutex already exists, it will be opened, but we can forge the result to appear as new
	// the retval is 0x40000000 and getlasterror is ERROR_ALREADY_EXISTS (b7) if the create causes an open
	// createmutant should 'succeed' (as if created new)

	// win: #define MUTEX_VPCXPMODE L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex"
	// only useful when using Microsoft Virtual PC
	BOOL* flag = NULL;
	// Unnamed mutexes are not of relevance for evasive behavior
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
			if (NT_SUCCESS(ret)) {
				if (ret == 0x40000000) { // STATUS_OBJECT_NAME_EXISTS
					// important: we only record createmutex calls that create an already existing mutex (evasive)
					ContextValue ctxVal;
					size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
					if (widec >= MAX_CTX_LEN) {
						widec = MAX_CTX_LEN - 1;
					}
					wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
					ctxVal.szCtx[widec] = L'\0';

					RecordCall(Call::cNtCreateMutant, CTX_STR, &ctxVal, Hash);

					Mutation* mut = FindMutation(mutNtCreateMutant, CTX_STR, &ctxVal);
					if (mut != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying NtCreateMutant mutation!\n");
#endif
						if (mut->mutType == MUT_SUCCEED) {
							if (flag) (*flag) = FALSE;
							return 0; // STATUS_SUCCESS (also clears GetLastError 0xb7)
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}

	ret = OgNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	//  SIMPLE_LOG(NTSTATUS, NtOpenMutant, MutantHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND:0xC0000034 named mutex does not exist)

	BOOL* flag = NULL;
	// if the open
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtOpenMutant, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtOpenMutant, CTX_STR, &ctxVal);
			if (mut != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying NtOpenMutant mutation!\n");
#endif
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					// STATUS_OBJECT_NAME_NOT_FOUND also sets LastError ERROR_FILE_NOT_FOUND
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenMutant(MutantHandle, DesiredAccess, ObjectAttributes);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenEvent, EventHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenEvent, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenTimer, TimerHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenTimer(TimerHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ReturnLength)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryTimer, TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtQueryTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtQueryTimer(TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateTimer, TimerHandle, DesiredAccess, ObjectAttributes, TimerType)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
	return ret;
}

NTSTATUS NTAPI HookNtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenSemaphore, SemaphoreHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenSemaphore, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG InitialCount, ULONG MaximumCount)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateSemaphore, SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateSemaphore, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
	return ret;
}
