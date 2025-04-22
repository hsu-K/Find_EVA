#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"


NTSTATUS NTAPI HookNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	// SIMPLE_LOG(NTSTATUS, NtMapViewOfSection, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMapViewOfSection, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	return ret;
}

NTSTATUS NTAPI HookNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
	// SIMPLE_LOG(NTSTATUS, NtUnmapViewOfSection, ProcessHandle, BaseAddress)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtUnmapViewOfSection, CTX_NONE, NULL, Hash);
	}
	ret = OgNtUnmapViewOfSection(ProcessHandle, BaseAddress);
	return ret;
}

NTSTATUS NTAPI HookNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	// SIMPLE_LOG(NTSTATUS, NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtWriteVirtualMemory, CTX_NONE, NULL, Hash);
	}
	ret = OgNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	return ret;
}

NTSTATUS NTAPI HookNtMakeTemporaryObject(HANDLE ObjectHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtMakeTemporaryObject, ObjectHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMakeTemporaryObject, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMakeTemporaryObject(ObjectHandle);
	return ret;
}

NTSTATUS NTAPI HookNtMakePermanentObject(HANDLE Handle)
{
	// SIMPLE_LOG(NTSTATUS, NtMakePermanentObject, Handle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMakePermanentObject, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMakePermanentObject(Handle);
	return ret;
}

HRESULT WINAPI HookCoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
	HRESULT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cCoCreateInstance, CTX_NONE, NULL, Hash);
		if (mutCoCreateInstance != NULL) {
			if (mutCoCreateInstance->mutType == MUT_FAIL) {
				if (flag) (*flag) = FALSE;
				return REGDB_E_CLASSNOTREG; //(long) 0x8000FFFFL
			}
		}
	}

	ret = OgCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
	if (flag) (*flag) = FALSE;
	return ret;
}
