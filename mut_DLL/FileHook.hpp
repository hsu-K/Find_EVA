#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

NTSTATUS NTAPI HookNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileAttributes)
{
	// MUT_TEST #3
	//	SIMPLE_LOG(NTSTATUS, NtQueryAttributesFile, ObjectAttributes, FileAttributes)
	NTSTATUS ret;

	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)
	BOOL* flag = NULL;
	// record the call
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtQueryAttributesFile, CTX_STR, &ctxVal, Hash, RetAddr);
			Mutation* mut = FindMutation(mutNtQueryAttributesFile, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtQueryAttributesFile!\n");
#endif
					// return error code
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryAttributesFile(ObjectAttributes, FileAttributes);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (opening existing file -> file does not exist: STATUS_OBJECT_NAME_NOT_FOUND)
	BOOL* flag = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtCreateFile, CTX_STR, &ctxVal, Hash, RetAddr);

			// A file that is being created cannot fail by not existing. We could mutate only FILE_OPEN
			// Files can also be found by being created, since the error code will be ala ERROR_ALREADY_EXISTS, but then the file is destroyed.
			// Since we would like to prevent the VM-sensitive files from being destroyed, we should be able to mutate all CreateFile calls
			// Unfortunately, we cannot set the Last Error from this hook (gets overwritten).

			Mutation* mut = FindMutation(mutNtCreateFile, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtCreateFile!\n");
#endif
					// return error code
					IoStatusBlock->Status = (NTSTATUS)mut->mutValue.nValue;
					IoStatusBlock->Information = FILE_DOES_NOT_EXIST;
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}

			/* CreateDisposition:
			FILE_OPEN           -> OPEN_EXISTING | TRUNCATE_EXISTING
			FILE_CREATE         -> CREATE_NEW
			FILE_OPEN_IF        -> OPEN_ALWAYS
			FILE_OVERWRITE_IF   -> CREATE_ALWAYS*/
		}
	}

	ret = OgNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	// 	SIMPLE_LOG(NTSTATUS, NtDeviceIoControlFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disk size), MUT_FAIL (STATUS_INVALID_HANDLE: 0xC0000008)
	// control code IOCTL_DISK_GET_LENGTH_INFO (0x7405c)
	BOOL* flag = NULL;
	//printf("Hook NtDeviceIoControlFile: Controlcode %x\n", IoControlCode);
	// If other controlcodes are interesting, the control code should be the record context
	//if (IoControlCode == 0x7405c) { // IOCTL_DISK_GET_LENGTH_INFO
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();

		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)IoControlCode;
		RecordCall(Call::cNtDeviceIoControlFile, CTX_NUM, &ctxVal, Hash, RetAddr);

		Mutation* mut = FindMutation(mutNtDeviceIoControlFile, CTX_NUM, &ctxVal, Hash); // ctx matches the class
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return (NTSTATUS)mut->mutValue.nValue;
			}
			else if (mut->mutType == MUT_ALT_NUM) { // only IoControlCode 0x7405c
				ret = OgNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
				if (NT_SUCCESS(ret)) {
					if (OutputBuffer != NULL) {
						PGET_LENGTH_INFORMATION size = (PGET_LENGTH_INFORMATION)OutputBuffer;
						// pass mutation as GB, then perform LONGLONG * 1000237400
						size->Length.QuadPart = (LONGLONG)mut->mutValue.nValue * 1000237400;
					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}
	//}

	ret = OgNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileSystemInformation, ULONG Length, FS_INFORMATION_CLASS FileSystemInformationClass)
{
	// 	SIMPLE_LOG(NTSTATUS, NtQueryVolumeInformationFile, FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disk size), MUT_FAIL (STATUS_INVALID_HANDLE: 0xC0000008)
	BOOL* flag = NULL;
	// if other classes are of interest, record context should be the class
	//if (FileSystemInformationClass == FileFsDeviceInformation) {
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)FileSystemInformationClass;
		RecordCall(Call::cNtQueryVolumeInformationFile, CTX_NUM, &ctxVal, Hash, RetAddr);

		// no findmutation since no context to match
		Mutation* mut = FindMutation(mutNtQueryVolumeInformationFile, CTX_NUM, &ctxVal, Hash);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return (NTSTATUS)mut->mutValue.nValue;
			}
			else if (mut->mutType == MUT_ALT_NUM) { // ctx only FileFsDeviceInformation
				ret = OgNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass);
				if (NT_SUCCESS(ret)) {
					// The value is used to multiply the total disk space
					PFILE_FS_SIZE_INFORMATION size = (PFILE_FS_SIZE_INFORMATION)FileSystemInformation;
					if (size != NULL) {
						size->TotalAllocationUnits.QuadPart *= mut->mutValue.nValue;
					}
					// Disk Size = TotalAllocationUnits * SectorsPerAllocationUnit * BytesPerSector
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}
	//}

	ret = OgNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileMask, BOOLEAN RestartScan)
{
	// MUT_TEST #4
	//  SIMPLE_LOG(NTSTATUS, NtQueryDirectoryFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan)
	NTSTATUS ret;

	// Mutation types: MUT_FAIL (STATUS_NO_SUCH_FILE: file not found), MUT_HIDE skip file (todo)
	// TODO: investigate repeated calls (list of files) structure

	/*
	The ZwQueryDirectoryFileroutine returns STATUS_SUCCESS or an appropriate error status.
	Note that the set of error status values that can be returned is file-system-specific.
	ZwQueryDirectoryFilealso returns the number of bytes actually written to the given FileInformation buffer in the Information member of IoStatusBlock.
	*/
	BOOL* flag = NULL;
	if (FileMask != NULL && FileInformationClass == 3) { // FileBothDirectoryInformation
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			//printf("::: FileMask: %ws\n", FileMask->Buffer);
			// record the call
			ContextValue ctxVal;
			size_t widec = FileMask->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, FileMask->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtQueryDirectoryFile, CTX_STR, &ctxVal, Hash, RetAddr);
			// STATUS_NO_SUCH_FILE for a single file request

			Mutation* mut = FindMutation(mutNtQueryDirectoryFile, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying NtQueryDirectoryFile mutation!\n");
#endif
				if (mut->mutType == MUT_FAIL) {
					// return error code
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan);
	if (flag) (*flag) = FALSE;
	return ret;
}

// not mut
NTSTATUS NTAPI HookNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenFile, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtOpenFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}

	ret = OgNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	return ret;
}

NTSTATUS NTAPI HookNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtReadFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return ret;
}

NTSTATUS NTAPI HookNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS ret;
	if (FileHandle == hPipe) { // always skip pipe writes
		return OgNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtWriteFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteFile, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtDeleteFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtDeleteFile(ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryInformationFile, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtQueryInformationFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return ret;
}

NTSTATUS NTAPI HookNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	// SIMPLE_LOG(NTSTATUS, NtSetInformationFile, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtSetInformationFile, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return ret;
}

NTSTATUS NTAPI HookNtLockFile(HANDLE FileHandle, HANDLE LockGrantedEvent, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, PULONG Key, BOOLEAN ReturnImmediately, BOOLEAN ExclusiveLock)
{
	// SIMPLE_LOG(NTSTATUS, NtLockFile, FileHandle, LockGrantedEvent, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, ReturnImmediately, ExclusiveLock)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtLockFile, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtLockFile(FileHandle, LockGrantedEvent, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, ReturnImmediately, ExclusiveLock);
	return ret;
}

NTSTATUS NTAPI HookNtOpenDirectoryObject(PHANDLE DirectoryObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenDirectoryObject, DirectoryObjectHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtOpenDirectoryObject, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtOpenDirectoryObject(DirectoryObjectHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength)
{
	//  SIMPLE_LOG(NTSTATUS, NtQueryDirectoryObject, DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL, "empty result"?
	// BOOL* flag = NULL;
	// unclear
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtQueryDirectoryObject, CTX_NONE, NULL, Hash, RetAddr);
	}

	ret = OgNtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateDirectoryObject, DirectoryHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtCreateDirectoryObject, CTX_STR, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

HRSRC WINAPI HookFindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage)
{
	HRSRC ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		if (IS_INTRESOURCE(lpName)) {
			ctxVal.dwCtx = (DWORD)((ULONG_PTR)(lpName));
			RecordCall(Call::cFindResourceExW, CTX_NUM, &ctxVal, Hash, RetAddr);
		}
		else {
			size_t widec = wcslen(lpName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindResourceExW, CTX_STR, &ctxVal, Hash, RetAddr);
		}
	}

	ret = OgFindResourceExW(hModule, lpType, lpName, wLanguage);
	if (flag) (*flag) = FALSE;
	return ret;
}

HRSRC WINAPI HookFindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage)
{
	HRSRC ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;

		if (IS_INTRESOURCE(lpName)) {
			ctxVal.dwCtx = (DWORD)((ULONG_PTR)(lpName));
			RecordCall(Call::cFindResourceExA, CTX_NUM, &ctxVal, Hash, RetAddr);
		}
		else {
			size_t widec = strlen(lpName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindResourceExA, CTX_STR, &ctxVal, Hash, RetAddr);
		}
	}

	ret = OgFindResourceExA(hModule, lpType, lpName, wLanguage);
	if (flag) (*flag) = FALSE;
	return ret;
}
