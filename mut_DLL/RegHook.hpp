#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

// 當前
// Environment Query Hooks
NTSTATUS NTAPI HookNtOpenKey(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)

	BOOL* flag = NULL;

	// 檢查傳入的ObjectAttributes是否為空
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		UINT64 RetAddr;

		// 利用SkipActivity來決定是否要記錄這次的調用，避免Hook又Hook
		if (!SkipActivity(&Hash, &RetAddr)) {
			// 紀錄已經進入Hook
			flag = EnterHook();
			ContextValue ctxVal;
			//cout << "進入Hook__" << endl;
			// 紀錄ObjectAttributes->ObjectName
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(WCHAR);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			//cout << ctxVal.szCtx << endl;
			// 紀錄Call，並回傳給主程式紀錄
			RecordCall(Call::cNtOpenKey, CTX_STR, &ctxVal, Hash, RetAddr);

			// 找到對應的Mutation
			Mutation* mut = FindMutation(mutNtOpenKey, CTX_STR, &ctxVal, Hash);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtOpenKey.\n");
#endif
					if (flag) { (*flag) = FALSE; }
					// 強制更改函數的回傳值
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenKey(pKeyHandle, DesiredAccess, ObjectAttributes);
	if (flag) { (*flag) = FALSE; }
	return ret;
}

NTSTATUS NTAPI HookNtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)

	BOOL* flag = NULL;
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
			RecordCall(Call::cNtOpenKeyEx, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtOpenKeyEx, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtOpenKeyEx.\n");
#endif
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	// MUT_TEST #2
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (value not found: STATUS_OBJECT_NAME_NOT_FOUND) or MUT_ALT_STR

	// Context ValueName:Value
	BOOL* flag = NULL;
	if (ValueName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ValueName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN - 30) {
				widec = MAX_CTX_LEN - 30; // save some space for data
			}
			wcsncpy(ctxVal.szCtx, ValueName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			if (KeyValueInformationClass == KeyValuePartialInformation) { // default from Win32 API
				ret = OgNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
				if (NT_SUCCESS(ret)) {
					PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
					if (info != NULL) {
						// DataLength: size of Data in bytes.
						size_t widerem = MAX_CTX_LEN - 1 - widec; // this can be 0
						size_t wreq = wcslen(info->Data);
						if (wreq + 2 >= widerem) { // more chars needed than remaining
							wcscat(ctxVal.szCtx, L":");
							wcsncat(ctxVal.szCtx, info->Data, widerem - 2);
						}
						else {
							wcscat(ctxVal.szCtx, L":");
							wcscat(ctxVal.szCtx, info->Data);
						}

						RecordCall(Call::cNtQueryValueKey, CTX_STR, &ctxVal, Hash);

						Mutation* mut = FindMutation(mutNtQueryValueKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
								// return error code
								KeyValueInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
								size_t lenMut = wcslen(mut->mutValue.szValue);
								if (lenMut * 2 + 2 > info->DataLength) {
									// max datalen
									ULONG LastIndex = ((info->DataLength - 1) / 2);
									memcpy(info->Data, mut->mutValue.szValue, LastIndex * sizeof(wchar_t));
									info->Data[LastIndex] = L'\0';
								}
								else {
									// fits
									memcpy(info->Data, mut->mutValue.szValue, (lenMut + 1) * sizeof(wchar_t));
								}
							}
						}

					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			} // include other cases for direct NT calls
		}
	}

	ret = OgNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtCreateKey(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateKey, pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disposition 1, indicating new key was created, while 2 opens an existing key)
	BOOL* flag = NULL;
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

			RecordCall(Call::cNtCreateKey, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtCreateKey, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_ALT_NUM && Disposition != NULL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_ALT_NUM mutation to NtCreateKey.\n");
#endif
					ret = OgNtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
					if (NT_SUCCESS(ret)) {
						*Disposition = (ULONG)mut->mutValue.nValue;
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgNtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
	//	SIMPLE_LOG(NTSTATUS, NtEnumerateKey, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_NO_MORE_ENTRIES?), MUT_ALT_STR

	BOOL* flag = NULL;
	ULONG NameSize;
	ContextValue ctxVal;
	if (GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
		if (KeyInformationClass == KeyBasicInformation) {
			UINT64 Hash;
			if (!SkipActivity(&Hash)) {
				flag = EnterHook();
				ret = OgNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
				if (NT_SUCCESS(ret)) {
					PKEY_BASIC_INFORMATION pkey = (PKEY_BASIC_INFORMATION)KeyInformation;
					if (pkey != NULL) {
						// Name is NOT null terminated...
						ULONG OgLenW = pkey->NameLength / 2;

						// Record
						wcscat(ctxVal.szCtx, L":");
						size_t curLen = NameSize + 1; // :
						size_t copylen = pkey->NameLength;
						if (curLen + (OgLenW) >= MAX_CTX_LEN) { // bounds
							copylen = (MAX_CTX_LEN - 1 - curLen) * 2;
						}
						memcpy(&ctxVal.szCtx[curLen], pkey->Name, copylen);
						ctxVal.szCtx[curLen + (copylen / 2)] = L'\0';
						RecordCall(Call::cNtEnumerateKey, CTX_STR, &ctxVal, Hash);

						// Mutations
						Mutation* mut = FindMutation(mutNtEnumerateKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
								KeyInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
								size_t lenMut = wcslen(mut->mutValue.szValue);
								if (lenMut <= OgLenW) {
									// fits
									memcpy(pkey->Name, mut->mutValue.szValue, lenMut * sizeof(wchar_t));
									pkey->NameLength = lenMut * 2;
								}
								else {
									// max
									memcpy(pkey->Name, mut->mutValue.szValue, pkey->NameLength);
								}
							}
						}
					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
		// TODO: handle other classes for direct NT calls
	}

	ret = OgNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	//	SIMPLE_LOG(NTSTATUS, NtEnumerateValueKey, KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_NO_MORE_ENTRIES), MUT_ALT_STR
	BOOL* flag = NULL;
	if (KeyValueInformationClass == KeyValueFullInformation) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
			if (NT_SUCCESS(ret)) {
				PKEY_VALUE_FULL_INFORMATION pvalue = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
				if (pvalue != NULL) {
					if (pvalue->Type == REG_MULTI_SZ || pvalue->Type == REG_SZ || pvalue->Type == REG_EXPAND_SZ) { // string
						wchar_t* data = (wchar_t*)((BYTE*)KeyValueInformation + pvalue->DataOffset);
						ContextValue ctxVal;

						size_t widec = pvalue->NameLength / sizeof(wchar_t);
						if (widec >= MAX_CTX_LEN - 30) {
							widec = MAX_CTX_LEN - 30; // make space
						}
						memcpy(&ctxVal.szCtx, pvalue->Name, widec * sizeof(wchar_t));
						ctxVal.szCtx[widec] = L'\0';
						size_t wreq = wcslen(data);
						size_t widerem = MAX_CTX_LEN - 1 - widec;
						if (wreq + 2 >= widerem) {
							wcscat(ctxVal.szCtx, L":");
							wcsncat(ctxVal.szCtx, data, widerem - 2);
						}
						else {
							wcscat(ctxVal.szCtx, L":");
							wcscat(ctxVal.szCtx, data);
						}

						RecordCall(Call::cNtEnumerateValueKey, CTX_STR, &ctxVal, Hash);

						Mutation* mut = FindMutation(mutNtEnumerateValueKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
								printf("Applying MUT_FAIL mutation to NtEnumerateValueKey.\n");
#endif
								KeyValueInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
#ifdef __DEBUG_PRINT
								printf("Applying MUT_ALT_STR mutation to NtEnumerateValueKey.\n");
#endif
								size_t lenMut = wcslen(mut->mutValue.szValue);
								size_t avail = pvalue->DataLength - pvalue->NameLength; // bytes

								if (lenMut * 2 + 2 <= avail) {
									memcpy(data, mut->mutValue.szValue, (lenMut + 1) * sizeof(wchar_t));
								}
								else {
									// limit avail bytes
									ULONG index = (avail / 2);
									memcpy(data, mut->mutValue.szValue, (index - 1) * sizeof(wchar_t));
									data[index - 1] = L'\0';
								}
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}
	// consider adding other cases for direct NT call completeness

	ret = OgNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID Data, ULONG DataSize, PULONG ResultDataSize)
{
	//   SIMPLE_LOG(NTSTATUS, NtQueryLicenseValue, ValueName, Type, Data, DataSize, ResultDataSize)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED (non-zero result), MUT_FAIL (STATUS_INVALID_PARAMETER: 0xC000000D)
	BOOL* flag = NULL;
	// ctx: L"Security-SPP-GenuineLocalStatus" -> Data = 1 (genuine)
	// ctx: L"Kernel-VMDetection-Private" -> Data = 0 (no VM)

	if (ValueName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ValueName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ValueName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtQueryLicenseValue, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtQueryLicenseValue, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_SUCCEED) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_SUCCEED mutation to NtQueryLicenseValue!\n");
#endif
					ret = OgNtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize);
					if (NT_SUCCESS(ret) && Data != NULL) {
						*(DWORD*)Data = (DWORD)mut->mutValue.nValue;
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
				else if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize);
	if (flag) (*flag) = FALSE;
	return ret;
}


// not mut
NTSTATUS NTAPI HookNtReplaceKey(POBJECT_ATTRIBUTES NewHiveFileName, HANDLE KeyHandle, POBJECT_ATTRIBUTES BackupHiveFileName)
{
	// SIMPLE_LOG(NTSTATUS, NtReplaceKey, NewHiveFileName, KeyHandle, BackupHiveFileName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {

		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtReplaceKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtReplaceKey(NewHiveFileName, KeyHandle, BackupHiveFileName);
	return ret;
}

NTSTATUS NTAPI HookNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName)
{
	// SIMPLE_LOG(NTSTATUS, NtRenameKey, KeyHandle, NewName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtRenameKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtRenameKey(KeyHandle, NewName);
	return ret;
}

NTSTATUS NTAPI HookNtSaveKey(HANDLE KeyHandle, HANDLE FileHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtSaveKey, KeyHandle, FileHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSaveKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSaveKey(KeyHandle, FileHandle);
	return ret;
}

NTSTATUS NTAPI HookNtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format)
{
	// SIMPLE_LOG(NTSTATUS, NtSaveKeyEx, KeyHandle, FileHandle, Format)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSaveKeyEx, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSaveKeyEx(KeyHandle, FileHandle, Format);
	return ret;
}

NTSTATUS NTAPI HookNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
	// SIMPLE_LOG(NTSTATUS, NtSetValueKey, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSetValueKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteKey(HANDLE KeyHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteKey, KeyHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtDeleteKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtDeleteKey(KeyHandle);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteValueKey, KeyHandle, ValueName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtDeleteValueKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtDeleteValueKey(KeyHandle, ValueName);
	return ret;
}

NTSTATUS NTAPI HookNtNotifyChangeKey(HANDLE KeyHandle, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID RegChangesDataBuffer, ULONG RegChangesDataBufferLength, BOOLEAN Asynchronous)
{
	// SIMPLE_LOG(NTSTATUS, NtNotifyChangeKey, KeyHandle, EventHandle, ApcRoutine, ApcRoutineContext, IoStatusBlock, NotifyFilter, WatchSubtree, RegChangesDataBuffer, RegChangesDataBufferLength, Asynchronous)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtNotifyChangeKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtNotifyChangeKey(KeyHandle, EventHandle, ApcRoutine, ApcRoutineContext, IoStatusBlock, NotifyFilter, WatchSubtree, RegChangesDataBuffer, RegChangesDataBufferLength, Asynchronous);
	return ret;
}