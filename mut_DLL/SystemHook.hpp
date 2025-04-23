#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "CoreUtil.hpp"
#include "syscalls.h"
#include "GlobalMutation.hpp"

NTSTATUS NTAPI HookNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS ret;
	// Mutation types: (context dependent) MUT_ALT_NUM, MUT_FAIL, MUT_ALT_STR
	BOOL* flag = NULL;
	//printf("Hook NtQuerySystemInformation: %d\n", SystemInformationClass);
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)SystemInformationClass;
		RecordCall(Call::cNtQuerySystemInformation, CTX_NUM, &ctxVal, Hash, RetAddr);

		Mutation* mut = FindMutation(mutNtQuerySystemInformation, CTX_NUM, &ctxVal, Hash); // ctx matches the class
		if (mut != NULL) {
			if (mut->mutType == MUT_FAIL) {
				// STATUS_INFO_LENGTH_MISMATCH...?
				// STATUS_INVALID_INFO_CLASS
				// STATUS_INVALID_PARAMETER
				ReturnLength = 0;
				if (flag) (*flag) = FALSE;
				return STATUS_INVALID_PARAMETER;
			}
			else if (mut->mutType == MUT_ALT_NUM) {
				if (SystemInformationClass == SystemBasicInformation) {
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PSYSTEM_BASIC_INFORMATION pbi = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
						if (pbi != NULL) {
							pbi->NumberOfProcessors = (CCHAR)mut->mutValue.nValue;
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
			else if (mut->mutType == MUT_HIDE) {
				if (SystemInformationClass == 11) { // SystemModuleInformation
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)SystemInformation;
						ULONG delptr = 0;
						for (ULONG i = 0; i < info->NumberOfModules; i++) {
							if (strstr((char*)info->Modules[i].FullPathName, "VBox") != NULL) {
#ifdef __DEBUG_PRINT
								printf("hook: %s\n", info->Modules[i].FullPathName);
#endif
								delptr++;
							}
						}
						ULONG newCount = info->NumberOfModules - delptr;
						// could probably allocate one struct less
						ULONG pmsize = sizeof(RTL_PROCESS_MODULE_INFORMATION) * (newCount);
						PRTL_PROCESS_MODULES nPM = (PRTL_PROCESS_MODULES)malloc(sizeof(RTL_PROCESS_MODULES) + pmsize);
						if (nPM != NULL) {
							nPM->NumberOfModules = newCount;
							ULONG j = 0;
							for (ULONG i = 0; i < info->NumberOfModules; i++) {
								if (strstr((char*)info->Modules[i].FullPathName, "VBox") == NULL) {
									memcpy(&nPM->Modules[j], &info->Modules[i], sizeof(RTL_PROCESS_MODULE_INFORMATION));
									j++;
								}
							}
							memcpy(SystemInformation, nPM, sizeof(RTL_PROCESS_MODULES) + pmsize);
							free(nPM);
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
				else if (SystemInformationClass == SystemProcessInformation) {
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PSYSTEM_PROCESS_INFORMATION curr = NULL;
						PSYSTEM_PROCESS_INFORMATION next = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
						do {
							curr = next;
							next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
							if (wcsncmp(next->ImageName.Buffer, L"VBoxTray.exe", next->ImageName.Length) == 0 ||
								wcsncmp(next->ImageName.Buffer, L"VBoxService.exe", next->ImageName.Length) == 0) {
								if (next->NextEntryOffset == 0)
									curr->NextEntryOffset = 0;
								else
									curr->NextEntryOffset += next->NextEntryOffset;
							}
						} while (curr->NextEntryOffset != 0);
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}
	ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	// 	SIMPLE_LOG(NTSTATUS, NtQuerySystemInformationEx, SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength)
	NTSTATUS ret;
	// Mutation types: (context dependent) MUT_ALT_NUM, MUT_FAIL, MUT_ALT_STR
	// BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)SystemInformationClass;
		RecordCall(Call::cNtQuerySystemInformationEx, CTX_NUM, &ctxVal, Hash, RetAddr);
	}
	ret = OgNtQuerySystemInformationEx(SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	//  SIMPLE_LOG(NTSTATUS, NtPowerInformation, InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED (return True)
	BOOL* flag = NULL;
	if (InformationLevel == SystemPowerCapabilities) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			RecordCall(Call::cNtPowerInformation, CTX_NONE, NULL, Hash, RetAddr);
			// no findmutation since no context to match
			if (mutNtPowerInformation != NULL) {
				// there is a mutation
				if (mutNtPowerInformation->mutType == MUT_SUCCEED) {
					ret = OgNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
					if (NT_SUCCESS(ret)) {
						SYSTEM_POWER_CAPABILITIES* powerCaps = (SYSTEM_POWER_CAPABILITIES*)OutputBuffer;
						if (powerCaps != NULL) {
							powerCaps->SystemS1 = TRUE;
							powerCaps->SystemS2 = TRUE;
							powerCaps->SystemS3 = TRUE;
							powerCaps->SystemS4 = TRUE;
							powerCaps->ThermalControl = TRUE;
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

ULONG WINAPI HookGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
	ULONG ret;
	// Mutation types: MUT_ALT_STR
	// Stock MAC: 10 4 5a 
	BOOL* flag = NULL;
	ret = OgGetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);

	if (ret == ERROR_SUCCESS) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();

			RecordCall(Call::cGetAdaptersAddresses, CTX_NONE, NULL, Hash, RetAddr);

			if (mutGetAdaptersAddresses != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
				printf("Applying GetAdaptersAddresses mutation!\n");
#endif
				if (mutGetAdaptersAddresses->mutType == MUT_ALT_STR) {
					IP_ADAPTER_ADDRESSES* ptr = AdapterAddresses;
					while (ptr != NULL) {
#ifdef __DEBUG_PRINT
						printf("Adapter: %ws\n", ptr->Description);
#endif
						// ptr->Description (name) can be revealing for some VMs (VMWare)
						if (ptr->PhysicalAddressLength == 0x6) {
							// if the paddr == virtualbox
							if (memcmp(VBOX_MAC, ptr->PhysicalAddress, 3) == 0) {
								for (int i = 0; i < 3; i++) {
									ptr->PhysicalAddress[i] = (BYTE)mutGetAdaptersAddresses->mutValue.szValue[i];
								}
							}
						}
						ptr = ptr->Next;
					}
				}
			}
		}
	}
	if (flag) (*flag) = FALSE;
	return ret;
}

ULONG WINAPI HookGetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
	ULONG ret;
	// Mutation types: MUT_ALT_STR
	BOOL* flag = NULL;
	ret = OgGetAdaptersInfo(AdapterInfo, SizePointer);

	if (ret == ERROR_SUCCESS) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			RecordCall(Call::cGetAdaptersInfo, CTX_NONE, NULL, Hash, RetAddr);
			if (mutGetAdaptersInfo != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying GetAdapterInfo mutation.\n");
#endif
				if (mutGetAdaptersInfo->mutType == MUT_ALT_STR) {
					IP_ADAPTER_INFO* ptr = AdapterInfo;
					while (ptr != NULL) {
						if (ptr->AddressLength == 6) {
							// if the paddr == virtualbox
							if (memcmp(VBOX_MAC, ptr->Address, 3) == 0) {
								for (int i = 0; i < 3; i++) {
									ptr->Address[i] = (BYTE)mutGetAdaptersInfo->mutValue.szValue[i];
								}
							}
						}
						ptr = ptr->Next;
					}
				}
			}
		}
	}

	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookSetupDiGetDeviceRegistryPropertyW(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_ALT_STR
	// buf contains VBOX
	BOOL* flag = NULL;
	if (Property == SPDRP_HARDWAREID) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ret = OgSetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
			if (ret) {
				if (wcsstr((wchar_t*)PropertyBuffer, L"VBOX") != NULL) { // VBOX
					RecordCall(Call::cSetupDiGetDeviceRegistryPropertyW, CTX_NONE, NULL, Hash, RetAddr);
					if (mutSetupDiGetDeviceRegistryPropertyW != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying SetupDiGetDeviceRegistryPropertyW mutation!\n");
#endif
						if (mutSetupDiGetDeviceRegistryPropertyW->mutType == MUT_FAIL) {
							memset(PropertyBuffer, 0, PropertyBufferSize);
							SetLastError(ERROR_INVALID_DATA);
							if (flag) (*flag) = FALSE;
							return FALSE;
						}
						else if (mutSetupDiGetDeviceRegistryPropertyW->mutType == MUT_ALT_STR) {
							size_t mutLen = wcslen(mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue);
							size_t wavail = PropertyBufferSize / sizeof(wchar_t);
							if (mutLen < wavail) {
								memcpy(PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue, (mutLen + 1) * sizeof(wchar_t));
							}
							else {
								memcpy(PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue, (wavail - 1) * sizeof(wchar_t));
								((wchar_t*)PropertyBuffer)[wavail - 1] = L'\0';
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}
	ret = OgSetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
	// flag cannot be set here
	return ret;
}

BOOL WINAPI HookSetupDiGetDeviceRegistryPropertyA(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_ALT_STR
	// buf contains VBOX
	//printf("hook HookSetupDiGetDeviceRegistryPropertyA\n");
	BOOL* flag = NULL;
	if (Property == SPDRP_HARDWAREID) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			ret = OgSetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
			if (ret) {
				if (strstr((char*)PropertyBuffer, "VBOX") != NULL) { // VBOX
					RecordCall(Call::cSetupDiGetDeviceRegistryPropertyA, CTX_NONE, NULL, Hash, RetAddr);
					if (mutSetupDiGetDeviceRegistryPropertyA != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying SetupDiGetDeviceRegistryPropertyA mutation!\n");
#endif
						if (mutSetupDiGetDeviceRegistryPropertyA->mutType == MUT_FAIL) {
							memset(PropertyBuffer, 0, PropertyBufferSize);
							SetLastError(ERROR_INVALID_DATA);
							if (flag) (*flag) = FALSE;
							return FALSE;
						}
						else if (mutSetupDiGetDeviceRegistryPropertyA->mutType == MUT_ALT_STR) {
							size_t wrlen = wcstombs((char*)PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyA->mutValue.szValue, PropertyBufferSize);
							if (wrlen != (size_t)-1) {
								PropertyBuffer[wrlen] = '\0';
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}

	ret = OgSetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
	// flag cannot be set here
	return ret;
}

BOOL WINAPI HookEnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
{
	BOOL ret;
	// Mutation types: MUT_HIDE

	BOOL* flag = NULL;
	if (InfoLevel == SC_ENUM_PROCESS_INFO && dwServiceType == SERVICE_DRIVER) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			RecordCall(Call::cEnumServicesStatusExA, CTX_NONE, NULL, Hash, RetAddr);

			if (mutEnumServicesStatusExA != NULL) {
				if (mutEnumServicesStatusExA->mutType == MUT_HIDE) {
					// requires mutation string source
					ret = OgEnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
					if (ret) {
						ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)lpServices;
						if (services != NULL && lpServicesReturned != NULL) {
							for (DWORD i = 0; i < *lpServicesReturned; i++) {
								if (strstr(services[i].lpServiceName, "VBox") || strstr(services[i].lpServiceName, "vbox")) {
									size_t mutLen = strlen((char*)mutEnumServicesStatusExA->mutValue.szValue);
									memcpy(services[i].lpServiceName, (char*)mutEnumServicesStatusExA->mutValue.szValue, (mutLen + 1) * sizeof(char));
								}
							}
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgEnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
	return ret;
}

BOOL WINAPI HookEnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
	BOOL ret;
	// Mutation types: MUT_HIDE
	BOOL* flag = NULL;
	if (InfoLevel == SC_ENUM_PROCESS_INFO && dwServiceType == SERVICE_DRIVER) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			RecordCall(Call::cEnumServicesStatusExW, CTX_NONE, NULL, Hash, RetAddr);

			if (mutEnumServicesStatusExW != NULL) {
				if (mutEnumServicesStatusExW->mutType == MUT_HIDE) {
					// requires mutation string source
					ret = OgEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
					if (ret) {
						ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)lpServices;
						if (services != NULL && lpServicesReturned != NULL) {
							for (DWORD i = 0; i < *lpServicesReturned; i++) {
								if (wcsstr(services[i].lpServiceName, L"VBox") || wcsstr(services[i].lpServiceName, L"vbox")) {
									size_t mutLen = wcslen(mutEnumServicesStatusExW->mutValue.szValue);
									memcpy(services[i].lpServiceName, mutEnumServicesStatusExW->mutValue.szValue, (mutLen + 1) * sizeof(wchar_t));
								}
							}
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}
	ret = OgEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
	if (flag) (*flag) = FALSE;
	return ret;
}

// Time
void WINAPI HookGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
	// todo: possibly mutate the time
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cGetSystemTime, CTX_NONE, NULL, Hash, RetAddr);
	}
	OgGetSystemTime(lpSystemTime);
	if (flag) (*flag) = FALSE;
}

void WINAPI HookGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	// todo: possibly mutate the time 
	BOOL* flag = NULL;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		flag = EnterHook();
		RecordCall(Call::cGetLocalTime, CTX_NONE, NULL, Hash, RetAddr);
	}
	OgGetLocalTime(lpSystemTime);
	if (flag) (*flag) = FALSE;
}

DWORD WINAPI HookGetTickCount()
{
	DWORD ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cGetTickCount, CTX_NONE, NULL, Hash, RetAddr);
	}
	// adjust for sleep skipping
	ret = OgGetTickCount() + TimeShift;
	return ret;
}

NTSTATUS NTAPI HookNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
{
	NTSTATUS ret;
	// DelayInterval: Delay in 100-ns units.
	// Negative value means delay relative to current
	// :10000 = milliseconds
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		if (DelayInterval->QuadPart < 0) {
			ContextValue ctxVal;
			ctxVal.dwCtx = (DWORD)(DelayInterval->QuadPart / -10000);
			RecordCall(Call::cNtDelayExecution, CTX_NUM, &ctxVal, Hash, RetAddr);
		}
		else {
			RecordCall(Call::cNtDelayExecution, CTX_NONE, NULL, Hash, RetAddr);
		}
	}
	if (DelayInterval->QuadPart < 0) {
		// atomic addition: flip sign & convert to ms
		_InterlockedExchangeAdd(&TimeShift, (ULONG)(DelayInterval->QuadPart / -10000));
		//TimeShift += (DWORD)(DelayInterval->QuadPart / -10000); 
#ifdef __DEBUG_PRINT
		printf("New TimeShift: %lu\n", TimeShift);
#endif
		// For TickCount: Add TimeShift
		// For QueryPerformance: Add TimeShift * FREQ
	}
	DelayInterval->QuadPart = -1000; // 0.1 ms
	ret = OgNtDelayExecution(Alertable, DelayInterval);
	return ret;
}

BOOL WINAPI HookQueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	BOOL ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cQueryPerformanceCounter, CTX_NONE, NULL, Hash, RetAddr);
	}
	// NOTE: malware can detect this behavior by executing rdtsc instruction
	ret = OgQueryPerformanceCounter(lpPerformanceCount);
	if (ret) {
		// adjust for sleep skipping
		lpPerformanceCount->QuadPart += (LONGLONG)(TimeShift * dFreq);
	}
#ifdef __DEBUG_PRINT
	printf("QueryPerformanceCounter: %lld\n", lpPerformanceCount->QuadPart);
#endif
	return ret;
}

NTSTATUS NTAPI HookNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	// SIMPLE_LOG(NTSTATUS, NtQuerySystemTime, SystemTime)
	NTSTATUS ret;
	UINT64 Hash;
	UINT64 RetAddr = 0;
	if (!SkipActivity(&Hash, &RetAddr)) {
		RecordCall(Call::cNtQuerySystemTime, CTX_NONE, NULL, Hash, RetAddr);
	}
	ret = OgNtQuerySystemTime(SystemTime);
	return ret;
}

BOOL WINAPI HookGetLastInputInfo(PLASTINPUTINFO plii)
{
	BOOL ret;
	// Mutation types: MUT_SUCCEED (GetTickCount())
	BOOL* flag = NULL;
	if (plii != NULL) {
		UINT64 Hash;
		UINT64 RetAddr = 0;
		if (!SkipActivity(&Hash, &RetAddr)) {
			flag = EnterHook();
			RecordCall(Call::cGetLastInputInfo, CTX_NONE, NULL, Hash, RetAddr);
			if (mutGetLastInputInfo != NULL) {
				if (mutGetLastInputInfo->mutType == MUT_SUCCEED) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_SUCCEED mutation to GetLastInputInfo\n");
#endif
					ret = OgGetLastInputInfo(plii);
					if (ret) {
						//plii->dwTime = mutGetLastInputInfo->mutValue.nValue;
						plii->dwTime = GetTickCount();
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgGetLastInputInfo(plii);
	if (flag) (*flag) = FALSE;
	return ret;
}

