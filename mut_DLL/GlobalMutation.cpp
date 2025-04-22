#include "pch.h"
#include "GlobalMutation.hpp"

Mutation* mutNtOpenKey = NULL;
Mutation* mutNtOpenKeyEx = NULL;
Mutation* mutNtQueryValueKey = NULL;
Mutation* mutNtCreateKey = NULL;
Mutation* mutNtEnumerateKey = NULL;
Mutation* mutNtEnumerateValueKey = NULL;
Mutation* mutNtCreateFile = NULL;
Mutation* mutNtQueryAttributesFile = NULL;
Mutation* mutNtDeviceIoControlFile = NULL;
Mutation* mutNtQueryVolumeInformationFile = NULL;
Mutation* mutNtQuerySystemInformation = NULL;
Mutation* mutNtQuerySystemInformationEx = NULL;
MutationNoCtx* mutNtPowerInformation = NULL;
Mutation* mutNtQueryLicenseValue = NULL;
Mutation* mutNtQueryDirectoryFile = NULL;
Mutation* mutNtQueryInformationProcess = NULL;
Mutation* mutNtCreateMutant = NULL;
Mutation* mutNtOpenMutant = NULL;
MutationNoCtx* mutGetAdaptersAddresses = NULL;
MutationNoCtx* mutProcess32FirstW = NULL;
MutationNoCtx* mutProcess32NextW = NULL;
MutationNoCtx* mutCoCreateInstance = NULL;
//Mutation* mutGetModuleHandleW = NULL;
//Mutation* mutGetModuleHandleA = NULL;
//Mutation* mutGetModuleHandleExW = NULL;
//Mutation* mutGetModuleHandleExA = NULL;
MutationNoCtx* mutGetAdaptersInfo = NULL;
MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyW = NULL;
MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyA = NULL;
MutationNoCtx* mutGetLastInputInfo = NULL;
MutationNoCtx* mutEnumServicesStatusExA = NULL;
MutationNoCtx* mutEnumServicesStatusExW = NULL;
MutationNoCtx* mutInternetCheckConnectionA = NULL;
MutationNoCtx* mutInternetCheckConnectionW = NULL;
MutationNoCtx* mutGetWindowRect = NULL;
MutationNoCtx* mutGetMonitorInfoA = NULL;
MutationNoCtx* mutGetMonitorInfoW = NULL;
Mutation* mutFindWindowA = NULL;
Mutation* mutFindWindowW = NULL;
Mutation* mutFindWindowExA = NULL;
Mutation* mutFindWindowExW = NULL;
MutationNoCtx* mutGetCursorPos = NULL;
//Mutation* mutGetSystemMetrics = NULL;
//Mutation* mutSystemParametersInfoA = NULL;
//Mutation* mutSystemParametersInfoW = NULL;
MutationNoCtx* mutGetAsyncKeyState = NULL;
MutationNoCtx* mutGetForegroundWindow = NULL;
Mutation* mutLoadLibraryExW = NULL;
Mutation* mutLoadLibraryExA = NULL;
Mutation* mutLoadLibraryW = NULL;
Mutation* mutLoadLibraryA = NULL;
Mutation* mutNtQueryDirectoryObject = NULL;

Mutation* mutMessageBoxW = NULL;
Mutation* mutMessageBoxA = NULL;
Mutation* mutMessageBoxExW = NULL;
Mutation* mutMessageBoxExA = NULL;

int AddMutationToCallListNoCtx(Mutation* src, MutationNoCtx** call)
{
	// call should be NULL
	if (*call != NULL) {
		fprintf(stderr, "This should not happen: NoCtx Call exists before add.\n");
		return -1;
	}

	*call = (MutationNoCtx*)malloc(sizeof(MutationNoCtx));
	if (*call == NULL) {
		fprintf(stderr, "Could not allocate memory for mutation no ctx.\n");
		return -1;
	}

	(*call)->mutType = src->mutType;
	(*call)->mutValue = src->mutValue;

	return 1;
}

// 將Mutation添加到各至Mutation所串起來的List
int AddMutationToCallList(Mutation* src, Mutation** call)
{
	Mutation* ptr = NULL;
	// 如果mutation list是空的，就為其分配空間
	if (*call == NULL) { // empty call mutation list
		*call = (Mutation*)malloc(sizeof(Mutation));
		if (*call == NULL) {
			fprintf(stderr, "Could not allocate memory for mutation.\n");
			return -1;
		}
		ptr = *call;
	}
	else { // 否則就將其添加在mutation list的最末端
		ptr = *call;
		while (ptr->next != NULL) {
			ptr = ptr->next;
		}
		// ptr is now equal to the last valid element
		ptr->next = (Mutation*)malloc(sizeof(Mutation));
		if (ptr->next == NULL) {
			fprintf(stderr, "Could not allocate memory for mutation 2.\n");
			return -1;
		}
		ptr = ptr->next;
	}

	// here ptr points to a fresh element
	ptr->mutType = src->mutType;
	ptr->mutValue = src->mutValue;
	ptr->rec = src->rec; // ctx
	ptr->next = NULL;

	return 1;
}

// 儲存Mutation，同一個Call的Mutation會用一個指針串列作連接
void StoreMutation(Mutation* gen)
{
	// we pass the address of the list because it's a NULL ptr by default
	switch (gen->rec.call) {
	case Call::cNtOpenKey: AddMutationToCallList(gen, &mutNtOpenKey); break;
	case Call::cNtOpenKeyEx: AddMutationToCallList(gen, &mutNtOpenKeyEx); break;
	case Call::cNtQueryValueKey: AddMutationToCallList(gen, &mutNtQueryValueKey); break;
	case Call::cNtCreateKey: AddMutationToCallList(gen, &mutNtCreateKey); break;
	case Call::cNtEnumerateKey: AddMutationToCallList(gen, &mutNtEnumerateKey); break;
	case Call::cNtEnumerateValueKey: AddMutationToCallList(gen, &mutNtEnumerateValueKey); break;
	case Call::cNtCreateFile: AddMutationToCallList(gen, &mutNtCreateFile); break;
	case Call::cNtQueryAttributesFile: AddMutationToCallList(gen, &mutNtQueryAttributesFile); break;
	case Call::cNtDeviceIoControlFile: AddMutationToCallList(gen, &mutNtDeviceIoControlFile); break;
	case Call::cNtQueryVolumeInformationFile: AddMutationToCallList(gen, &mutNtQueryVolumeInformationFile); break;
	case Call::cNtQuerySystemInformation: AddMutationToCallList(gen, &mutNtQuerySystemInformation); break;
	case Call::cNtQuerySystemInformationEx: AddMutationToCallList(gen, &mutNtQuerySystemInformationEx); break;
	case Call::cNtPowerInformation: AddMutationToCallListNoCtx(gen, &mutNtPowerInformation); break;
	case Call::cNtQueryLicenseValue: AddMutationToCallList(gen, &mutNtQueryLicenseValue); break;
	case Call::cNtQueryDirectoryFile: AddMutationToCallList(gen, &mutNtQueryDirectoryFile); break;
	case Call::cNtQueryInformationProcess: AddMutationToCallList(gen, &mutNtQueryInformationProcess); break;
	case Call::cNtQueryDirectoryObject: AddMutationToCallList(gen, &mutNtQueryDirectoryObject); break;
	case Call::cNtCreateMutant: AddMutationToCallList(gen, &mutNtCreateMutant); break;
	case Call::cNtOpenMutant: AddMutationToCallList(gen, &mutNtOpenMutant); break;
	case Call::cGetAdaptersAddresses: AddMutationToCallListNoCtx(gen, &mutGetAdaptersAddresses); break;
	case Call::cProcess32FirstW: AddMutationToCallListNoCtx(gen, &mutProcess32FirstW); break;
	case Call::cProcess32NextW: AddMutationToCallListNoCtx(gen, &mutProcess32NextW); break;
	case Call::cCoCreateInstance: AddMutationToCallListNoCtx(gen, &mutCoCreateInstance); break;
		//case Call::cGetModuleHandleW: AddMutationToCallList(gen, &mutGetModuleHandleW); break;
		//case Call::cGetModuleHandleA: AddMutationToCallList(gen, &mutGetModuleHandleA); break;
		//case Call::cGetModuleHandleExW: AddMutationToCallList(gen, &mutGetModuleHandleExW); break;
		//case Call::cGetModuleHandleExA: AddMutationToCallList(gen, &mutGetModuleHandleExA); break;
	case Call::cGetAdaptersInfo: AddMutationToCallListNoCtx(gen, &mutGetAdaptersInfo); break;
	case Call::cSetupDiGetDeviceRegistryPropertyW: AddMutationToCallListNoCtx(gen, &mutSetupDiGetDeviceRegistryPropertyW); break;
	case Call::cSetupDiGetDeviceRegistryPropertyA: AddMutationToCallListNoCtx(gen, &mutSetupDiGetDeviceRegistryPropertyA); break;
	case Call::cGetLastInputInfo: AddMutationToCallListNoCtx(gen, &mutGetLastInputInfo); break;
	case Call::cEnumServicesStatusExA: AddMutationToCallListNoCtx(gen, &mutEnumServicesStatusExA); break;
	case Call::cEnumServicesStatusExW: AddMutationToCallListNoCtx(gen, &mutEnumServicesStatusExW); break;
	case Call::cInternetCheckConnectionA: AddMutationToCallListNoCtx(gen, &mutInternetCheckConnectionA); break;
	case Call::cInternetCheckConnectionW: AddMutationToCallListNoCtx(gen, &mutInternetCheckConnectionW); break;
	case Call::cGetWindowRect: AddMutationToCallListNoCtx(gen, &mutGetWindowRect); break;
	case Call::cGetMonitorInfoA: AddMutationToCallListNoCtx(gen, &mutGetMonitorInfoA); break;
	case Call::cGetMonitorInfoW: AddMutationToCallListNoCtx(gen, &mutGetMonitorInfoW); break;
	case Call::cFindWindowA: AddMutationToCallList(gen, &mutFindWindowA); break;
	case Call::cFindWindowW: AddMutationToCallList(gen, &mutFindWindowW); break;
	case Call::cFindWindowExA: AddMutationToCallList(gen, &mutFindWindowExA); break;
	case Call::cFindWindowExW: AddMutationToCallList(gen, &mutFindWindowExW); break;
	case Call::cGetCursorPos: AddMutationToCallListNoCtx(gen, &mutGetCursorPos); break;
		//case Call::cGetSystemMetrics: AddMutationToCallList(gen, &mutGetSystemMetrics); break;
		//case Call::cSystemParametersInfoA: AddMutationToCallList(gen, &mutSystemParametersInfoA); break;
		//case Call::cSystemParametersInfoW: AddMutationToCallList(gen, &mutSystemParametersInfoW); break;
	case Call::cGetAsyncKeyState: AddMutationToCallListNoCtx(gen, &mutGetAsyncKeyState); break;
	case Call::cGetForegroundWindow: AddMutationToCallListNoCtx(gen, &mutGetForegroundWindow); break;
	case Call::cLoadLibraryExW: AddMutationToCallList(gen, &mutLoadLibraryExW); break;
	case Call::cLoadLibraryExA: AddMutationToCallList(gen, &mutLoadLibraryExA); break;
	case Call::cLoadLibraryW: AddMutationToCallList(gen, &mutLoadLibraryW); break;
	case Call::cLoadLibraryA: AddMutationToCallList(gen, &mutLoadLibraryA); break;
	case Call::cMessageBoxW: AddMutationToCallList(gen, &mutMessageBoxW); break;
	case Call::cMessageBoxA: AddMutationToCallList(gen, &mutMessageBoxA); break;
	case Call::cMessageBoxExW: AddMutationToCallList(gen, &mutMessageBoxExW); break;
	case Call::cMessageBoxExA: AddMutationToCallList(gen, &mutMessageBoxExA); break;
	default: fprintf(stderr, "Unknown mutation target\n"); break;
	}
}
