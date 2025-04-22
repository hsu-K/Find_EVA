#pragma once
#include "communication.h"
#include "Mutation.hpp"
#include <stdio.h>
#include <stdlib.h>

extern Mutation* mutNtQueryAttributesFile;
extern Mutation* mutNtCreateFile;
extern Mutation* mutNtDeviceIoControlFile;
extern Mutation* mutNtQueryVolumeInformationFile;
extern Mutation* mutNtQueryDirectoryFile;
extern Mutation* mutNtOpenKey;
extern Mutation* mutNtOpenKeyEx;
extern Mutation* mutNtQueryValueKey;
extern Mutation* mutNtCreateKey;
extern Mutation* mutNtEnumerateKey;
extern Mutation* mutNtEnumerateValueKey;
extern Mutation* mutNtQueryLicenseValue;
extern MutationNoCtx* mutCoCreateInstance;
extern MutationNoCtx* mutInternetCheckConnectionA;
extern MutationNoCtx* mutInternetCheckConnectionW;
extern Mutation* mutNtQueryInformationProcess;
extern MutationNoCtx* mutProcess32NextW;
extern MutationNoCtx* mutProcess32FirstW;
extern Mutation* mutLoadLibraryExW;
extern Mutation* mutLoadLibraryExA;
extern Mutation* mutLoadLibraryW;
extern Mutation* mutLoadLibraryA;
extern Mutation* mutNtCreateMutant;
extern Mutation* mutNtOpenMutant;
extern Mutation* mutNtQuerySystemInformation;
extern MutationNoCtx* mutNtPowerInformation;
extern MutationNoCtx* mutGetAdaptersAddresses;
extern MutationNoCtx* mutGetAdaptersInfo;
extern MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyW;
extern MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyA;
extern MutationNoCtx* mutEnumServicesStatusExA;
extern MutationNoCtx* mutEnumServicesStatusExW;
extern MutationNoCtx* mutGetLastInputInfo;
extern Mutation* mutFindWindowA;
extern Mutation* mutFindWindowW;
extern Mutation* mutFindWindowExA;
extern Mutation* mutFindWindowExW;
extern MutationNoCtx* mutGetForegroundWindow;
extern MutationNoCtx* mutGetCursorPos;
extern MutationNoCtx* mutGetAsyncKeyState;
extern Mutation* mutNtQuerySystemInformationEx;
extern Mutation* mutNtQueryDirectoryObject;
extern MutationNoCtx* mutGetWindowRect;
extern MutationNoCtx* mutGetMonitorInfoA;
extern MutationNoCtx* mutGetMonitorInfoW;


extern Mutation* mutMessageBoxW;
extern Mutation* mutMessageBoxA;
extern Mutation* mutMessageBoxExW;
extern Mutation* mutMessageBoxExA;

int AddMutationToCallListNoCtx(Mutation* src, MutationNoCtx** call);

// 將Mutation添加到各至Mutation所串起來的List
int AddMutationToCallList(Mutation* src, Mutation** call);

// 儲存Mutation，同一個Call的Mutation會用一個指針串列作連接
void StoreMutation(Mutation* gen);
