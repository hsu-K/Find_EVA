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

// �NMutation�K�[��U��Mutation�Ҧ�_�Ӫ�List
int AddMutationToCallList(Mutation* src, Mutation** call);

// �x�sMutation�A�P�@��Call��Mutation�|�Τ@�ӫ��w��C�@�s��
void StoreMutation(Mutation* gen);
