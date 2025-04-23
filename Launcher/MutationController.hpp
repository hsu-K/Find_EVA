#pragma once
#include <iostream>
#include <windows.h>
#include "Execution.hpp"
#include "Mutation.hpp"
#include "GlobalState.hpp"
#include "communication.h"
#include <Shlwapi.h>

class MutationController
{
public:
	static Mutation* GetCurrentMutation() {
		// �����e�ܲ�
		return GlobalState::GetInst()->get_frameCurr()->mutCurr;
	}

	// �s�W�n�ܲ������e��Frame��List��
	static int AddMutationToList(Recording* rec, MutationType* mutType, MutationValue* mutVal)
	{
		std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
		// first element
		// �p�GmutHead�O�Ū��A�h�Ыؤ@�ӷs��Mutation
		Mutation* newMut = new Mutation();
		if (frameCurr->mutHead == nullptr) {
			frameCurr->mutHead = newMut;
			if (frameCurr->mutHead == NULL) return -1;
			frameCurr->mutCurr = frameCurr->mutHead;
		}
		// head exists, curr points to last element
		else {
			frameCurr->mutCurr->next = newMut;
			if (frameCurr->mutCurr->next == nullptr) return -1;
			frameCurr->mutCurr = frameCurr->mutCurr->next;
		}

		// �N�ǤJ��rec�BmutType�BmutVal�]�m��frameCurr��mutCurr��
		frameCurr->mutCurr->mutType = *mutType;
		if (mutVal != nullptr) {
			frameCurr->mutCurr->mutValue = *mutVal;
		}
		frameCurr->mutCurr->rec = *rec;
		frameCurr->mutCurr->next = nullptr;

		// �W�[���ܭp��
		frameCurr->dwMutationCount++;

		return 1;
	}

	// �M�ũҦ�Mutation���O����
	static void DestroyMutationList()
	{
		Mutation* loop = GlobalState::GetInst()->get_frameCurr()->mutHead;
		Mutation* temp = nullptr;
		while (loop != nullptr) {
			temp = loop->next;
			delete loop;
			loop = temp;
		}
	}

	// �ˬdMutation�O�_�w�g�s�b
	static BOOL MutationExists(Recording* rec)
	{
		//std::cout << "find " << DebugCallNames[rec->call] << ", origin from: " << rec->origin << std::endl;
		std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
		Mutation* loop = frameCurr->mutHead;

		while (loop != nullptr) {
			//std::cout << DebugCallNames[loop->rec.call] << ", origin from: " << loop->rec.origin << std::endl;
			if (loop->rec.call == rec->call) {
				if (rec->type == CTX_NUM) {
					if (loop->rec.value.dwCtx == rec->value.dwCtx) {
						if (loop->rec.origin == rec->origin) {
							// context match
							return TRUE;
						}
					}
				}
				else if (rec->type == CTX_STR) {
					if (wcsncmp(loop->rec.value.szCtx, rec->value.szCtx, MAX_CTX_LEN) == 0) {
						if (loop->rec.origin == rec->origin) {
							// context match
							return TRUE;
						}
					}
				}
				else if (rec->type == CTX_NONE) {
					if (loop->rec.origin == rec->origin) {
						// context match
						return TRUE;
					}
				}
			}
			loop = loop->next;
		}

		// frames backtracking: mutation(s) to skip
		// �ˬd�O�_�ݩ�n���L��Mutation
		loop = frameCurr->skip;
		while (loop != NULL) {
			if (loop->rec.call == rec->call) {
				if (rec->type == CTX_NUM) {
					if (loop->rec.value.dwCtx == rec->value.dwCtx) {
						if (loop->rec.origin == rec->origin) {
							// context match
							return TRUE;
						}
					}
				}
				else if (rec->type == CTX_STR) {
					if (wcsncmp(loop->rec.value.szCtx, rec->value.szCtx, MAX_CTX_LEN) == 0) {
						if (loop->rec.origin == rec->origin) {
							// context match
							return TRUE;
						}
					}
				}
				else if (rec->type == CTX_NONE) {
					if (loop->rec.origin == rec->origin) {
						// context match
						return TRUE;
					}
				}
			}
			loop = loop->next;
		}

		return FALSE;
	}

	static BOOL GenerateBlockingMutation(Execution* exec) {
		exec->mutStore = GetCurrentMutation();

		BOOL NewMutation = FALSE;

		MutationType mutType;
		MutationValue mutVal;
		RecordList* entry;
		LONG i;
		// �M��Exec���Ҧ��I�s����
		for (i = 0; i <= exec->RecIndex; i++) {
			entry = exec->recordings[i].recHead;
			while (entry != nullptr) {
				// ���L non-evasive calls
				if (entry->rec.call <= CALL_BLOCK) {
					entry = entry->next;
					continue;
				}

				switch (entry->rec.call) {
				case Call::cMessageBoxW:
					// �ˬd�o��rec�O�_�w�g���ܲ��A�p�G���N���L�A�S���N�s�W�iList��
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = IDOK; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return true;
				case Call::cMessageBoxA:
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = IDOK; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return true;
				case Call::cMessageBoxExW:
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = IDOK; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return true;
				case Call::cMessageBoxExA:
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = IDOK; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return true;
				}
			}
		}
	}

	static BOOL GenerateResponsiveMutationsAll(Execution* exec) {

		// �]�mexec���̫�@�����檺�ܲ�(mutStore)��Frame��e���ܲ�(mutCurr)
		exec->mutStore = GetCurrentMutation();

		// alternatively, we can compare mutCurr before and after
		BOOL NewMutation = FALSE;

		MutationType mutType;
		MutationValue mutVal;
		RecordList* entry;
		LONG i;
		// �M��Exec���Ҧ��I�s����
		for (i = 0; i <= exec->RecIndex; i++) {
			entry = exec->recordings[i].recHead;
			while (entry != NULL) {
				//printf("Recording %d: %d\n", i, entry->rec.call);
				// ���L non-evasive calls
				if (entry->rec.call > CALL_SEPARATOR) {
					entry = entry->next;
					continue;
				}

				switch (entry->rec.call) {
				case Call::cNtOpenKey:
				case Call::cNtOpenKeyEx:
				case Call::cLoadLibraryExW:
				case Call::cLoadLibraryExA:
				case Call::cLoadLibraryA:
				case Call::cLoadLibraryW:
					// MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
					if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual") || StrStrIW(entry->rec.value.szCtx, L"vmware")) {
						// evaluate the ctx first, because its cheaper and frequently evaluates to false 
						// �ˬd�o��rec�O�_�w�g���ܲ��A�p�G���N���L�A�S���N�s�W�iList��
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_FAIL;
						mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtQueryValueKey:
				case Call::cNtEnumerateKey:
				case Call::cNtEnumerateValueKey:
					// MUT_ALT_STR -> Ctx "VBox", "Virtual"
					if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual") || StrStrIW(entry->rec.value.szCtx, L"vmware")) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_ALT_STR;
						wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Bolt");
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtCreateKey:
					// MUT_ALT_NUM -> Ctx "VBox", "Virtual"	Num 1
					if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual") || StrStrIW(entry->rec.value.szCtx, L"vmware")) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_ALT_NUM;
						mutVal.nValue = 1; // Disposition == new key created
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtCreateFile:
				case Call::cNtQueryAttributesFile:
				case Call::cFindWindowA:
				case Call::cFindWindowW:
				case Call::cFindWindowExA:
				case Call::cFindWindowExW:
					// MUT_FAIL -> Ctx "VBox"	Ret STATUS_OBJECT_NAME_NOT_FOUND
					if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"vmware")) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_FAIL;
						mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtDeviceIoControlFile:
					// MUT_ALT_NUM -> Ctx	0x7405c (IOCTL_DISK_GET_LENGTH_INFO) Num 1024
					if (entry->rec.value.dwCtx == 0x7405c) { // IOCTL_DISK_GET_LENGTH_INFO
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_ALT_NUM;
						mutVal.nValue = 1024; // Disk size in GB
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtQueryVolumeInformationFile:
					// MUT_ALT_NUM -> Ctx	FileFsDeviceInformation	Num (multiplies current size -- match with ^)
					if (entry->rec.value.dwCtx == 3) { // FileFsDeviceInformation
						if (!MutationExists(&entry->rec)) {
							mutType = MUT_ALT_NUM;
							mutVal.nValue = 2; // Disk size multiplier
							AddMutationToList(&entry->rec, &mutType, &mutVal);
							NewMutation = TRUE;
						}
					}
					break;
				case Call::cNtQuerySystemInformation:
					// MUT_ALT_NUM -> Ctx SystemBasicInformation	Num 8 MUT_HIDE SystemModuleInformation (11) & SystemProcessInformation
					if (entry->rec.value.dwCtx == 0) { // SystemBasicInformation
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_ALT_NUM;
						mutVal.nValue = 8; // Number of logical processors 
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					else if (entry->rec.value.dwCtx == 11 || entry->rec.value.dwCtx == 5) { // SystemModuleInformation || SystemProcessInformation
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_HIDE;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtPowerInformation:
				case Call::cGetLastInputInfo:
				case Call::cInternetCheckConnectionA:
				case Call::cInternetCheckConnectionW:
				case Call::cGetAsyncKeyState:
					// MUT_SUCCEED -> NO Ctx NO Val
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_SUCCEED;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtQueryLicenseValue:
					// MUT_SUCCEED -> Ctx1 L"Security-SPP-GenuineLocalStatus" Num 1 Ctx2 L"Kernel-VMDetection-Private" Num 0
					if (wcscmp(entry->rec.value.szCtx, L"Security-SPP-GenuineLocalStatus") == 0) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_SUCCEED;
						mutVal.nValue = 1; // genuine
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					else if (wcscmp(entry->rec.value.szCtx, L"Kernel-VMDetection-Private") == 0) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_SUCCEED;
						mutVal.nValue = 0; // no VM
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtQueryDirectoryFile:
					// MUT_FAIL -> Ctx "VBox" Ret STATUS_NO_SUCH_FILE
					if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"vmware")) {
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_FAIL;
						mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cNtQueryInformationProcess:
					if (entry->rec.value.dwCtx == 0) { // ProcessBasicInformation
						if (MutationExists(&entry->rec)) break;
						mutType = MUT_HIDE;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;
				case Call::cProcess32FirstW:
				case Call::cProcess32NextW:
				case Call::cEnumServicesStatusExA:
				case Call::cEnumServicesStatusExW:
					// MUT_HIDE -> NO Ctx NO Val
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_HIDE;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;
				case Call::cGetAdaptersAddresses:
				case Call::cGetAdaptersInfo:
					// MUT_ALT_STR -> NO Ctx
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_ALT_STR;
						wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"\x10\x04\x5a"); // fake MAC
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;
				case Call::cSetupDiGetDeviceRegistryPropertyW:
				case Call::cSetupDiGetDeviceRegistryPropertyA:
					// MUT_ALT_STR -> NO Ctx
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_ALT_STR;
						wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"DEVICE\\BOLT"); // fake device
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
					break;

				case Call::cGetCursorPos:
					// MUT_RND_TUP -> NO Ctx
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_RND_TUP;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;

				case Call::cGetForegroundWindow:
					// MUT_RND_NUM -> NO Ctx
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_RND_NUM;
						AddMutationToList(&entry->rec, &mutType, NULL);
						NewMutation = TRUE;
					}
					break;
				}
				entry = entry->next;
			}
		}
		return NewMutation;
	}

	static RecordList* GenerateResponsiveVolatileMutation(Execution* exec, RecordList* start, LONG* index) {

		// ���oFrame����eMutation�@��exec���̫�Mutation
		exec->mutStore = GetCurrentMutation();

		// �q�W����vol Recording�}�l�A�Y���ūh�ϥη�e�i�{��recHead
		RecordList* entry;
		if (start != NULL) {
			// continue where we left off since the last mutation was gainless
			entry = start;
		}
		else {
			// start at the head, this is a fresh execution
			entry = exec->recordings[*index].recHead;
		}

		MutationType mutType;
		MutationValue mutVal;

		while (TRUE) {
			while (entry != NULL) {

				// Call���ƭȤj��CALL_SEPARATOR�A��ܤ��ݭn�ܲ�
				if (entry->rec.call > CALL_SEPARATOR) {
					entry = entry->next;
					continue;
				}

				// all calls need to be checked for existing mutations
				// �P�_�O�_�w�g���s�b��Mutation
				if (MutationExists(&entry->rec)) {
					entry = entry->next;
					continue;
				}

				/*
				check for expansion ctx:
				cSetupDiGetDeviceRegistryPropertyW/A	-> ctx: Property
				*/

				switch (entry->rec.call) {
				case Call::cNtOpenKey:
				case Call::cNtOpenKeyEx:
				case Call::cNtCreateFile:
				case Call::cNtQueryAttributesFile:
				case Call::cNtOpenMutant:
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQueryValueKey:
				case Call::cNtEnumerateKey:
				case Call::cNtEnumerateValueKey:
					mutType = MUT_ALT_STR;
					wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Blue");
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtCreateKey:
					mutType = MUT_ALT_NUM;
					mutVal.nValue = 1; // Disposition == new key created
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQuerySystemInformation:
				case Call::cCoCreateInstance:
					//case Call::cGetModuleHandleW:
					//case Call::cGetModuleHandleA:
					//case Call::cGetModuleHandleExW:
					//case Call::cGetModuleHandleExA:
				case Call::cFindWindowA:
				case Call::cFindWindowW:
				case Call::cFindWindowExA:
				case Call::cFindWindowExW:
					//case Call::cGetSystemMetrics:
					//case Call::cSystemParametersInfoA:
					//case Call::cSystemParametersInfoW:
						// generic fail
					mutType = MUT_FAIL;
					AddMutationToList(&entry->rec, &mutType, NULL);
					return entry;

				case Call::cNtDeviceIoControlFile:
					if (entry->rec.value.dwCtx != 0x7405c) {
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryVolumeInformationFile:
					if (entry->rec.value.dwCtx != 3) {
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryInformationProcess:
					if (entry->rec.value.dwCtx != 0 && entry->rec.value.dwCtx != 36) { // hide & windows dep.
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryLicenseValue:
					mutType = MUT_FAIL;
					mutVal.nValue = STATUS_INVALID_PARAMETER;
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQueryDirectoryFile:
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE;
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtCreateMutant:
					mutType = MUT_SUCCEED;
					AddMutationToList(&entry->rec, &mutType, NULL);
					return entry;
				}

				entry = entry->next;
			}

			// move to next process
			(*index)++;
			if (*index > exec->RecIndex) {
				break;
			}
			entry = exec->recordings[*index].recHead;
		}

		return NULL;
	}

};

