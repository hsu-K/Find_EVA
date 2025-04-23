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
		// 獲取當前變異
		return GlobalState::GetInst()->get_frameCurr()->mutCurr;
	}

	// 新增要變異的內容到Frame的List中
	static int AddMutationToList(Recording* rec, MutationType* mutType, MutationValue* mutVal)
	{
		std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
		// first element
		// 如果mutHead是空的，則創建一個新的Mutation
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

		// 將傳入的rec、mutType、mutVal設置到frameCurr的mutCurr中
		frameCurr->mutCurr->mutType = *mutType;
		if (mutVal != nullptr) {
			frameCurr->mutCurr->mutValue = *mutVal;
		}
		frameCurr->mutCurr->rec = *rec;
		frameCurr->mutCurr->next = nullptr;

		// 增加突變計數
		frameCurr->dwMutationCount++;

		return 1;
	}

	// 清空所有Mutation的記憶體
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

	// 檢查Mutation是否已經存在
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
		// 檢查是否屬於要跳過的Mutation
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
		// 遍歷Exec的所有呼叫紀錄
		for (i = 0; i <= exec->RecIndex; i++) {
			entry = exec->recordings[i].recHead;
			while (entry != nullptr) {
				// 跳過 non-evasive calls
				if (entry->rec.call <= CALL_BLOCK) {
					entry = entry->next;
					continue;
				}

				switch (entry->rec.call) {
				case Call::cMessageBoxW:
					// 檢查這個rec是否已經有變異，如果有就跳過，沒有就新增進List裡
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

		// 設置exec的最後一次執行的變異(mutStore)為Frame當前的變異(mutCurr)
		exec->mutStore = GetCurrentMutation();

		// alternatively, we can compare mutCurr before and after
		BOOL NewMutation = FALSE;

		MutationType mutType;
		MutationValue mutVal;
		RecordList* entry;
		LONG i;
		// 遍歷Exec的所有呼叫紀錄
		for (i = 0; i <= exec->RecIndex; i++) {
			entry = exec->recordings[i].recHead;
			while (entry != NULL) {
				//printf("Recording %d: %d\n", i, entry->rec.call);
				// 跳過 non-evasive calls
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
						// 檢查這個rec是否已經有變異，如果有就跳過，沒有就新增進List裡
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

		// 取得Frame的當前Mutation作為exec的最後Mutation
		exec->mutStore = GetCurrentMutation();

		// 從上次的vol Recording開始，若為空則使用當前進程的recHead
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

				// Call的數值大於CALL_SEPARATOR，表示不需要變異
				if (entry->rec.call > CALL_SEPARATOR) {
					entry = entry->next;
					continue;
				}

				// all calls need to be checked for existing mutations
				// 判斷是否已經有存在的Mutation
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

