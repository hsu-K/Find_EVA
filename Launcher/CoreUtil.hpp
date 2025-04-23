#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "GlobalState.hpp"
#include "Launcher_MiscUtil.hpp"
#include "LogUtil.hpp"
#include "CalculateUtil.hpp"
#include "MutationController.hpp"
#include "RecordingController.hpp"

#define LAUNCH_TIME_LIMIT 2500 // 2.5 seconds
#define MUTATE_TIME_LIMIT 50000 // 50 seconds
#define GAIN_THRESHOLD 1

class CoreUtil
{
public:
	// 用於終止子進程
	static void NukeChildren(DWORD pid)
	{
		DWORD i;

		// 創建進程快照
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE)
			return;

		// 初始化進程快照結構，用於進程枚舉
		PROCESSENTRY32 pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &pe32))
			return;

		do {
			for (i = 0; i < GlobalState::GetInst()->get_pidptr() ; i++) {
				// 如果找到子進程的PID，則終止此子進程
				if (pe32.th32ProcessID == GlobalState::GetInst()->get_pids()[i]) {
#ifdef __DEBUG_PRINT
					printf("[MATCH]: Child Process Recorded PID: %u\n", pids[i]);
#endif
					// 用OpenProcess獲得子進程關閉的權限
					HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
					if (hProc != NULL) {
						// terminate
#ifdef __DEBUG_PRINT
						BOOL kill = TerminateProcess(hProc, 66);
						printf("Kill %u result: %d\n", pids[i], kill);
#else
						TerminateProcess(hProc, 0);
#endif
					}
#ifdef __DEBUG_PRINT
					else {
						printf("it appears we do not have sufficient access to terminate the process.\n");
					}
#endif
				}
			}

		} while (Process32Next(hProcessSnap, &pe32));
	}

	// 啟動目標進程並注入DLL
	static int LaunchTarget(char* target, bool* time_out = nullptr)
	{
		// 將SyncEvent設定為未設置，以便讓線程繼續運行
		// threads will loop
		// 獲取事件句柄
		HANDLE syncEventHandle = *(GlobalState::GetInst()->get_SyncEvent().get());

		// 重置事件
		if (!ResetEvent(syncEventHandle)) {
			fprintf(stderr, "無法重置事件: %d\n", GetLastError());
			return -1;
		}

		STARTUPINFOA si;		// 進程啟動訊息結構
		PROCESS_INFORMATION pi;	// 進程訊息結構
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		// start process in suspended mode
		// 以暫停模式啟動目標進程
		if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		{
			fprintf(stderr, "Could not create target process\n");
			return -1;
		}

		
		// problem
		// DLL注入，注意DLL的路徑(存在TARGET_DLL)
		// allocate memory for dll name(分配記憶體給dll路徑)
		size_t lendll = sizeof(TARGET_DLL); //strlen(TARGET_DLL);
		LPVOID dllname = VirtualAllocEx(pi.hProcess, NULL, lendll + 1, MEM_COMMIT, PAGE_READWRITE);
		if (dllname == NULL)
		{
			fprintf(stderr, "Could not allocate memory in target for dll name\n");
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		
		// write dll name in target memory(寫入dll路徑到記憶體)
		if (!WriteProcessMemory(pi.hProcess, dllname, TARGET_DLL, lendll, NULL))
		{
			fprintf(stderr, "Could not write to target process memory for dll name\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// 獲取LoadLibraryA的函數地址，從kernel32.dll取得
		// get the kernel32 DLL module
		HMODULE k32 = GetModuleHandleA("kernel32.dll");
		if (k32 == NULL)
		{
			fprintf(stderr, "Could not obtain kernel32.dll handle\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// obtain pointer to LoadLibraryA()
		LPVOID pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");
		if (pLoadLibraryA == NULL)
		{
			fprintf(stderr, "Could not get address of LoadLibraryA\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}


		// call LoadLibraryA() in the target process
		// 在目標進程創建一個新的線程，並在該線程中調用LoadLibraryA()來加載dll
		HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllname, NULL, NULL);
		if (hThread == NULL)
		{
			fprintf(stderr, "Could not create thread in target process\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}

		// wait for the new loader thread to finish
		// 等待新的加載線程結束
		DWORD wait = WaitForSingleObject(hThread, INFINITE); // INFINITE?
		if (wait == WAIT_FAILED)
		{
			fprintf(stderr, "Could not wait for loader thread\n");
			VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return -1;
		}
		

		// resume the original suspended target process (primary thread)
		// 恢復目標進程的主線程執行
		DWORD resume = ResumeThread(pi.hThread);
		if (resume == (DWORD)-1)
		{
			fprintf(stderr, "Could not resume execution of target process\n");
			return -1;
		}

		VirtualFreeEx(pi.hProcess, dllname, 0, MEM_RELEASE);

		// wait for target process to finish(等待目標進程結束)
		//WaitForSingleObject(pi.hProcess, LAUNCH_TIME_LIMIT);
		//DWORD wait = WaitForSingleObject(pi.hProcess, INFINITE);

		// 監控CPU使用率來判斷程式是否被卡住
		FILETIME prevSysTime = { 0 }, prevProcKernelTime = { 0 }, prevProcUserTime = { 0 };
		int suspend_time = 0;
		while (WaitForSingleObject(pi.hProcess, 1000) == WAIT_TIMEOUT) { // 每秒檢查一次
			double cpuUsage = Launcher_MiscUtil::CalculateCPUUsage(pi.hProcess, prevSysTime, prevProcKernelTime, prevProcUserTime);
			if (cpuUsage == 0) {
				printf("[Enviral Launcher] Target is Blocking, CUP Usage is 0\n");
				suspend_time++;
				if (suspend_time * 1000 >= LAUNCH_TIME_LIMIT) {
					printf("[Enviral Launcher] Target Suspen Out Of Time, LAUNCH_TIME_LIMIT: %d\n", LAUNCH_TIME_LIMIT);
					if (time_out) {
						*time_out = true; // 更新 time_out 的值
					}
					break;
				}
			}
			else if (cpuUsage > 0) {
				suspend_time = 0;
#ifdef __DEBUG_PRINT
				std::cout << "CPU Usage: " << cpuUsage << "%" << std::endl;
#endif
			}
			else {
				std::cerr << "Failed to calculate CPU usage." << std::endl;
			}
		}



		printf("[Enviral Launcher] Tager End...\n");
		// cease responder threads
		// 設置線程同步資料
		SetEvent(syncEventHandle);

		// 獲取線程池大小
		size_t threadCount = GlobalState::GetInst()->getThreadPoolSize();

		// 先取消所有線程的同步 I/O 操作
		for (int i = static_cast<int>(threadCount) - 1; i >= 0; i--) {
			try {
				// 取消同步 I/O 操作
				if (!GlobalState::GetInst()->cancelThreadIO(i)) {
					std::cerr << "無法取消線程的同步 I/O 操作: " << i << std::endl;
				}
			}
			catch (const std::exception& e) {
				std::cerr << "取消同步 I/O 時發生錯誤: " << e.what() << std::endl;
			}
		}

		// 移除所有線程
		for (int i = static_cast<int>(threadCount) - 1; i >= 0; i--) {
			try {
				if (!GlobalState::GetInst()->removeThread(i)) {
					std::cerr << "無法從線程池移除線程: " << i << std::endl;
				}
			}
			catch (const std::exception& e) {
				std::cerr << "關閉線程時發生錯誤: " << e.what() << std::endl;
			}
		}

		// 確認所有線程已經被移除
		if (GlobalState::GetInst()->getThreadPoolSize() > 0) {
			std::cerr << "警告: 仍有 " << GlobalState::GetInst()->getThreadPoolSize() << " 個線程未被關閉" << std::endl;
		}

		// The SyncEvent will cancel the pipe communication, however the target process may still be running.
		TerminateProcess(pi.hProcess, 0);

		// 關閉所以的子進程
		NukeChildren(pi.dwProcessId);

		if (time_out && *time_out != true) {
			*time_out = false; // 如果未超時，設置為 false
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}

	static int RunExploration(char* path, Execution* baseExec, ULONG* cycle, ULONG* volapplied) {
		BOOL getMut = FALSE;
		LONG recindex = 0;
		RecordList* vol = nullptr;
		LONG gain = 0;
		std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
		// 設置時間限制
		DWORD CurTime = timeGetTime(); // milliseconds
		DWORD EndTime = CurTime + MUTATE_TIME_LIMIT; // s * 1000 (30)
		int exit = 0;

		
		// to store newExec
		//std::vector<std::shared_ptr<Execution>> executions;
		std::vector<std::shared_ptr<Execution>>& executions = GlobalState::GetInst()->get_executions();
		std::shared_ptr<Execution> newExec = nullptr;
		while (CurTime < EndTime) {
			getMut = FALSE;
			printf("PH3: Cycle %d\n", *cycle);
			//紀錄每次的執行，方便進行回溯
			// 如果當前的執行是第一次執行，則將第一次執行設置為當前執行，並且初始化時base->next 不會被設置
			if (frameCurr->currExec == baseExec) {
				newExec = std::make_shared<Execution>(baseExec, nullptr, TRUE);
				frameCurr->firstExec = newExec.get();
			}
			else {
				newExec = std::make_shared<Execution>(frameCurr->currExec, nullptr, FALSE);
			}
			//GlobalState::GetInst()->push_executions(newExec);
			//std::cout << newExec.get() << std::endl;
			executions.push_back(newExec);
			frameCurr->currExec = newExec.get();
			
			printf("[Enviral Launcher] Launching target.\n");

			// Run next execution
			bool time_out = false;
			LaunchTarget(path, &time_out);

			// Generate the equalized call counts
			CalculateUtil::GenerateUniqueCallcounts(frameCurr->currExec);

			// 輸出所有Recording 
			LogUtil::PrintRecordList(frameCurr->currExec, 0);


			// 判斷是否有超時，優先級最高
			if (time_out) {
				printf("Target process time out, try generate BlockingMutation\n");
				if (MutationController::GenerateBlockingMutation(frameCurr->currExec)) {
					printf("Generate BlockingMutation success!\n");
					// 成功找到變異
					getMut = TRUE;
					// 重製recindex
					recindex = 0;
				}
			}

			if (!getMut && vol) {
				if (MutationController::GenerateResponsiveMutationsAll(frameCurr->currExec)) {

					// 如果這個Volatile突變可以觸發新的Mutation，則表示是有效的，需要保留
					// 並且跳過下一個循環的突變生成，因為已經完成了
					getMut = TRUE;
					recindex = 0;
					vol = nullptr;
					(*volapplied)++;
#ifdef __DEBUG_PRINT
					printf("[new!!] Volatile mutation resulted in stable gain. Keep.\n");
#endif
				}
				else {
					// 若沒有產生新的Responsive Muatation，則計算其活動增益
					gain = CalculateUtil::CalculateActivityGain(frameCurr->currExec); // IsActivityGainExtended
					// 如果大於閥值就保留，否則丟棄
					if (gain >= GAIN_THRESHOLD) {
						recindex = 0;
						vol = NULL;
						(*volapplied)++;
#ifdef __DEBUG_PRINT
						printf("Gainful volatile mutation. Keep.\n");
#endif
					}
					else {
#ifdef __DEBUG_PRINT
						printf("Gainless volatile mutation. Discard/Reset.\n");
#endif
						// 回溯到上一個Exec，如果先現在就是firstExec就回復baseExec
						if (frameCurr->currExec == frameCurr->firstExec) {
							// the first exec has no prev.
							//GlobalState::GetInst()->pop_executions();
							executions.pop_back();
							frameCurr->currExec = baseExec;
							frameCurr->firstExec = nullptr;
						}
						else {
							// reset currExec back to prev
							//GlobalState::GetInst()->pop_executions();
							executions.pop_back();
							//frameCurr->currExec = GlobalState::GetInst()->get_executions().back().get();
							frameCurr->currExec = executions.back().get();
							frameCurr->currExec->next = nullptr;
						}

						// reset mutation list 重製突變列表
						if (frameCurr->currExec->mutStore == nullptr) {
							// no previous mutations, empty mutation list.
							// 沒有上一個突變，清空突變列表
#ifdef __DEBUG_PRINT
							printf("No previous mutations. Destroy mutation list.\n");
#endif
							MutationController::DestroyMutationList();
							frameCurr->mutHead = nullptr;
							frameCurr->mutCurr = nullptr;
							frameCurr->dwMutationCount = 0;
						}
						else {
							// reset the mutations to what is stored in currExec
#ifdef __DEBUG_PRINT
							printf("Reset mutations to past mutStore.\n");
#endif
							// 將Frame儲存的Mutation回到上一個Exec的Mutation的狀態
							frameCurr->mutCurr = frameCurr->currExec->mutStore;

							// remove unwanted mutations
							Mutation* del = frameCurr->mutCurr->next;
							Mutation* tmp = nullptr;
							while (del != nullptr) {
								tmp = del->next;
								delete del;
								del = tmp;
								frameCurr->dwMutationCount--;
							}

							// reset the end of the mutations
							frameCurr->mutCurr->next = nullptr;
						}

						// 當變異失效後，尋找下一個可用的變異點(往回找之前呼叫過的函數，因為是反向指針)
						BOOL NoCallsLeftToMutate = FALSE;
						RecordList* nextStart = vol->next;
						if (nextStart != nullptr) {
							// 檢查是否為相同呼叫，避免對相同類型的呼叫重複變異
							while (RecordingController::IsRecordingIdentical(&vol->rec, &nextStart->rec)) {
#ifdef __DEBUG_PRINT
								printf("Finding Next Entry Point: %s is identical (skip!)\n", DebugCallNames[nextStart->rec.call]);
#endif
								// 發現這個Recording是相同的就再繼續往回找，直到找到不同的或是找不到(遇到NULL)
								nextStart = nextStart->next;
								if (nextStart == nullptr) {
#ifdef __DEBUG_PRINT
									printf("The next entry point is NULL so that aint great\n");
#endif
									NoCallsLeftToMutate = TRUE;
									break;
								}
							}
						}
						else {
							// nextStart is NULL, no next call in this process
							NoCallsLeftToMutate = TRUE;
						}


						// if no calls can be found, we increase the RecIndex, as long as it is in bounds for RecIndex.
						// 如果沒有找到可變異的呼叫，就去尋找下一個進程(在RecIndex的範圍內允許)
						if (NoCallsLeftToMutate) {
#ifdef __DEBUG_PRINT
							printf("There are no calls left to mutate in the current RecIndex.\n");
#endif
							if (recindex + 1 > frameCurr->currExec->RecIndex) {
								// nothing left to mutate
#ifdef __DEBUG_PRINT
								printf("There are no other process recordings left to mutate. Exit loop.\n");
#endif
								exit = 2;
								// 如果找不到就離開整個檢測
								break;
							}
							recindex++;
						}

						// starting point for next search (can be NULL)
						vol = nextStart;

					}
				}
			}

			if (!getMut) {
				if (MutationController::GenerateResponsiveMutationsAll(frameCurr->currExec)) {
#ifdef __DEBUG_PRINT
					printf("There are stable mutations to apply.\n");
#endif
					getMut = TRUE;
					recindex = 0;
				}
				else {
#ifdef __DEBUG_PRINT
					printf("No (new) stable mutations, try volatile.\n");
#endif
					// 嘗試生成新的Volatile突變，如果有生成就返回
					vol = MutationController::GenerateResponsiveVolatileMutation(frameCurr->currExec, vol, &recindex);
					if (vol == nullptr) {
						// no volatile mutations to create - exit
#ifdef __DEBUG_PRINT
						printf("No volatile mutations to create. Exit loop.\n");
#endif
						exit = 1;
						break;
					}
					else {
#ifdef __DEBUG_PRINT
						printf("生成Volatile mutation: %s\n", DebugCallNames[vol->rec.call]);
#endif
					}
				}
			}

			(*cycle)++;
			CurTime = timeGetTime();

		}
		return 1;
	}
};

