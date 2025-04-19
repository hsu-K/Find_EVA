#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "GlobalState.hpp"
#include "Launcher_MiscUtil.hpp"

#define LAUNCH_TIME_LIMIT 2500 // 2.5 seconds

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
				printf("程式被卡住了，CUP 使用率為0\n");
				suspend_time++;
				if (suspend_time * 1000 >= LAUNCH_TIME_LIMIT) {
					printf("目標進程超時，超過預設時間: %d\n", LAUNCH_TIME_LIMIT);
					if (time_out) {
						*time_out = true; // 更新 time_out 的值
					}
					break;
				}
			}
			else if (cpuUsage > 0) {
				suspend_time = 0;
				std::cout << "CPU Usage: " << cpuUsage << "%" << std::endl;
			}
			else {
				std::cerr << "Failed to calculate CPU usage." << std::endl;
			}
		}



		printf("目標進程結束\n");
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
};

