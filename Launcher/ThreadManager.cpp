#include "ThreadManager.hpp"
#include <windows.h>
#include "communication.h"
#include "PipeManager.hpp"

//#define __DEBUG_PRINT

void ThreadManager::startListenerThread()
{
	dwThreadId = 0;
	hListenerThread = CreateThread(NULL, 0, ListenerThread, NULL, 0, &dwThreadId);
	if (hListenerThread == NULL) {
		fprintf(stderr, "Could not create listener thread\n");
		return;
	}
	//_listenerThread = std::make_shared<std::thread>(&ThreadManager::ListenerThreadEntry, this);
}

void ThreadManager::stopListenerThread()
{
	CloseHandle(hListenerThread);
	//stopListener = true;	// 設定停止標誌為true
	//if (_listenerThread && _listenerThread->joinable()) {
	//	_listenerThread->join();	// 等待線程結束
	//}
	//else {
	//	std::cout << "Listener thread is not joinable or already stopped." << std::endl;
	//}
}

// 監聽線程
DWORD WINAPI ThreadManager::ListenerThreadEntry()
{
	printf("[Enviral Launcher] Listener thread is active.\n");
	HANDLE InstancePipe = nullptr;
	DWORD dwThreadId = 0;
	while (!stopListener) {

		// 創建一個新的命名管道實例，雙向通信模式(PIPE_ACCESS_DUPLEX)、消息類型管道(PIPE_TYPE_MESSAGE)
		// 建立 overlapped 非同步命名管道
		InstancePipe = CreateNamedPipeW(
			szPipeName,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			8192, 8192, 0, NULL
		);

		if (InstancePipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "Could not create named pipe\n");
			break;
		}

		OVERLAPPED ol = {};
		ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!ol.hEvent) {
			CloseHandle(InstancePipe);
			break;
		}

		BOOL connected = ConnectNamedPipe(InstancePipe, &ol);
		if (!connected) {
			DWORD err = GetLastError();
			if (err == ERROR_IO_PENDING) {
				DWORD waitResult = WaitForSingleObject(ol.hEvent, 1000);
				if (waitResult == WAIT_TIMEOUT) {
					CloseHandle(ol.hEvent);
					CloseHandle(InstancePipe);
					continue; // timeout -> 檢查 stopListener 再重來
				}
			}
			else if (err != ERROR_PIPE_CONNECTED) {
				std::cerr << "ConnectNamedPipe failed.\n";
				CloseHandle(ol.hEvent);
				CloseHandle(InstancePipe);
				break;
			}
			else {
				std::cout << err << std::endl;
				break;
			}
		}
#ifdef __DEBUG_PRINT
		printf("[LISTENER] New client connection obtained!\n");
#endif
		// 判斷是否超過最大可用的回應線程(20)

		if (GlobalState::GetInst()->getThreadPoolSize() >= MAX_CHILD) {
			printf("Exceeded max available responder threads!\n");
			continue;
		}

		// 創建響應線程
		try {
			printf("[LISTENER] Creating responder thread...\n");
			auto responderThread = std::make_shared<std::thread>(&ThreadManager::ResponderThreadEntry, this, InstancePipe);
			// 添加到 GlobalState 的線程池
			GlobalState::GetInst()->addThread(responderThread);

			// 記錄線程已創建的信息
#ifdef __DEBUG_PRINT
            std::cout << "Created responder thread and added to thread pool." << std::endl;
#endif 
		}
		catch (const std::exception& e) {
			fprintf(stderr, "Could not create responder thread: %s\n", e.what());
			return 0;
		}

		CloseHandle(ol.hEvent);

	}
	return 1;
}

DWORD WINAPI ThreadManager::ListenerThread(LPVOID lpvParam){
	printf("[Enviral Launcher] Listener thread is active.\n");
	HANDLE InstancePipe = NULL;
	BOOL conn = FALSE;
	DWORD dwThreadId = 0;

	HANDLE* hThreads = GlobalState::GetInst()->get_hThreads();
	DWORD& dwThreadCount = GlobalState::GetInst()->get_dwThreadCount();

	while (TRUE) {
		// 創建一個新的命名管道實例，雙向通信模式(PIPE_ACCESS_DUPLEX)、消息類型管道(PIPE_TYPE_MESSAGE)
		InstancePipe = CreateNamedPipeW(szPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
		if (InstancePipe == NULL || InstancePipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "Could not create named pipe\n");
			return 0;
		}

		// 等待客戶端連接(等待DLL連接)
		conn = ConnectNamedPipe(InstancePipe, NULL);
		if (!conn && GetLastError() != ERROR_PIPE_CONNECTED) {
			fprintf(stderr, "Could not connect named pipe\n");
			return 0;
		}
#ifdef __DEBUG_PRINT
		printf("[LISTENER] New client connection obtained!\n");
#endif
		// 判斷是否超過最大可用的回應線程(20)
		if (dwThreadCount >= MAX_CHILD) {
			printf("Exceeded max available responder threads!\n");
			continue;
		}

		// 創建響應線程，並存在hThreads陣列中，用dwThreadCount計數
		// 這個Responder
		hThreads[dwThreadCount] = CreateThread(NULL, 0, ResponderThread, (LPVOID)InstancePipe, 0, &dwThreadId);
		if (hThreads[dwThreadCount] == NULL) {
			fprintf(stderr, "Could not create responder thread\n");
			return 0;
		}
		dwThreadCount++;
	}

	return 1;
}


// 回應線程
DWORD WINAPI ThreadManager::ResponderThread(LPVOID lpvParam)
{
	HANDLE hPipe = (HANDLE)lpvParam;	// 接收一個命名管道(Named Pipe)的 handle 作為參數
	DWORD tid = GetCurrentThreadId();	// 取得當前執行緒的 ID

	// 安全地增加並獲取一個索引值
	LONG LocalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));
#ifdef __DEBUG_PRINT
	printf("This Responder Thread Gets Index: %ld\n", LocalRecIndex);
	printf("[RESPONDER %lu] Transfering mutations to new process.\n", tid);
#endif
	// 將frameCurr的每個突變資料傳送到管道，讓DLL可以接收
	PipeManager::TransferMutations(hPipe);
	//TransferMutations(hPipe);

	// 檢查SyncEvent是否已設置，如有，則繼續讀取管道的Mutation的Recording
	while (WaitForSingleObject(*(GlobalState::GetInst()->get_SyncEvent().get()), 0) != WAIT_OBJECT_0) {
		Recording rec;
		DWORD dwRead;

		// 讀取管道的Mutation的Recording(從DLL來的)
		BOOL rd = ReadFile(hPipe, (void*)&rec, sizeof(rec), &dwRead, NULL);
		if (rd) {

			// 將讀取到的Recording加入到frameCurr的currExec的本地記錄中
			std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
			PipeManager::AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);
			//AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

			// 檢查rec是否是CreateProcessInternalW這個Windows API
			if (rec.call == Call::cCreateProcessInternalW) {
#ifdef __DEBUG_PRINT
				printf("We found creation of PID: %u\n", rec.value.dwCtx);
#endif
				// 檢查是否超過上限(100)，並將其加入到pids陣列中
				if (GlobalState::GetInst()->get_pidptr() < MAX_PID) {
					GlobalState::GetInst()->set_pids(GlobalState::GetInst()->get_pidptr(), rec.value.dwCtx);
					GlobalState::GetInst()->set_pidptr(GlobalState::GetInst()->get_pidptr() + 1);
				}
				//if (pidptr < MAX_PIDS) {
				//	pids[pidptr] = rec.value.dwCtx;
				//	pidptr++;
				//}
			}

			//printf("[RESPONDER %lu] Recv recording: %s\n", tid, DebugCallNames[rec.call]);
		}
		else {
			// 如果讀取失敗，則檢查錯誤碼
			// ReadFile failed, if it is because ERROR_BROKEN_PIPE, then the client disconnected.
			DWORD err = GetLastError();

			// 客戶端斷開連接
			if (err == ERROR_BROKEN_PIPE) {
#ifdef __DEBUG_PRINT
				printf("[RESPONDER %lu] No more reading, the client disconnected.\n", tid);
#endif
			}
			// 客戶端取消操作
			else if (err == ERROR_OPERATION_ABORTED) {
#ifdef __DEBUG_PRINT
				printf("[RESPONDER %lu] Cancelling ghost orphan child.\n", tid);
#endif
			}
			else {
				printf("[RESPONDER %lu] Unexpected fatal ReadFile error: %ld\n", tid, err);
			}
			break;
		}
	}
#ifdef __DEBUG_PRINT
	printf("[RESPONDER %lu] Shutting down gracefully.\n", tid);
#endif	

	// 關閉管道
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}


DWORD WINAPI ThreadManager::ResponderThreadEntry(HANDLE hPipe){

	std::cout << "ResponderThreadEntry創建成功" << std::endl;
	DWORD tid = GetCurrentThreadId();

	// 安全地增加並獲取一個索引值
	LONG LocalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));

	// 將 frameCurr 的每個突變資料傳送到管道
	PipeManager::TransferMutations(hPipe);
	printf("[RESPONDER] Transfered mutations to pipe\n");

	// 檢查 SyncEvent 是否已設置
	while (WaitForSingleObject(*(GlobalState::GetInst()->get_SyncEvent().get()), 0) != WAIT_OBJECT_0) {
		if (shouldTerminate) {
			break;
		}

		// 初始化 OVERLAPPED 結構
		OVERLAPPED ol = {};
		ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!ol.hEvent) {
			std::cerr << "[RESPONDER] Cannot create EventHandle" << GetLastError() << std::endl;
			break;
		}

		Recording rec;
		DWORD dwRead = 0;

		// 非同步讀取數據
		BOOL readSuccess = ReadFile(hPipe, &rec, sizeof(rec), NULL, &ol);

		// 檢查讀取操作是否立即完成
		if (readSuccess) {
			// 讀取立即完成，無需等待
			if (!GetOverlappedResult(hPipe, &ol, &dwRead, FALSE)) {
				std::cerr << "[RESPONDER] GetOverlappedResult Fail: " << GetLastError() << std::endl;
				CloseHandle(ol.hEvent);
				break;
			}
		}
		else {
			// 檢查是否為非同步操作仍在進行中
			DWORD lastError = GetLastError();
			if (lastError != ERROR_IO_PENDING) {
				if (lastError == ERROR_BROKEN_PIPE) {
#ifdef __DEBUG_PRINT
					std::cout << "[RESPONDER] Pipe already closed" << std::endl;
#endif
				}
				else if (lastError == ERROR_NO_DATA) {
#ifdef __DEBUG_PRINT
					std::cout << "[RESPONDER] No data in pipe, wait for 5 sec" << std::endl;
#endif
					CloseHandle(ol.hEvent);
					Sleep(5);
					continue;
				}
				else {
					std::cerr << "[RESPONDER] ReadFile Error: " << lastError << std::endl;
					CloseHandle(ol.hEvent);
					break;
				}
			}

			// 等待最多 100ms，看看事件是否被觸發
			DWORD dwWait = WaitForSingleObject(ol.hEvent, 100);

			// 檢查等待結果
			if (dwWait == WAIT_OBJECT_0) {
				// 讀取操作已完成，獲取結果
				if (!GetOverlappedResult(hPipe, &ol, &dwRead, FALSE)) {
					DWORD error = GetLastError();
					if (error == ERROR_BROKEN_PIPE) {
#ifdef __DEBUG_PRINT
						std::cout << "[RESPONDER] Pipe already closed" << std::endl;
#endif
					}
					else {
						std::cerr << "[RESPONDER] GetOverlappedResult Fail: " << error << std::endl;
					}
					CloseHandle(ol.hEvent);
					break;
				}
			}
			else if (dwWait == WAIT_TIMEOUT) {
				// 超時，取消操作並繼續下一輪
				CancelIoEx(hPipe, &ol);
				CloseHandle(ol.hEvent);
				continue;
			}
			else {
				// 等待失敗
				std::cerr << "[RESPONDER] WaitForSingleObject Fail: " << GetLastError() << std::endl;
				CloseHandle(ol.hEvent);
				break;
			}
		}

		// 檢查是否真正讀取到數據
		if (dwRead == sizeof(rec)) {
			//std::cout << DebugCallNames[rec.call] << std::endl;

			// 將讀取到的 Recording 加入到 frameCurr 的 currExec 的本地記錄中
			std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
			PipeManager::AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

			// 檢查 rec 是否是 CreateProcessInternalW
			if (rec.call == Call::cCreateProcessInternalW) {
				// 檢查是否超過上限並加入到 pids 陣列
				if (GlobalState::GetInst()->get_pidptr() < MAX_PID) {
					GlobalState::GetInst()->set_pids(GlobalState::GetInst()->get_pidptr(), rec.value.dwCtx);
					GlobalState::GetInst()->set_pidptr(GlobalState::GetInst()->get_pidptr() + 1);
				}
			}
		}

		// 關閉事件句柄
		CloseHandle(ol.hEvent);
	}

	// 關閉管道
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}
