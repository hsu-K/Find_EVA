#include "ThreadManager.hpp"
#include <windows.h>
#include "communication.h"

void ThreadManager::startListenerThread()
{
	_listenerThread = std::make_shared<std::thread>(&ThreadManager::ListenerThreadEntry, this);
}

void ThreadManager::stopListenerThread()
{
	stopListener = true;	// 設定停止標誌為true
	if (_listenerThread && _listenerThread->joinable()) {
		_listenerThread->join();	// 等待線程結束
	}
	else {
		std::cout << "Listener thread is not joinable or already stopped." << std::endl;
	}
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
			0, 0, 0, NULL
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
		}
		else {
#ifdef _DEBUG
			printf("[LISTENER] New client connection obtained!\n");
#endif
			// 判斷是否超過最大可用的回應線程(20)
			if (GlobalState::GetInst()->getThreadPoolSize() >= MAX_CHILD) {
				printf("Exceeded max available responder threads!\n");
				continue;
			}

			// 創建響應線程
			try {
				auto responderThread = std::make_shared<std::thread>(&ThreadManager::ResponderThreadEntry, this, InstancePipe);

				// 添加到 GlobalState 的線程池
				GlobalState::GetInst()->addThread(responderThread);

				// 記錄線程已創建的信息
				std::cout << "Created responder thread and added to thread pool." << std::endl;
			}
			catch (const std::exception& e) {
				fprintf(stderr, "Could not create responder thread: %s\n", e.what());
				return 0;
			}
		}

		CloseHandle(ol.hEvent);

#ifdef _DEBUG
		printf("[LISTENER] New client connection obtained!\n");
#endif
	}
	return 1;
}

DWORD WINAPI ThreadManager::ResponderThreadEntry(HANDLE hPipe)
{
	
	DWORD tid = GetCurrentThreadId();	// 取得當前執行緒的 ID

	// 安全地增加並獲取一個索引值
	LONG LocalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));
#ifdef __DEBUG_PRINT
	printf("This Responder Thread Gets Index: %ld\n", LocalRecIndex);
	printf("[RESPONDER %lu] Transfering mutations to new process.\n", tid);
#endif
	// 將frameCurr的每個突變資料傳送到管道，讓DLL可以接收
	//TransferMutations(hPipe);

	// 檢查SyncEvent是否已設置，如有，則繼續讀取管道的Mutation的Recording
	while (WaitForSingleObject(*(GlobalState::GetInst()->get_SyncEvent().get()), 0) != WAIT_OBJECT_0) {
		Recording rec;
		DWORD dwRead;

		// 讀取管道的Mutation的Recording(從DLL來的)
		BOOL rd = ReadFile(hPipe, (void*)&rec, sizeof(rec), &dwRead, NULL);
		if (rd) {

			/*
			// 將讀取到的Recording加入到frameCurr的currExec的本地記錄中
			AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

			// 檢查rec是否是CreateProcessInternalW這個Windows API
			if (rec.call == Call::cCreateProcessInternalW) {
#ifdef __DEBUG_PRINT
				printf("We found creation of PID: %u\n", rec.value.dwCtx);
#endif
				// 檢查是否超過上限(100)，並將其加入到pids陣列中
				if (pidptr < MAX_PIDS) {
					pids[pidptr] = rec.value.dwCtx;
					pidptr++;
				}
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
			*/
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
