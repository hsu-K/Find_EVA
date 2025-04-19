#include "ThreadManager.hpp"
#include <windows.h>
#include "communication.h"

void ThreadManager::startListenerThread()
{
	_listenerThread = std::make_shared<std::thread>(&ThreadManager::ListenerThreadEntry, this);
}

void ThreadManager::stopListenerThread()
{
	stopListener = true;	// �]�w����лx��true
	if (_listenerThread && _listenerThread->joinable()) {
		_listenerThread->join();	// ���ݽu�{����
	}
	else {
		std::cout << "Listener thread is not joinable or already stopped." << std::endl;
	}
}

// ��ť�u�{
DWORD WINAPI ThreadManager::ListenerThreadEntry()
{
	printf("[Enviral Launcher] Listener thread is active.\n");
	HANDLE InstancePipe = nullptr;
	DWORD dwThreadId = 0;
	while (!stopListener) {

		// �Ыؤ@�ӷs���R�W�޹D��ҡA���V�q�H�Ҧ�(PIPE_ACCESS_DUPLEX)�B���������޹D(PIPE_TYPE_MESSAGE)
		// �إ� overlapped �D�P�B�R�W�޹D
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
					continue; // timeout -> �ˬd stopListener �A����
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
			// �P�_�O�_�W�L�̤j�i�Ϊ��^���u�{(20)
			if (GlobalState::GetInst()->getThreadPoolSize() >= MAX_CHILD) {
				printf("Exceeded max available responder threads!\n");
				continue;
			}

			// �Ы��T���u�{
			try {
				auto responderThread = std::make_shared<std::thread>(&ThreadManager::ResponderThreadEntry, this, InstancePipe);

				// �K�[�� GlobalState ���u�{��
				GlobalState::GetInst()->addThread(responderThread);

				// �O���u�{�w�Ыت��H��
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
	
	DWORD tid = GetCurrentThreadId();	// ���o��e������� ID

	// �w���a�W�[������@�ӯ��ޭ�
	LONG LocalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));
#ifdef __DEBUG_PRINT
	printf("This Responder Thread Gets Index: %ld\n", LocalRecIndex);
	printf("[RESPONDER %lu] Transfering mutations to new process.\n", tid);
#endif
	// �NframeCurr���C�Ӭ��ܸ�ƶǰe��޹D�A��DLL�i�H����
	//TransferMutations(hPipe);

	// �ˬdSyncEvent�O�_�w�]�m�A�p���A�h�~��Ū���޹D��Mutation��Recording
	while (WaitForSingleObject(*(GlobalState::GetInst()->get_SyncEvent().get()), 0) != WAIT_OBJECT_0) {
		Recording rec;
		DWORD dwRead;

		// Ū���޹D��Mutation��Recording(�qDLL�Ӫ�)
		BOOL rd = ReadFile(hPipe, (void*)&rec, sizeof(rec), &dwRead, NULL);
		if (rd) {

			/*
			// �NŪ���쪺Recording�[�J��frameCurr��currExec�����a�O����
			AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

			// �ˬdrec�O�_�OCreateProcessInternalW�o��Windows API
			if (rec.call == Call::cCreateProcessInternalW) {
#ifdef __DEBUG_PRINT
				printf("We found creation of PID: %u\n", rec.value.dwCtx);
#endif
				// �ˬd�O�_�W�L�W��(100)�A�ñN��[�J��pids�}�C��
				if (pidptr < MAX_PIDS) {
					pids[pidptr] = rec.value.dwCtx;
					pidptr++;
				}
			}

			//printf("[RESPONDER %lu] Recv recording: %s\n", tid, DebugCallNames[rec.call]);
		}
		else {
			// �p�GŪ�����ѡA�h�ˬd���~�X
			// ReadFile failed, if it is because ERROR_BROKEN_PIPE, then the client disconnected.
			DWORD err = GetLastError();

			// �Ȥ���_�}�s��
			if (err == ERROR_BROKEN_PIPE) {
#ifdef __DEBUG_PRINT
				printf("[RESPONDER %lu] No more reading, the client disconnected.\n", tid);
#endif
			}
			// �Ȥ�ݨ����ާ@
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

	// �����޹D
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);
	return 1;
}
