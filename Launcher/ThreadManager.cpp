#include "ThreadManager.hpp"
#include <windows.h>
#include "communication.h"
#include "PipeManager.hpp"

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
	//printf("[Enviral Launcher] Listener thread is active.\n");
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
			else {
				std::cout << err << std::endl;
				break;
			}
		}
#ifdef __DEBUG_PRINT
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

DWORD WINAPI ThreadManager::ResponderThreadEntry(HANDLE hPipe)
{

    //std::cout << "ResponderThreadEntry�Ыئ��\" << std::endl;
    DWORD tid = GetCurrentThreadId();

    // �w���a�W�[������@�ӯ��ޭ�
    LONG LocalRecIndex = InterlockedIncrement(&(GlobalState::GetInst()->get_frameCurr()->currExec->RecIndex));

    // �N frameCurr ���C�Ӭ��ܸ�ƶǰe��޹D
    PipeManager::TransferMutations(hPipe);

    // �ˬd SyncEvent �O�_�w�]�m
    while (WaitForSingleObject(*(GlobalState::GetInst()->get_SyncEvent().get()), 0) != WAIT_OBJECT_0) {
        if (shouldTerminate) {
            break;
        }

        // ��l�� OVERLAPPED ���c
        OVERLAPPED ol = {};
        ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ol.hEvent) {
            std::cerr << "[RESPONDER] Cannot create EventHandle" << GetLastError() << std::endl;
            break;
        }

        Recording rec;
        DWORD dwRead = 0;

        // �D�P�BŪ���ƾ�
        BOOL readSuccess = ReadFile(hPipe, &rec, sizeof(rec), NULL, &ol);

        // �ˬdŪ���ާ@�O�_�ߧY����
        if (readSuccess) {
            // Ū���ߧY�����A�L�ݵ���
            if (!GetOverlappedResult(hPipe, &ol, &dwRead, FALSE)) {
                std::cerr << "[RESPONDER] GetOverlappedResult Fail: " << GetLastError() << std::endl;
                CloseHandle(ol.hEvent);
                break;
            }
        }
        else {
            // �ˬd�O�_���D�P�B�ާ@���b�i�椤
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

            // ���ݳ̦h 100ms�A�ݬݨƥ�O�_�QĲ�o
            DWORD dwWait = WaitForSingleObject(ol.hEvent, 100);

            // �ˬd���ݵ��G
            if (dwWait == WAIT_OBJECT_0) {
                // Ū���ާ@�w�����A������G
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
                // �W�ɡA�����ާ@���~��U�@��
                CancelIoEx(hPipe, &ol);
                CloseHandle(ol.hEvent);
                continue;
            }
            else {
                // ���ݥ���
                std::cerr << "[RESPONDER] WaitForSingleObject Fail: " << GetLastError() << std::endl;
                CloseHandle(ol.hEvent);
                break;
            }
        }

        // �ˬd�O�_�u��Ū����ƾ�
        if (dwRead == sizeof(rec)) {
            //std::cout << DebugCallNames[rec.call] << std::endl;

            // �NŪ���쪺 Recording �[�J�� frameCurr �� currExec �����a�O����
            std::shared_ptr<Frame> frameCurr = GlobalState::GetInst()->get_frameCurr();
            PipeManager::AddRecordToList(frameCurr->currExec, &rec, LocalRecIndex);

            // �ˬd rec �O�_�O CreateProcessInternalW
            if (rec.call == Call::cCreateProcessInternalW) {
                // �ˬd�O�_�W�L�W���å[�J�� pids �}�C
                if (GlobalState::GetInst()->get_pidptr() < MAX_PID) {
                    GlobalState::GetInst()->set_pids(GlobalState::GetInst()->get_pidptr(), rec.value.dwCtx);
                    GlobalState::GetInst()->set_pidptr(GlobalState::GetInst()->get_pidptr() + 1);
                }
            }
        }

        // �����ƥ�y�`
        CloseHandle(ol.hEvent);
    }

    // �����޹D
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
	return 1;
}
