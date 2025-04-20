#include "GlobalState.hpp"
#include <future>

std::shared_ptr<GlobalState> GlobalState::_instance = nullptr;

void GlobalState::addThread(std::shared_ptr<std::thread> thread)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	threadPool.push_back(thread);

	// �s�x�u�{����ͥy�`
	HANDLE nativeHandle = (HANDLE)thread->native_handle();
	threadNativeHandles.push_back(nativeHandle);
}

bool GlobalState::removeThread(size_t index)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	if (index < threadPool.size()) {
		// �����ը����u�{�� I/O �ާ@
		HANDLE threadHandle = threadNativeHandles[index];

		if (threadPool[index]->joinable()) {
			/*threadPool[index]->join();*/
			std::future<void> future = std::async(std::launch::async, [&]() {
				threadPool[index]->join();
				});

			// ���ݽu�{�����A���̦h���� 3 ��
			if (future.wait_for(std::chrono::seconds(1)) == std::future_status::timeout) {
				std::cerr << "ĵ�i: �u�{ " << index << " �L�k�b�W�ɮɶ�������" << std::endl;
				// �j��פ�u�{ (���w��!)
				DWORD exitCode = 0;
				if (!TerminateThread(threadHandle, exitCode)) {
					std::cerr << "�j��פ�u�{����: " << GetLastError() << std::endl;
				}
				// �`�N�G�o�̵L�k�w���a detach�A�i��|�ɭP�귽���|
				// �����F������{�ǡA�ڭ̥����~��
			}
		}
		threadPool.erase(threadPool.begin() + index);

		// �P�ɲ�����ͥy�`
		if (index < threadNativeHandles.size()) {
			threadNativeHandles.erase(threadNativeHandles.begin() + index);
		}
		return true;
	}
	return false;
}

size_t GlobalState::getThreadPoolSize()
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	return threadPool.size();
}

HANDLE GlobalState::getThreadNativeHandle(size_t index)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	if (index < threadNativeHandles.size()) {
		return threadNativeHandles[index];
	}
	return NULL;
}

bool GlobalState::cancelThreadIO(size_t index)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	if (index < threadNativeHandles.size()) {
		HANDLE threadHandle = threadNativeHandles[index];
		if (threadHandle != NULL) {
			// �����u�{���P�B I/O �ާ@
			if (!CancelSynchronousIo(threadHandle)) {
				DWORD error = GetLastError();
				if (error != ERROR_NOT_FOUND) { // ERROR_NOT_FOUND ��ܨS�����i������ I/O
					std::cerr << "�����P�B I/O ����: " << error << std::endl;
					return false;
				}
			}
			return true;
		}
	}
	return false;
}
