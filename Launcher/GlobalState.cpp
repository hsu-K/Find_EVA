#include "GlobalState.hpp"

std::shared_ptr<GlobalState> GlobalState::_instance = nullptr;

void GlobalState::addThread(std::shared_ptr<std::thread> thread)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	threadPool.push_back(thread);

	// 存儲線程的原生句柄
	HANDLE nativeHandle = (HANDLE)thread->native_handle();
	threadNativeHandles.push_back(nativeHandle);
}

bool GlobalState::removeThread(size_t index)
{
	std::unique_lock<std::mutex> lock(threadPoolMutex);
	if (index < threadPool.size()) {
		if (threadPool[index]->joinable()) {
			threadPool[index]->join();
		}
		threadPool.erase(threadPool.begin() + index);

		// 同時移除原生句柄
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
			// 取消線程的同步 I/O 操作
			if (!CancelSynchronousIo(threadHandle)) {
				DWORD error = GetLastError();
				if (error != ERROR_NOT_FOUND) { // ERROR_NOT_FOUND 表示沒有找到可取消的 I/O
					std::cerr << "取消同步 I/O 失敗: " << error << std::endl;
					return false;
				}
			}
			return true;
		}
	}
	return false;
}
